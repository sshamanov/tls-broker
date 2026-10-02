// Package audit implements the append-only JSONL audit log (architecture
// §14): a core.Auditor that writes one JSON object per line under a
// directory, and a core.AuditReader that queries it across rotated files.
//
// Files are named audit-YYYY-MM-DD.jsonl (UTC day of the write) and, when a
// file reaches the size limit, audit-YYYY-MM-DD.N.jsonl. There is no hash
// chain; SQLite is the authoritative state and this is readable history.
//
// Record never returns an error and never panics: a write failure (disk full,
// directory removed, ...) is logged, passed to Options.OnError (the metrics
// hook) and dropped, and the next Record tries again. Lines are written with
// a single write call, so concurrent readers and a crash can leave at most a
// truncated last line, which readers skip and the writer terminates with a
// newline before appending.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tls-broker/internal/core"
)

// ErrClosed is reported through OnError for an event recorded after Close.
var ErrClosed = errors.New("audit log is closed")

// DefaultSyncInterval is the fsync interval when Options.SyncInterval is 0.
const DefaultSyncInterval = time.Second

// Options configure a Log.
type Options struct {
	// Dir is the audit directory, normally <data>/audit. Created if absent.
	Dir string
	// Clock supplies event times (when zero) and decides the rotation day.
	// Nil means the system clock.
	Clock core.Clock
	// MaxFileBytes rotates to a new file once the current one has reached
	// this size (a file can exceed it by one line). 0 disables size rotation.
	MaxFileBytes int64
	// MaxFiles is how many rotated (non-current) files are kept; older ones
	// are deleted after a rotation. 0 keeps everything.
	MaxFiles int
	// SyncInterval is the fsync policy. 0 means DefaultSyncInterval: data is
	// written to the kernel immediately (it survives a process crash) and
	// fsynced at most that late by a background goroutine, on rotation, and
	// on Close. A negative value fsyncs after every record.
	SyncInterval time.Duration
	// OnError is called for every event that could not be written, with the
	// cause. It must not block. Wire it to metrics.AuditWriteFailure.
	OnError func(error)
	// Logger receives write failures; nil means slog.Default().
	Logger *slog.Logger
}

// Log is the audit writer and reader. Safe for concurrent use.
type Log struct {
	Reader
	opts  Options
	clock core.Clock
	log   *slog.Logger

	mu       sync.Mutex
	f        *os.File
	date     string
	seq      int
	size     int64
	dirty    bool
	closed   bool
	stopSync chan struct{}
	syncDone chan struct{}
}

var (
	_ core.Auditor     = (*Log)(nil)
	_ core.AuditReader = (*Log)(nil)
)

// Open prepares the audit directory and returns the log. The file itself is
// opened by the first Record.
func Open(opts Options) (*Log, error) {
	if opts.Dir == "" {
		return nil, errors.New("audit: Dir is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	l := &Log{Reader: Reader{dir: opts.Dir}, opts: opts, clock: opts.Clock, log: opts.Logger}
	if l.clock == nil {
		l.clock = core.SystemClock{}
	}
	if l.log == nil {
		l.log = slog.Default()
	}
	if opts.SyncInterval >= 0 {
		iv := opts.SyncInterval
		if iv == 0 {
			iv = DefaultSyncInterval
		}
		l.stopSync = make(chan struct{})
		l.syncDone = make(chan struct{})
		go l.syncLoop(iv)
	}
	return l, nil
}

// Record implements core.Auditor.
func (l *Log) Record(_ context.Context, ev core.AuditEvent) {
	defer func() {
		if r := recover(); r != nil {
			l.fail(fmt.Errorf("audit: panic while recording: %v", r))
		}
	}()
	if ev.Time.IsZero() {
		ev.Time = l.clock.Now()
	}
	ev.Time = ev.Time.UTC()
	line, err := json.Marshal(ev)
	if err != nil {
		l.fail(fmt.Errorf("audit: encode: %w", err))
		return
	}
	line = append(line, '\n')
	if err := l.write(line); err != nil {
		l.fail(err)
	}
}

func (l *Log) fail(err error) {
	l.log.Error("audit write failed", "error", err)
	if l.opts.OnError != nil {
		func() {
			defer func() { _ = recover() }()
			l.opts.OnError(err)
		}()
	}
}

func (l *Log) write(line []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if err := l.ensure(); err != nil {
		return err
	}
	n, err := l.f.Write(line)
	if err != nil {
		// Do not keep a handle with an unknown tail; the next Record
		// reopens the file and terminates a partial line.
		_ = l.f.Close()
		l.f = nil
		return fmt.Errorf("audit: write: %w", err)
	}
	l.size += int64(n)
	l.dirty = true
	if l.opts.SyncInterval < 0 {
		if err := l.f.Sync(); err != nil {
			return fmt.Errorf("audit: sync: %w", err)
		}
		l.dirty = false
	}
	return nil
}

// ensure makes l.f the file the next line belongs to, rotating by day and
// size. Called with l.mu held.
func (l *Log) ensure() error {
	date := l.clock.Now().UTC().Format(dateLayout)
	max := l.opts.MaxFileBytes
	switch {
	case l.f != nil && l.date == date && (max <= 0 || l.size < max):
		return nil
	case l.f != nil && l.date == date:
		l.closeFile()
		l.seq++
	case l.f != nil:
		l.closeFile()
		l.date, l.seq = date, 0
		if files, err := listFiles(l.opts.Dir); err == nil {
			for _, f := range files {
				if f.Date == date && f.Seq > l.seq {
					l.seq = f.Seq
				}
			}
		}
	case l.date != date:
		// first use, or reopening on a new day after a failure
		l.date, l.seq = date, 0
		if files, err := listFiles(l.opts.Dir); err == nil {
			for _, f := range files {
				if f.Date == date && f.Seq > l.seq {
					l.seq = f.Seq
				}
			}
		}
	}
	for {
		if err := l.openCurrent(); err != nil {
			return err
		}
		if max > 0 && l.size >= max {
			l.closeFile()
			l.seq++
			continue
		}
		break
	}
	l.prune()
	return nil
}

func (l *Log) openCurrent() error {
	path := filepath.Join(l.opts.Dir, nameOf(l.date, l.seq))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("audit: stat: %w", err)
	}
	size := st.Size()
	if size > 0 {
		// A crash or a failed write may have left a partial line; end it
		// so the next event starts on its own line.
		var last [1]byte
		if rf, err := os.Open(path); err == nil {
			_, rerr := rf.ReadAt(last[:], size-1)
			_ = rf.Close()
			if rerr == nil && last[0] != '\n' {
				if _, err := f.Write([]byte{'\n'}); err == nil {
					size++
				}
			}
		}
	}
	l.f, l.size = f, size
	return nil
}

// closeFile syncs and closes the current file. Called with l.mu held.
func (l *Log) closeFile() {
	if l.f == nil {
		return
	}
	_ = l.f.Sync()
	_ = l.f.Close()
	l.f, l.dirty = nil, false
}

// prune deletes the oldest files beyond MaxFiles rotated files. Called with
// l.mu held, after the current file exists.
func (l *Log) prune() {
	keep := l.opts.MaxFiles
	if keep <= 0 {
		return
	}
	files, err := listFiles(l.opts.Dir)
	if err != nil || len(files) <= keep+1 {
		return
	}
	for _, f := range files[:len(files)-(keep+1)] {
		if err := os.Remove(filepath.Join(l.opts.Dir, f.Name)); err != nil {
			l.log.Warn("audit retention: remove failed", "file", f.Name, "error", err)
		}
	}
}

func (l *Log) syncLoop(iv time.Duration) {
	defer close(l.syncDone)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-l.stopSync:
			return
		case <-t.C:
			l.mu.Lock()
			f, dirty := l.f, l.dirty
			l.dirty = false
			l.mu.Unlock()
			if f != nil && dirty {
				// A concurrent rotation may have closed f (after
				// syncing it); that error is harmless.
				_ = f.Sync()
			}
		}
	}
}

// Close fsyncs and closes the log. Events recorded before Close are durable
// when it returns. Safe to call more than once.
func (l *Log) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	var err error
	if l.f != nil {
		err = l.f.Sync()
		if cerr := l.f.Close(); err == nil {
			err = cerr
		}
		l.f = nil
	}
	l.mu.Unlock()
	if l.stopSync != nil {
		close(l.stopSync)
		<-l.syncDone
	}
	return err
}

var _ io.Closer = (*Log)(nil)
