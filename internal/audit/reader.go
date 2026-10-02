package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tls-broker/internal/core"
)

const defaultLimit = 200

// Reader queries the audit files of one directory. It is safe to use while a
// writer appends.
type Reader struct{ dir string }

var _ core.AuditReader = Reader{}

// NewReader returns a reader over dir (a missing directory reads as empty).
func NewReader(dir string) Reader { return Reader{dir: dir} }

// Query implements core.AuditReader. Results are newest first by position in
// the log (files newest first, lines last first), which is write order and
// equals time order except for events recorded with an explicit older Time.
//
// Unparsable lines (a truncated tail, corruption) are skipped. Files whose
// day ends more than a day before Since are not opened.
func (r Reader) Query(ctx context.Context, q core.AuditQuery) ([]core.AuditEvent, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	files, err := listFiles(r.dir)
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(q.Contains)
	var out []core.AuditEvent
	for i := len(files) - 1; i >= 0 && len(out) < limit; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if day, ok := files[i].day(); ok && !q.Since.IsZero() && day.Add(48*time.Hour).Before(q.Since) {
			continue
		}
		evs, err := readFile(ctx, filepath.Join(r.dir, files[i].Name), q, needle, limit-len(out))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) { // pruned meanwhile
				continue
			}
			return nil, err
		}
		out = append(out, evs...)
	}
	return out, nil
}

// readFile returns up to max matching events of one file, newest first.
func readFile(ctx context.Context, path string, q core.AuditQuery, needle string, max int) ([]core.AuditEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64<<10)
	var ring []core.AuditEvent // keeps the last max matches, oldest first
	n := 0
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if n++; n%4096 == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if ev, ok := parseLine(line); ok && matches(&ev, q, needle) {
				if len(ring) >= 2*max {
					ring = append(ring[:0], ring[len(ring)-max:]...)
				}
				ring = append(ring, ev)
			}
		}
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
	}
	if len(ring) > max {
		ring = ring[len(ring)-max:]
	}
	for i, j := 0, len(ring)-1; i < j; i, j = i+1, j-1 {
		ring[i], ring[j] = ring[j], ring[i]
	}
	return ring, nil
}

func parseLine(line []byte) (core.AuditEvent, bool) {
	var ev core.AuditEvent
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' || json.Unmarshal(line, &ev) != nil {
		return ev, false
	}
	return ev, true
}

func matches(ev *core.AuditEvent, q core.AuditQuery, needle string) bool {
	if !q.IncludeAdmin && ev.Visibility != core.AuditVisibilityAll {
		return false // empty visibility means admin
	}
	if !q.Since.IsZero() && ev.Time.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && !ev.Time.Before(q.Until) {
		return false
	}
	if q.Type != "" && ev.Type != q.Type {
		return false
	}
	if q.Mode != "" && ev.Mode != q.Mode {
		return false
	}
	if needle == "" {
		return true
	}
	for _, s := range []string{ev.SourceIP, ev.Username, ev.Provider, ev.Reason, ev.Detail} {
		if strings.Contains(strings.ToLower(s), needle) {
			return true
		}
	}
	for _, s := range ev.Names {
		if strings.Contains(strings.ToLower(s), needle) {
			return true
		}
	}
	return false
}
