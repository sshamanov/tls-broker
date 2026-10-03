package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

var ctx = context.Background()

func open(t *testing.T, o Options) *Log {
	t.Helper()
	if o.Dir == "" {
		o.Dir = filepath.Join(t.TempDir(), "audit")
	}
	l, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	fs, err := listFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}

func TestConcurrentWritesProduceValidLines(t *testing.T) {
	l := open(t, Options{SyncInterval: -1})
	const writers, each = 16, 100
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				l.Record(ctx, core.AuditEvent{Type: core.AuditGate,
					Detail: strings.Repeat("x", 200), OrderID: fmt.Sprintf("w%d-%d", w, i)})
			}
		}()
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, n := range names(t, l.dir) {
		f, err := os.Open(filepath.Join(l.dir, n))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var ev core.AuditEvent
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				t.Fatalf("invalid line %q: %v", sc.Text(), err)
			}
			if ev.Time.IsZero() {
				t.Fatal("time not filled in")
			}
			seen[ev.OrderID] = true
		}
		f.Close()
	}
	if len(seen) != writers*each {
		t.Fatalf("got %d distinct events, want %d", len(seen), writers*each)
	}
}

func TestRotationByDateAndSize(t *testing.T) {
	clock := coretest.NewFakeClock(time.Date(2026, 3, 1, 23, 0, 0, 0, time.UTC))
	l := open(t, Options{Clock: clock, MaxFileBytes: 300})
	rec := func(id string) {
		l.Record(ctx, core.AuditEvent{Type: core.AuditIssue, OrderID: id, Detail: strings.Repeat("d", 100)})
	}
	rec("a1") // ~200 bytes, below the limit
	rec("a2") // brings it past 300
	rec("a3") // rotates to .1
	want := []string{"audit-2026-03-01.1.jsonl", "audit-2026-03-01.jsonl"}
	got := names(t, l.dir)
	if len(got) != 2 || got[0] != want[1] || got[1] != want[0] {
		t.Fatalf("files %v", got)
	}
	clock.Advance(2 * time.Hour) // 01:00 next day
	rec("b1")
	got = names(t, l.dir)
	if len(got) != 3 || got[2] != "audit-2026-03-02.jsonl" {
		t.Fatalf("files %v", got)
	}
	// Records land in the right files.
	b, _ := os.ReadFile(filepath.Join(l.dir, "audit-2026-03-02.jsonl"))
	if !strings.Contains(string(b), `"b1"`) || strings.Contains(string(b), `"a3"`) {
		t.Fatalf("day file: %s", b)
	}
	evs, err := l.Query(ctx, core.AuditQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range evs {
		ids = append(ids, e.OrderID)
	}
	if strings.Join(ids, ",") != "b1,a3,a2,a1" {
		t.Fatalf("order %v", ids)
	}
	// A new writer on the same day resumes the newest file.
	l2 := open(t, Options{Dir: l.dir, Clock: clock, MaxFileBytes: 300})
	l2.Record(ctx, core.AuditEvent{Type: core.AuditIssue, OrderID: "b2"})
	if got := names(t, l.dir); len(got) != 3 {
		t.Fatalf("files %v", got)
	}
}

func TestRetention(t *testing.T) {
	clock := coretest.NewFakeClock()
	l := open(t, Options{Clock: clock, MaxFiles: 2})
	for i := 0; i < 5; i++ {
		l.Record(ctx, core.AuditEvent{Type: core.AuditLogin, OrderID: fmt.Sprint(i)})
		clock.Advance(24 * time.Hour)
	}
	l.Record(ctx, core.AuditEvent{Type: core.AuditLogin, OrderID: "last"})
	got := names(t, l.dir)
	if len(got) != 3 { // current + 2 rotated
		t.Fatalf("files %v", got)
	}
}

func seed(t *testing.T) *Log {
	clock := coretest.NewFakeClock(time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC))
	l := open(t, Options{Clock: clock, MaxFileBytes: 1 << 20})
	rec := func(ev core.AuditEvent) {
		l.Record(ctx, ev)
		clock.Advance(time.Minute)
	}
	rec(core.AuditEvent{Type: core.AuditGate, Mode: core.ModeACME,
		SourceIP: "10.0.0.5", Names: []string{"Web.Example.com"}, Decision: core.AuditDecisionAllow, Reason: core.ReasonDNSIPMatch})
	rec(core.AuditEvent{Type: core.AuditGate, Mode: core.ModeACME, SourceIP: "10.0.0.6",
		Names: []string{"db.example.com"}, Decision: core.AuditDecisionDeny, Reason: core.ReasonDNSMismatch})
	clock.Advance(24 * time.Hour)
	rec(core.AuditEvent{Type: core.AuditIssue, Mode: core.ModeDirect,
		SourceIP: "10.0.0.5", Names: []string{"web.example.com"}, Provider: "letsencrypt", Result: core.AuditResultOK})
	rec(core.AuditEvent{Type: core.AuditGrantChange, Mode: core.ModeUI, Username: "Alice", Detail: "grant 4 created"})
	return l
}

func ids(evs []core.AuditEvent) string {
	var s []string
	for _, e := range evs {
		s = append(s, e.Type+"/"+e.SourceIP+e.Username)
	}
	return strings.Join(s, " ")
}

func TestQueryFiltersAndOrder(t *testing.T) {
	l := seed(t)
	q := func(q core.AuditQuery) []core.AuditEvent {
		t.Helper()
		evs, err := l.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return evs
	}
	if got := q(core.AuditQuery{}); ids(got) != "grant_change/Alice issue/10.0.0.5 gate/10.0.0.6 gate/10.0.0.5" {
		t.Fatalf("all: %s", ids(got))
	}
	if got := q(core.AuditQuery{Limit: 1}); len(got) != 1 || got[0].Type != core.AuditGrantChange {
		t.Fatalf("limit: %v", got)
	}
	if got := q(core.AuditQuery{Mode: core.ModeACME}); len(got) != 2 {
		t.Fatalf("mode: %v", got)
	}
	if got := q(core.AuditQuery{Type: core.AuditIssue}); len(got) != 1 {
		t.Fatalf("type: %v", got)
	}
	for needle, want := range map[string]int{"10.0.0.5": 2, "WEB.example": 2, "alice": 1, "letsencrypt": 1,
		"dns_mismatch": 1, "grant 4": 1, "nothing": 0} {
		if got := q(core.AuditQuery{Contains: needle}); len(got) != want {
			t.Errorf("contains %q: %d, want %d", needle, len(got), want)
		}
	}
	// time range: Since inclusive, Until exclusive
	t0 := time.Date(2026, 3, 1, 10, 1, 0, 0, time.UTC)
	if got := q(core.AuditQuery{Since: t0, Until: t0.Add(time.Minute)}); len(got) != 1 || got[0].SourceIP != "10.0.0.6" {
		t.Fatalf("range: %v", got)
	}
	if got := q(core.AuditQuery{Since: time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)}); len(got) != 2 {
		t.Fatalf("since: %v", got)
	}
	if got := q(core.AuditQuery{Until: t0}); len(got) != 1 {
		t.Fatalf("until: %v", got)
	}
}

// Types is an allow-list; SkipDetail keeps Detail out of the Contains match
// (a view that hides Detail must not let a search probe it).
func TestQueryTypesAndSkipDetail(t *testing.T) {
	l := seed(t)
	got, _ := l.Query(ctx, core.AuditQuery{Types: []string{core.AuditIssue, core.AuditGrantChange}})
	if ids(got) != "grant_change/Alice issue/10.0.0.5" {
		t.Fatalf("types: %s", ids(got))
	}
	if got, _ := l.Query(ctx, core.AuditQuery{Contains: "grant 4", SkipDetail: true}); len(got) != 0 {
		t.Fatalf("detail matched with SkipDetail: %s", ids(got))
	}
	if got, _ := l.Query(ctx, core.AuditQuery{Contains: "alice", SkipDetail: true}); len(got) != 1 {
		t.Fatalf("username not matched with SkipDetail: %s", ids(got))
	}
}

func TestQueryAcrossFilesWithLimit(t *testing.T) {
	clock := coretest.NewFakeClock()
	l := open(t, Options{Clock: clock, MaxFileBytes: 150})
	for i := 0; i < 12; i++ {
		l.Record(ctx, core.AuditEvent{Type: core.AuditLogin, OrderID: fmt.Sprintf("%02d", i)})
	}
	if len(names(t, l.dir)) < 3 {
		t.Fatalf("expected several files: %v", names(t, l.dir))
	}
	evs, _ := l.Query(ctx, core.AuditQuery{Limit: 5})
	var got []string
	for _, e := range evs {
		got = append(got, e.OrderID)
	}
	if strings.Join(got, ",") != "11,10,09,08,07" {
		t.Fatalf("got %v", got)
	}
	if evs, _ := l.Query(ctx, core.AuditQuery{Limit: 100}); len(evs) != 12 {
		t.Fatalf("all: %d", len(evs))
	}
}

func TestTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	good := `{"time":"2026-03-01T10:00:00Z","type":"login","visibility":"public","username":"bob"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "audit-2026-03-01.jsonl"),
		[]byte(good+"garbage\n"+`{"time":"2026-03-01T10:01:00Z","type":"log`), 0o640); err != nil {
		t.Fatal(err)
	}
	evs, err := NewReader(dir).Query(ctx, core.AuditQuery{})
	if err != nil || len(evs) != 1 || evs[0].Username != "bob" {
		t.Fatalf("%v %v", evs, err)
	}
	// A writer reopening the file ends the partial line before appending.
	clock := coretest.NewFakeClock(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	l := open(t, Options{Dir: dir, Clock: clock})
	l.Record(ctx, core.AuditEvent{Type: core.AuditLogout, Username: "bob"})
	evs, _ = l.Query(ctx, core.AuditQuery{})
	if len(evs) != 2 || evs[0].Type != core.AuditLogout {
		t.Fatalf("%v", evs)
	}
}

func TestMissingDirAndCancel(t *testing.T) {
	evs, err := NewReader(filepath.Join(t.TempDir(), "none")).Query(ctx, core.AuditQuery{})
	if err != nil || len(evs) != 0 {
		t.Fatalf("%v %v", evs, err)
	}
	l := seed(t)
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := l.Query(c, core.AuditQuery{}); err == nil {
		t.Fatal("want context error")
	}
}

func TestWriteFailureIsCountedAndRecovers(t *testing.T) {
	var failures atomic.Int32
	l := open(t, Options{OnError: func(error) { failures.Add(1) }, SyncInterval: -1})
	l.Record(ctx, core.AuditEvent{Type: core.AuditLogin, OrderID: "1"})
	// Break the writer: remove the directory and replace it with a file.
	l.mu.Lock()
	_ = l.f.Close() // writes to the closed handle now fail
	l.mu.Unlock()
	l.Record(ctx, core.AuditEvent{Type: core.AuditLogin, OrderID: "2"}) // must not panic
	if failures.Load() != 1 {
		t.Fatalf("failures = %d", failures.Load())
	}
	l.Record(ctx, core.AuditEvent{Type: core.AuditLogin, OrderID: "3"})
	evs, _ := l.Query(ctx, core.AuditQuery{})
	if len(evs) != 2 || evs[0].OrderID != "3" {
		t.Fatalf("%v", evs)
	}
	// Unopenable file: the directory is replaced by a regular file.
	if err := os.RemoveAll(l.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	_ = l.f.Close()
	l.f = nil
	l.mu.Unlock()
	l.Record(ctx, core.AuditEvent{Type: core.AuditLogin, OrderID: "4"})
	if failures.Load() != 2 {
		t.Fatalf("failures = %d", failures.Load())
	}
}

func TestCloseIsDurableAndRecordAfterCloseCounts(t *testing.T) {
	var failures atomic.Int32
	l := open(t, Options{OnError: func(error) { failures.Add(1) }})
	l.Record(ctx, core.AuditEvent{Type: core.AuditLogin})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l.Record(ctx, core.AuditEvent{Type: core.AuditLogin})
	if failures.Load() != 1 {
		t.Fatalf("failures = %d", failures.Load())
	}
	if evs, _ := NewReader(l.dir).Query(ctx, core.AuditQuery{}); len(evs) != 1 {
		t.Fatalf("%v", evs)
	}
}

func TestOpenRequiresDir(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("want error")
	}
}
