package config

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

type stubLDAP struct {
	mu    sync.Mutex
	err   error
	calls []core.LDAPConfig
}

func (s *stubLDAP) TestLDAP(_ context.Context, cfg core.LDAPConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, cfg)
	return s.err
}

func (s *stubLDAP) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

type fixture struct {
	t       *testing.T
	data    string
	env     Env
	secrets *coretest.FakeSecrets
	ldap    *stubLDAP
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, data: t.TempDir(), secrets: coretest.NewFakeSecrets(), ldap: &stubLDAP{}}
	f.env = testEnv()
	f.env.DataDir = f.data
	return f
}

func (f *fixture) open() *Store {
	f.t.Helper()
	s, err := Open(Options{Env: f.env, Secrets: f.secrets, LDAP: f.ldap, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) dir() string { return filepath.Join(f.data, "config") }

func (f *fixture) target() string {
	f.t.Helper()
	l, err := os.Readlink(filepath.Join(f.dir(), "current"))
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

const ldapYAML = `ldap:
  url: ldaps://ldap.example.com:636
  bind_dn: cn=svc,dc=example,dc=com
  bind_password_secret: ldap-bind-password
  base_dn: ou=people,dc=example,dc=com
  user_filter: (&(objectClass=person)(uid=%s))
`

func TestFirstStartWritesGeneration1(t *testing.T) {
	f := newFixture(t)
	s := f.open()
	cur := s.Current()
	if cur.Generation != 1 || cur.DataDir != f.data || cur.Bootstrap.Admins[0] != "alice" {
		t.Fatalf("%+v", cur)
	}
	if f.target() != "000001.yaml" {
		t.Fatal(f.target())
	}
	data, err := os.ReadFile(filepath.Join(f.dir(), "000001.yaml"))
	if err != nil || string(data) != string(DefaultYAML()) {
		t.Fatalf("content: %v\n%s", err, data)
	}
	if fi, _ := os.Stat(f.dir()); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	gens, _ := s.Generations(context.Background())
	if len(gens) != 1 || !gens[0].Active || gens[0].Number != 1 || gens[0].CreatedAt.IsZero() || time.Since(gens[0].CreatedAt) > time.Minute {
		t.Fatalf("%+v", gens)
	}
	// Reopening does not create another generation.
	s2 := f.open()
	if s2.Current().Generation != 1 {
		t.Fatal("generation changed on reopen")
	}
	if ents, _ := filepath.Glob(filepath.Join(f.dir(), "0*.yaml")); len(ents) != 1 {
		t.Fatalf("%v", ents)
	}
}

func TestActivateNumbersAndSwitches(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	n, check, err := s.Activate(ctx, []byte("scheduler:\n  admit_wait: 45s\n"))
	if err != nil || !check.OK() || n != 2 {
		t.Fatalf("%d %+v %v", n, check, err)
	}
	if f.target() != "000002.yaml" || s.Current().Generation != 2 || s.Current().Scheduler.AdmitWait != 45*time.Second {
		t.Fatalf("not switched: %s %+v", f.target(), s.Current().Scheduler)
	}
	// The stored text is the submitted text, verbatim (comments preserved).
	src := "# keep me\nscheduler:\n  admit_wait: 50s\n"
	if n, _, err := s.Activate(ctx, []byte(src)); err != nil || n != 3 {
		t.Fatal(n, err)
	}
	if got, _ := s.Read(ctx, 3); string(got) != src {
		t.Fatalf("%q", got)
	}
	gens, _ := s.Generations(ctx)
	var nums []int
	for _, g := range gens {
		nums = append(nums, g.Number)
		if g.Active != (g.Number == 3) {
			t.Fatalf("active flag: %+v", g)
		}
	}
	if !slices.Equal(nums, []int{3, 2, 1}) {
		t.Fatalf("order %v", nums)
	}
	// Generations are immutable files with no temporary leftovers.
	ents, _ := os.ReadDir(f.dir())
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"000001.yaml", "000002.yaml", "000003.yaml", "current"}) {
		t.Fatalf("dir: %v", names)
	}
	// A restart picks the same state.
	if s2 := f.open(); s2.Current().Generation != 3 {
		t.Fatalf("after reopen: %d", s2.Current().Generation)
	}
}

func TestInvalidActivateStoresNothing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	n, check, err := s.Activate(ctx, []byte("direct:\n  rsa_bits: 7\nbogus: 1\n"))
	if err != nil || n != 0 || check.OK() || len(check.Errors) == 0 {
		t.Fatalf("%d %+v %v", n, check, err)
	}
	_, check, _ = s.Activate(ctx, []byte("direct:\n  rsa_bits: 7\n"))
	if !strings.Contains(strings.Join(check.Errors, "\n"), "direct.rsa_bits") {
		t.Fatalf("%v", check.Errors)
	}
	if s.Current().Generation != 1 || f.target() != "000001.yaml" {
		t.Fatal("current changed")
	}
	if _, err := os.Stat(filepath.Join(f.dir(), "000002.yaml")); !os.IsNotExist(err) {
		t.Fatal("generation written for invalid config")
	}
}

func TestValidateDoesNotStore(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	check, err := s.Validate(ctx, []byte("zones:\n  - {name: example.com, hosted_zone_id: Z1}\n"))
	if err != nil || !check.OK() {
		t.Fatalf("%+v %v", check, err)
	}
	if len(check.Warnings) == 0 {
		t.Fatal("expected warnings (no providers)")
	}
	if s.Current().Generation != 1 || len(s.Current().Zones) != 0 {
		t.Fatal("Validate changed state")
	}
	if gens, _ := s.Generations(ctx); len(gens) != 1 {
		t.Fatal("Validate stored a generation")
	}
}

func TestMissingSecretBlocksActivation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	n, check, err := s.Activate(ctx, []byte(ldapYAML))
	if err != nil || n != 0 || check.OK() || !strings.Contains(strings.Join(check.Errors, "\n"), "ldap.bind_password_secret") {
		t.Fatalf("%d %+v %v", n, check, err)
	}
	if f.ldap.count() != 0 {
		t.Fatal("LDAP tested although a secret is missing")
	}
	f.secrets.Put(ctx, "ldap-bind-password", []byte("pw"))
	if n, check, err := s.Activate(ctx, []byte(ldapYAML)); err != nil || n != 2 || !check.OK() {
		t.Fatalf("%d %+v %v", n, check, err)
	}
}

func TestLDAPTestFailureBlocksActivation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.secrets.Put(ctx, "ldap-bind-password", []byte("pw"))
	s := f.open()
	f.ldap.err = errors.New("bind rejected")
	n, check, err := s.Activate(ctx, []byte(ldapYAML))
	if err != nil || n != 0 || check.OK() || !check.LDAPTested || check.LDAPError != "bind rejected" {
		t.Fatalf("%d %+v %v", n, check, err)
	}
	if !strings.Contains(strings.Join(check.Errors, "\n"), "bind rejected") {
		t.Fatalf("%v", check.Errors)
	}
	if s.Current().Generation != 1 || f.target() != "000001.yaml" {
		t.Fatal("current changed after failed LDAP test")
	}
	if ents, _ := filepath.Glob(filepath.Join(f.dir(), "0*.yaml")); len(ents) != 1 {
		t.Fatalf("generation written: %v", ents)
	}
	if got := f.ldap.calls[0]; got.URL != "ldaps://ldap.example.com:636" || got.BindPasswordSecret != "ldap-bind-password" {
		t.Fatalf("tester got %+v", got)
	}
	// Recovery: the directory works again.
	f.ldap.err = nil
	if n, check, err := s.Activate(ctx, []byte(ldapYAML)); err != nil || n != 2 || !check.LDAPTested || check.LDAPError != "" {
		t.Fatalf("%d %+v %v", n, check, err)
	}
}

func TestLDAPTestOnlyWhenSettingsChanged(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.secrets.Put(ctx, "ldap-bind-password", []byte("pw"))
	s := f.open()
	// Nothing configured: no test.
	if _, check, _ := s.Activate(ctx, []byte("scheduler:\n  admit_wait: 40s\n")); check.LDAPTested || f.ldap.count() != 0 {
		t.Fatal("tested with LDAP unconfigured")
	}
	if _, _, err := s.Activate(ctx, []byte(ldapYAML)); err != nil || f.ldap.count() != 1 {
		t.Fatalf("%v %d", err, f.ldap.count())
	}
	// Same LDAP settings, other change: no test even if the directory is down.
	f.ldap.err = errors.New("down")
	n, check, err := s.Activate(ctx, []byte(ldapYAML+"scheduler:\n  admit_wait: 41s\n"))
	if err != nil || n != 4 || check.LDAPTested || f.ldap.count() != 1 {
		t.Fatalf("%d %+v %v", n, check, err)
	}
	// Changed LDAP settings are tested (and refused).
	changed := strings.Replace(ldapYAML, "ou=people", "ou=staff", 1)
	if n, check, _ := s.Activate(ctx, []byte(changed)); n != 0 || check.OK() || f.ldap.count() != 2 {
		t.Fatalf("%d %+v", n, check)
	}
	// Validate runs the test too.
	if check, _ := s.Validate(ctx, []byte(changed)); check.OK() || !check.LDAPTested {
		t.Fatalf("%+v", check)
	}
	// Invalid LDAP settings are reported without calling the tester.
	before := f.ldap.count()
	_, check, _ = s.Activate(ctx, []byte(strings.Replace(ldapYAML, "(uid=%s)", "(uid=x)", 1)))
	if check.OK() || f.ldap.count() != before {
		t.Fatalf("%+v", check)
	}
}

func TestLDAPChangedWithoutTesterWarns(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.secrets.Put(ctx, "ldap-bind-password", []byte("pw"))
	s, err := Open(Options{Env: f.env, Secrets: f.secrets, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	n, check, err := s.Activate(ctx, []byte(ldapYAML))
	if err != nil || n != 2 || check.LDAPTested || len(check.Warnings) == 0 {
		t.Fatalf("%d %+v %v", n, check, err)
	}
}

func TestRollbackCreatesNewGeneration(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	v2 := "# v2\nscheduler:\n  admit_wait: 41s\n"
	s.Activate(ctx, []byte(v2))
	s.Activate(ctx, []byte("scheduler:\n  admit_wait: 42s\n"))
	if err := s.Rollback(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if s.Current().Generation != 4 || s.Current().Scheduler.AdmitWait != 41*time.Second || f.target() != "000004.yaml" {
		t.Fatalf("%d %v %s", s.Current().Generation, s.Current().Scheduler.AdmitWait, f.target())
	}
	if got, _ := s.Read(ctx, 4); string(got) != v2 {
		t.Fatalf("%q", got)
	}
	// History intact.
	if got, _ := s.Read(ctx, 3); !strings.Contains(string(got), "42s") {
		t.Fatalf("generation 3 modified: %q", got)
	}
	if gens, _ := s.Generations(ctx); len(gens) != 4 {
		t.Fatalf("%+v", gens)
	}
	// Rolling back to the initial defaults works too.
	if err := s.Rollback(ctx, 1); err != nil || s.Current().Generation != 5 {
		t.Fatal(err, s.Current().Generation)
	}
	if err := s.Rollback(ctx, 99); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if err := s.Rollback(ctx, 0); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := s.Read(ctx, 99); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestRollbackSkipsLDAPTestButRevalidates(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.secrets.Put(ctx, "ldap-bind-password", []byte("pw"))
	s := f.open()
	s.Activate(ctx, []byte(ldapYAML))
	s.Activate(ctx, []byte("scheduler:\n  admit_wait: 41s\n"))
	f.ldap.err = errors.New("down")
	calls := f.ldap.count()
	if err := s.Rollback(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if f.ldap.count() != calls {
		t.Fatal("rollback ran the LDAP test")
	}
	// A secret that vanished since blocks the rollback and changes nothing.
	f.secrets.Delete(ctx, "ldap-bind-password")
	err := s.Rollback(ctx, 2)
	if err == nil || !strings.Contains(err.Error(), "ldap.bind_password_secret") {
		t.Fatalf("%v", err)
	}
	if s.Current().Generation != 4 {
		t.Fatal("state changed")
	}
}

func TestRecoverMissingCurrent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	s.Activate(ctx, []byte("scheduler:\n  admit_wait: 41s\n"))
	s.Activate(ctx, []byte("scheduler:\n  admit_wait: 42s\n"))
	if err := os.Remove(filepath.Join(f.dir(), "current")); err != nil {
		t.Fatal(err)
	}
	s2 := f.open()
	if s2.Current().Generation != 3 || f.target() != "000003.yaml" {
		t.Fatalf("%d %s", s2.Current().Generation, f.target())
	}
}

func TestRecoverDanglingCurrent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	s.Activate(ctx, []byte("scheduler:\n  admit_wait: 41s\n"))
	os.Remove(filepath.Join(f.dir(), "000002.yaml"))
	s2 := f.open()
	if s2.Current().Generation != 1 || f.target() != "000001.yaml" {
		t.Fatalf("%d %s", s2.Current().Generation, f.target())
	}
	// Numbers are never reused below the highest present file.
	if n, _, _ := s2.Activate(ctx, []byte("")); n != 2 {
		t.Fatal(n)
	}
}

func TestRecoverSkipsIncompleteGeneration(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	s.Activate(ctx, []byte("scheduler:\n  admit_wait: 41s\n"))
	// A truncated and a garbage generation above, link gone.
	os.WriteFile(filepath.Join(f.dir(), "000003.yaml"), []byte("scheduler:\n  admit_"), 0o600)
	os.WriteFile(filepath.Join(f.dir(), "000004.yaml"), nil, 0o600)
	os.WriteFile(filepath.Join(f.dir(), "000005.yaml"), []byte("direct:\n  rsa_bits: 1\n"), 0o600)
	os.Remove(filepath.Join(f.dir(), "current"))
	s2 := f.open()
	if s2.Current().Generation != 4 {
		// 000004 is empty, which is a valid configuration (all defaults).
		t.Fatalf("got generation %d", s2.Current().Generation)
	}
	os.Remove(filepath.Join(f.dir(), "000004.yaml"))
	os.Remove(filepath.Join(f.dir(), "current"))
	s3 := f.open()
	if s3.Current().Generation != 2 || f.target() != "000002.yaml" {
		t.Fatalf("%d %s", s3.Current().Generation, f.target())
	}
	if n, _, _ := s3.Activate(ctx, nil); n != 6 {
		t.Fatalf("next number %d, want 6", n)
	}
}

func TestRecoverCurrentPointingAtCorruptGeneration(t *testing.T) {
	f := newFixture(t)
	s := f.open()
	s.Activate(context.Background(), []byte("scheduler:\n  admit_wait: 41s\n"))
	os.WriteFile(filepath.Join(f.dir(), "000002.yaml"), []byte("a: [\n"), 0o600)
	s2 := f.open()
	if s2.Current().Generation != 1 || f.target() != "000001.yaml" {
		t.Fatalf("%d %s", s2.Current().Generation, f.target())
	}
}

func TestCurrentValidWithHigherUnactivatedGeneration(t *testing.T) {
	f := newFixture(t)
	s := f.open()
	s.Activate(context.Background(), []byte("scheduler:\n  admit_wait: 41s\n"))
	// Crash between writing generation 3 and switching: current stays 2.
	os.WriteFile(filepath.Join(f.dir(), "000003.yaml"), []byte("scheduler:\n  admit_wait: 43s\n"), 0o600)
	s2 := f.open()
	if s2.Current().Generation != 2 {
		t.Fatalf("%d", s2.Current().Generation)
	}
	if n, _, _ := s2.Activate(context.Background(), nil); n != 4 {
		t.Fatalf("next %d", n)
	}
}

func TestNoUsableGenerationIsAnError(t *testing.T) {
	f := newFixture(t)
	os.MkdirAll(f.dir(), 0o700)
	os.WriteFile(filepath.Join(f.dir(), "000001.yaml"), []byte("bogus: 1\n"), 0o600)
	if _, err := Open(Options{Env: f.env}); err == nil {
		t.Fatal("opened with only an invalid generation")
	}
}

func TestStaleTempFilesRemoved(t *testing.T) {
	f := newFixture(t)
	f.open()
	os.WriteFile(filepath.Join(f.dir(), ".tmp-123"), []byte("x"), 0o600)
	os.Symlink("000001.yaml", filepath.Join(f.dir(), ".tmp-link-2"))
	f.open()
	if m, _ := filepath.Glob(filepath.Join(f.dir(), ".tmp-*")); len(m) != 0 {
		t.Fatalf("%v", m)
	}
}

func TestSubscribe(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	ch, cancel := s.Subscribe()
	select {
	case <-ch:
		t.Fatal("notified for the initial state")
	default:
	}
	s.Activate(ctx, []byte("scheduler:\n  admit_wait: 41s\n"))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("no notification")
	}
	if s.Current().Generation != 2 {
		t.Fatal("not published before notification")
	}
	// Failed activation does not notify.
	s.Activate(ctx, []byte("bogus: 1"))
	select {
	case <-ch:
		t.Fatal("notified on failure")
	default:
	}
	// Coalescing: two changes without a reader leave one pending signal.
	s.Activate(ctx, []byte("scheduler:\n  admit_wait: 42s\n"))
	s.Rollback(ctx, 1)
	<-ch
	select {
	case <-ch:
		t.Fatal("notifications did not coalesce")
	default:
	}
	cancel()
	cancel() // idempotent
	if _, ok := <-ch; ok {
		t.Fatal("channel not closed")
	}
	s.Activate(ctx, nil) // must not panic with the subscription gone
}

func TestSubscribersConcurrent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	const subs, changes = 8, 25

	var wg sync.WaitGroup
	var ready sync.WaitGroup
	var lastSeen [subs]atomic.Int64
	for i := range subs {
		ch, cancel := s.Subscribe()
		wg.Add(1)
		ready.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			ready.Done()
			for range ch {
				g := int64(s.Current().Generation)
				lastSeen[i].Store(g)
				if g == changes+1 {
					return
				}
			}
		}()
	}
	ready.Wait()
	// Readers hammer Current while a writer applies; apply never blocks on
	// slow subscribers.
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if s.Current() == nil {
						t.Error("nil config")
					}
				}
			}
		}()
	}
	// A late cancel/subscribe churn while changes happen.
	churn := make(chan struct{})
	go func() {
		defer close(churn)
		for range 50 {
			_, c := s.Subscribe()
			c()
		}
	}()
	for i := range changes {
		src := "scheduler:\n  admit_wait: " + (time.Duration(30+i) * time.Second).String() + "\n"
		if _, check, err := s.Activate(ctx, []byte(src)); err != nil || !check.OK() {
			t.Fatalf("%v %+v", err, check)
		}
	}
	<-churn
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a subscriber missed the final state")
	}
	close(stop)
	readers.Wait()
	for i := range subs {
		if lastSeen[i].Load() != changes+1 {
			t.Errorf("subscriber %d last saw %d", i, lastSeen[i].Load())
		}
	}
}

func TestConcurrentActivateGetsDistinctNumbers(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := f.open()
	var mu sync.Mutex
	got := map[int]bool{}
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, check, err := s.Activate(ctx, []byte("scheduler:\n  admit_wait: "+(time.Duration(30+i)*time.Second).String()+"\n"))
			if err != nil || !check.OK() {
				t.Error(err, check)
				return
			}
			mu.Lock()
			got[n] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(got) != 10 || s.Current().Generation != 11 {
		t.Fatalf("%v current %d", got, s.Current().Generation)
	}
}

func TestStoreNeverStoresSecretValues(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.secrets.Put(ctx, "ldap-bind-password", []byte("TOPSECRET"))
	s := f.open()
	s.Activate(ctx, []byte(ldapYAML))
	ents, _ := filepath.Glob(filepath.Join(f.dir(), "0*.yaml"))
	for _, e := range ents {
		b, _ := os.ReadFile(e)
		if strings.Contains(string(b), "TOPSECRET") {
			t.Fatal("secret value in generation")
		}
	}
}

func TestStoreWithFileSecretsAndReadOnlyInterfaces(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	fs, err := NewFileSecrets(f.data)
	if err != nil {
		t.Fatal(err)
	}
	var _ core.SecretStore = fs
	s, err := Open(Options{Env: f.env, Secrets: fs, LDAP: f.ldap, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	var src core.ConfigSource = s
	var adm core.ConfigAdmin = s
	_ = src
	if _, check, _ := adm.Activate(ctx, []byte(ldapYAML)); check.OK() {
		t.Fatal("missing secret accepted")
	}
	fs.Put(ctx, "ldap-bind-password", []byte("pw"))
	if n, check, err := adm.Activate(ctx, []byte(ldapYAML)); err != nil || n != 2 || !check.OK() {
		t.Fatal(n, check, err)
	}
}

// A generation written while zones[].trusted_accounts existed (production
// has one) still loads at startup: the key is ignored with a deprecation
// warning, and a configuration rendered from it no longer has the key.
func TestDeprecatedTrustedAccountsGenerationLoads(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.open()
	old := "zones:\n  - name: example.com\n    trusted_accounts:\n      - https://acme-v02.api.letsencrypt.org/acme/acct/111111111\n"
	os.WriteFile(filepath.Join(f.dir(), "000002.yaml"), []byte(old), 0o600)
	os.Remove(filepath.Join(f.dir(), "current"))
	os.Symlink("000002.yaml", filepath.Join(f.dir(), "current"))

	s := f.open()
	cur := s.Current()
	if cur.Generation != 2 || f.target() != "000002.yaml" || len(cur.Zones) != 1 || cur.Zones[0].Name != "example.com" {
		t.Fatalf("generation %d (%s): %+v", cur.Generation, f.target(), cur.Zones)
	}
	check, err := s.Validate(ctx, []byte(old))
	if err != nil || !check.OK() || !slices.ContainsFunc(check.Warnings, func(w string) bool {
		return strings.Contains(w, "zones[0].trusted_accounts") && strings.Contains(w, "ignored")
	}) {
		t.Fatalf("validate: %v %+v", err, check)
	}
	if out, err := Marshal(cur); err != nil || strings.Contains(string(out), "trusted_accounts") {
		t.Fatalf("rendered:\n%s %v", out, err)
	}
	// Activating it again (the editor shows the current YAML) also works.
	if n, check, err := s.Activate(ctx, []byte(old)); err != nil || n != 3 || len(check.Warnings) == 0 {
		t.Fatalf("activate: %d %+v %v", n, check, err)
	}
}
