package config

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"tls-broker/internal/core"
)

// Options configures a Store.
type Options struct {
	// Env supplies the process-level settings merged into every Config.
	Env Env
	// Secrets, when set, is used to check that every secret a candidate
	// configuration names exists.
	Secrets core.SecretStore
	// LDAP, when set, tests changed LDAP settings before activation.
	LDAP core.LDAPTester
	// Logger receives recovery and activation messages; slog.Default() when
	// nil. Secret values are never logged.
	Logger *slog.Logger
}

// Store is the generation store under <data>/config (architecture §15). It
// implements core.ConfigSource and core.ConfigAdmin.
//
// Layout: immutable files 000001.yaml, 000002.yaml, ... and a "current"
// symlink to the active one. A new generation is written to a temporary file,
// fsynced, linked to its final name, and then "current" is switched by
// renaming a fresh symlink over it, with the directory fsynced after each
// step. History is append-only: Rollback writes a new generation holding the
// old content.
type Store struct {
	opts Options
	dir  string
	log  *slog.Logger

	mu  sync.Mutex // serializes Activate and Rollback (and their LDAP test)
	cur atomic.Pointer[core.Config]

	subMu sync.Mutex
	subs  map[int]chan struct{}
	next  int
}

var (
	_ core.ConfigSource = (*Store)(nil)
	_ core.ConfigAdmin  = (*Store)(nil)
)

const currentLink = "current"

var genFileRe = regexp.MustCompile(`^([0-9]{6,})\.yaml$`)

func genFile(n int) string { return fmt.Sprintf("%06d.yaml", n) }

// Open opens the store of opts.Env.DataDir, creating it and writing generation
// 000001 from the defaults on first start. A missing, dangling or unreadable
// "current" link is repaired by pointing it at the highest generation that
// parses and validates. It fails when generations exist but none is usable.
func Open(opts Options) (*Store, error) {
	if opts.Env.DataDir == "" {
		return nil, errors.New("config: data directory is not set")
	}
	s := &Store{opts: opts, dir: filepath.Join(opts.Env.DataDir, "config"), subs: map[int]chan struct{}{}, log: opts.Logger}
	if s.log == nil {
		s.log = slog.Default()
	}
	if err := ensureDir(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("config directory: %w", err)
	}
	s.removeTemps()

	nums, err := s.numbers()
	if err != nil {
		return nil, err
	}
	if len(nums) == 0 {
		return s.bootstrap()
	}

	if n, ok := s.currentNumber(); ok {
		if cfg, _, err := s.load(n); err == nil {
			s.cur.Store(cfg)
			return s, nil
		} else {
			s.log.Warn("config: current generation is unusable, recovering", "generation", n, "error", err)
		}
	} else {
		s.log.Warn("config: current link missing or dangling, recovering")
	}
	for _, n := range slices.Backward(nums) {
		cfg, _, err := s.load(n)
		if err != nil {
			s.log.Warn("config: skipping unusable generation", "generation", n, "error", err)
			continue
		}
		if err := s.switchTo(n); err != nil {
			return nil, err
		}
		s.log.Warn("config: recovered", "generation", n)
		s.cur.Store(cfg)
		return s, nil
	}
	return nil, fmt.Errorf("config: %s holds %d generation file(s) but none is valid; fix or remove them", s.dir, len(nums))
}

// bootstrap writes generation 1 from the defaults.
func (s *Store) bootstrap() (*Store, error) {
	data := DefaultYAML()
	cfg, rep := Parse(data, s.opts.Env, 1)
	if !rep.OK() {
		return nil, fmt.Errorf("config: default configuration is invalid with this environment: %w", rep.Errors)
	}
	if err := s.writeGeneration(1, data); err != nil {
		return nil, err
	}
	if err := s.switchTo(1); err != nil {
		return nil, err
	}
	s.cur.Store(cfg)
	s.log.Info("config: wrote default generation", "generation", 1)
	return s, nil
}

// removeTemps deletes leftovers of interrupted writes.
func (s *Store) removeTemps() {
	ents, _ := os.ReadDir(s.dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			os.Remove(filepath.Join(s.dir, e.Name()))
		}
	}
}

// numbers lists the generation numbers present, ascending.
func (s *Store) numbers() ([]int, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var out []int
	for _, e := range ents {
		m := genFileRe.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 1 {
			continue
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

// currentNumber resolves the "current" link to a generation number; false if
// the link is missing, dangling or points anywhere but a generation file.
func (s *Store) currentNumber() (int, bool) {
	target, err := os.Readlink(filepath.Join(s.dir, currentLink))
	if err != nil {
		return 0, false
	}
	m := genFileRe.FindStringSubmatch(target)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 1 {
		return 0, false
	}
	if _, err := os.Stat(filepath.Join(s.dir, target)); err != nil {
		return 0, false
	}
	return n, true
}

// load reads and validates generation n (syntax and semantics; no LDAP test,
// no secret existence check, so a deleted secret never blocks start-up).
func (s *Store) load(n int) (*core.Config, []byte, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, genFile(n)))
	if err != nil {
		return nil, nil, err
	}
	cfg, rep := Parse(data, s.opts.Env, n)
	if !rep.OK() {
		return nil, nil, rep.Errors
	}
	return cfg, data, nil
}

// writeGeneration durably creates the immutable file for generation n and
// fails if it already exists.
func (s *Store) writeGeneration(n int, data []byte) error {
	tmp, err := writeTemp(s.dir, data, 0o600)
	if err != nil {
		return fmt.Errorf("config: write generation %d: %w", n, err)
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, filepath.Join(s.dir, genFile(n))); err != nil {
		return fmt.Errorf("config: create generation %d: %w", n, err)
	}
	return syncDir(s.dir)
}

// switchTo atomically points "current" at generation n.
func (s *Store) switchTo(n int) error {
	tmp := filepath.Join(s.dir, fmt.Sprintf(".tmp-link-%d", n))
	os.Remove(tmp)
	if err := os.Symlink(genFile(n), tmp); err != nil {
		return fmt.Errorf("config: switch to generation %d: %w", n, err)
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, currentLink)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: switch to generation %d: %w", n, err)
	}
	return syncDir(s.dir)
}

// Current implements core.ConfigSource.
func (s *Store) Current() *core.Config { return s.cur.Load() }

// Subscribe implements core.ConfigSource. Notifications never block the
// publisher: the channel has capacity 1 and a pending notification absorbs
// further ones, and the configuration is published before it is signalled, so
// a subscriber that calls Current after receiving always sees the final state.
func (s *Store) Subscribe() (<-chan struct{}, func()) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	id := s.next
	s.next++
	ch := make(chan struct{}, 1)
	s.subs[id] = ch
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			s.subMu.Lock()
			defer s.subMu.Unlock()
			delete(s.subs, id)
			close(ch)
		})
	}
}

func (s *Store) publish(cfg *core.Config) {
	s.cur.Store(cfg)
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for _, ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Generations implements core.ConfigAdmin.
func (s *Store) Generations(_ context.Context) ([]core.ConfigGeneration, error) {
	nums, err := s.numbers()
	if err != nil {
		return nil, err
	}
	active := s.Current().Generation
	out := make([]core.ConfigGeneration, 0, len(nums))
	for _, n := range slices.Backward(nums) {
		g := core.ConfigGeneration{Number: n, Active: n == active}
		if fi, err := os.Stat(filepath.Join(s.dir, genFile(n))); err == nil {
			g.CreatedAt = fi.ModTime().UTC()
		}
		out = append(out, g)
	}
	return out, nil
}

// Read implements core.ConfigAdmin.
func (s *Store) Read(_ context.Context, number int) ([]byte, error) {
	if number < 1 {
		return nil, fmt.Errorf("generation %d: %w", number, core.ErrNotFound)
	}
	data, err := os.ReadFile(filepath.Join(s.dir, genFile(number)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("generation %d: %w", number, core.ErrNotFound)
	}
	return data, err
}

// Validate implements core.ConfigAdmin. Nothing is stored.
func (s *Store) Validate(ctx context.Context, yaml []byte) (core.ConfigCheck, error) {
	_, check := s.check(ctx, yaml, s.Current().Generation+1, true)
	return check, nil
}

// check runs every validation step on candidate YAML.
func (s *Store) check(ctx context.Context, data []byte, number int, testLDAP bool) (*core.Config, core.ConfigCheck) {
	cfg, rep := parse(data, s.opts.Env, number)
	errs, warns := rep.Errors, rep.Warnings
	if cfg != nil && s.opts.Secrets != nil {
		if have, err := s.opts.Secrets.List(ctx); err != nil {
			errs = append(errs, Problem{Message: "cannot list secrets: " + err.Error()})
		} else {
			errs = append(errs, CheckSecrets(cfg, have)...)
		}
	}
	var check core.ConfigCheck
	if cfg != nil && testLDAP && cfg.LDAP.URL != "" && cfg.LDAP != s.Current().LDAP && !hasPrefixPath(errs, "ldap") {
		if s.opts.LDAP == nil {
			warns = append(warns, Problem{Path: "ldap", Message: "LDAP settings changed but no LDAP tester is available; not tested"})
		} else {
			check.LDAPTested = true
			if err := s.opts.LDAP.TestLDAP(ctx, cfg.LDAP); err != nil {
				check.LDAPError = err.Error()
				errs = append(errs, Problem{Path: "ldap", Message: "LDAP test failed: " + err.Error()})
			}
		}
	}
	check.Errors = errs.Strings()
	check.Warnings = warns.Strings()
	return cfg, check
}

func hasPrefixPath(ps Problems, prefix string) bool {
	for _, p := range ps {
		if p.Path == prefix || strings.HasPrefix(p.Path, prefix+".") {
			return true
		}
	}
	return false
}

// nextNumber is one more than the highest generation file present, so an
// unactivated leftover is never overwritten.
func (s *Store) nextNumber() (int, error) {
	nums, err := s.numbers()
	if err != nil {
		return 0, err
	}
	if len(nums) == 0 {
		return 1, nil
	}
	return nums[len(nums)-1] + 1, nil
}

// Activate implements core.ConfigAdmin: validate (including the LDAP test
// when the LDAP settings changed), store as the next generation, switch
// "current" and notify subscribers. When validation fails nothing is stored
// and the active generation is untouched.
func (s *Store) Activate(ctx context.Context, yaml []byte) (int, core.ConfigCheck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.nextNumber()
	if err != nil {
		return 0, core.ConfigCheck{}, err
	}
	cfg, check := s.check(ctx, yaml, n, true)
	if !check.OK() {
		return 0, check, nil
	}
	if err := s.commit(n, yaml, cfg); err != nil {
		return 0, check, err
	}
	return n, check, nil
}

// Rollback implements core.ConfigAdmin. The old content becomes a NEW
// generation (history stays append-only); it is re-validated without the LDAP
// test. A content that no longer validates is refused with a Problems error.
func (s *Store) Rollback(ctx context.Context, number int) error {
	data, err := s.Read(ctx, number)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.nextNumber()
	if err != nil {
		return err
	}
	cfg, check := s.check(ctx, data, n, false)
	if !check.OK() {
		return fmt.Errorf("generation %d no longer validates: %s", number, strings.Join(check.Errors, "; "))
	}
	return s.commit(n, data, cfg)
}

func (s *Store) commit(n int, data []byte, cfg *core.Config) error {
	if err := s.writeGeneration(n, data); err != nil {
		return err
	}
	if err := s.switchTo(n); err != nil {
		return err
	}
	s.publish(cfg)
	s.log.Info("config: activated generation", "generation", n)
	return nil
}
