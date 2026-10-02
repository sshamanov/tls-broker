package auth

import (
	"context"
	"sort"
	"sync"
	"time"

	"tls-broker/internal/core"
)

// memUsers is an in-memory core.UserStore.
type memUsers struct {
	mu   sync.Mutex
	next int64
	m    map[int64]*core.User
}

func newMemUsers() *memUsers { return &memUsers{m: map[int64]*core.User{}} }

func (s *memUsers) find(name string, local bool) *core.User {
	for _, u := range s.m {
		if u.Username == name && u.Local == local {
			return u
		}
	}
	return nil
}

func (s *memUsers) Ensure(_ context.Context, name string, local bool, now time.Time) (*core.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.find(name, local); u != nil {
		c := *u
		return &c, false, nil
	}
	s.next++
	u := &core.User{ID: s.next, Username: name, Role: core.RoleNormal, Local: local, CreatedAt: now}
	s.m[u.ID] = u
	c := *u
	return &c, true, nil
}

func (s *memUsers) Get(_ context.Context, id int64) (*core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.m[id]
	if !ok {
		return nil, core.ErrNotFound
	}
	c := *u
	return &c, nil
}

func (s *memUsers) GetByUsername(_ context.Context, name string, local bool) (*core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.find(name, local)
	if u == nil {
		return nil, core.ErrNotFound
	}
	c := *u
	return &c, nil
}

func (s *memUsers) List(context.Context) ([]core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []core.User
	for _, u := range s.m {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (s *memUsers) mutate(id int64, f func(*core.User)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.m[id]
	if !ok {
		return core.ErrNotFound
	}
	f(u)
	return nil
}

func (s *memUsers) SetRole(_ context.Context, id int64, r core.Role) error {
	return s.mutate(id, func(u *core.User) { u.Role = r })
}
func (s *memUsers) SetBlocked(_ context.Context, id int64, b bool) error {
	return s.mutate(id, func(u *core.User) { u.Blocked = b })
}
func (s *memUsers) TouchLogin(_ context.Context, id int64, at time.Time) error {
	return s.mutate(id, func(u *core.User) { u.LastLoginAt = at })
}

// memSessions is an in-memory core.SessionStore.
type memSessions struct {
	mu sync.Mutex
	m  map[string]core.Session
}

func newMemSessions() *memSessions { return &memSessions{m: map[string]core.Session{}} }

func (s *memSessions) Create(_ context.Context, x *core.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[x.TokenHash]; ok {
		return core.ErrConflict
	}
	s.m[x.TokenHash] = *x
	return nil
}
func (s *memSessions) Get(_ context.Context, h string) (*core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[h]
	if !ok {
		return nil, core.ErrNotFound
	}
	return &x, nil
}
func (s *memSessions) Touch(_ context.Context, h string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.m[h]; ok {
		x.LastSeenAt = at
		s.m[h] = x
	}
	return nil
}
func (s *memSessions) Delete(_ context.Context, h string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, h)
	return nil
}
func (s *memSessions) DeleteByUser(_ context.Context, id int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for h, x := range s.m {
		if x.UserID == id {
			delete(s.m, h)
			n++
		}
	}
	return n, nil
}
func (s *memSessions) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for h, x := range s.m {
		if !x.ExpiresAt.After(now) {
			delete(s.m, h)
			n++
		}
	}
	return n, nil
}
func (s *memSessions) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
