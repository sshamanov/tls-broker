package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"tls-broker/internal/core"
)

const (
	touchInterval     = time.Minute
	defaultSessionTTL = 30 * 24 * time.Hour
	maxAuditName      = 128
)

// Deps are the collaborators of Service.
type Deps struct {
	Config    core.ConfigSource
	Users     core.UserStore
	Sessions  core.SessionStore
	Directory core.Directory
	Clock     core.Clock
	Audit     core.Auditor
}

// Service implements core.Authenticator.
type Service struct {
	Deps
	throttle *throttle
}

var _ core.Authenticator = (*Service)(nil)

// New returns the authenticator.
func New(d Deps) *Service { return &Service{Deps: d, throttle: newThrottle()} }

// NormalizeUsername is the form usernames take everywhere: trimmed, lower case.
func NormalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func digest(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// constEq compares two strings in constant time regardless of length.
func constEq(a, b string) bool {
	da, db := digest(a), digest(b)
	return subtle.ConstantTimeCompare(da[:], db[:]) == 1
}

// Login implements core.Authenticator.
func (s *Service) Login(ctx context.Context, username, password string, src netip.Addr) (*core.Login, error) {
	name := NormalizeUsername(username)
	cfg := s.Config.Current()
	now := s.Clock.Now()
	key := throttleKey{name, src}

	if wait := s.throttle.check(key, now); wait > 0 {
		s.auditLogin(ctx, name, src, false, "throttled", "")
		return nil, &ThrottledError{RetryAfter: wait}
	}

	user, method, err := s.authenticate(ctx, cfg, name, password)
	if err != nil {
		reason := "invalid_credentials"
		if errors.Is(err, core.ErrDirectoryUnavailable) {
			reason = "directory_unavailable"
		} else if !errors.Is(err, core.ErrInvalidCredentials) {
			// Store or context failure: not the user's fault, not counted.
			return nil, err
		}
		if reason == "invalid_credentials" {
			s.throttle.fail(key, now)
		}
		s.auditLogin(ctx, name, src, false, reason, "")
		if reason == "directory_unavailable" {
			s.Audit.Record(ctx, core.AuditEvent{Type: core.AuditError, Result: core.AuditResultFailed,
				Reason: "ldap_unavailable", Detail: err.Error()})
		}
		return nil, err
	}
	s.throttle.reset(key)

	if err := s.Users.TouchLogin(ctx, user.ID, now); err != nil {
		return nil, err
	}
	user.LastLoginAt = now
	token := core.NewToken()
	ttl := cfg.Sessions.TTL
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	sess := core.Session{
		TokenHash:  core.HashToken(token),
		UserID:     user.ID,
		CSRFToken:  core.NewToken(),
		SourceIP:   src,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		LastSeenAt: now,
	}
	if err := s.Sessions.Create(ctx, &sess); err != nil {
		return nil, err
	}
	s.auditLogin(ctx, name, src, true, "", method)
	return &core.Login{Token: token, Session: sess, User: *user}, nil
}

// authenticate verifies the credentials and returns the up-to-date user row.
func (s *Service) authenticate(ctx context.Context, cfg *core.Config, name, password string) (*core.User, string, error) {
	if name == "" || password == "" {
		return nil, "", core.ErrInvalidCredentials
	}
	if local, ok := s.isLocalAdmin(cfg, name, password); local {
		if !ok {
			// The break-glass name is reserved: a wrong password is a wrong
			// password, counted by the throttle, never tried against LDAP
			// (that would leak the typed password to the directory and,
			// with LDAP down, make the break-glass password guessable
			// without any throttling, as "directory unavailable").
			return nil, "", core.ErrInvalidCredentials
		}
		u, err := s.localAdminUser(ctx, name)
		return u, "local", err
	}
	if err := s.Directory.Authenticate(ctx, name, password); err != nil {
		return nil, "", err
	}
	u, err := s.ldapUser(ctx, cfg, name)
	return u, "ldap", err
}

// isLocalAdmin reports whether name is the configured break-glass admin
// (local) and, if so, whether the password is right (ok). The password is
// only checked for that name: the bcrypt comparison would otherwise cost
// every login attempt of every user tens of milliseconds of CPU.
func (s *Service) isLocalAdmin(cfg *core.Config, name, password string) (local, ok bool) {
	b := cfg.Bootstrap
	if b.LocalAdminUser == "" || b.LocalAdminPassword == "" {
		return false, false
	}
	if !constEq(NormalizeUsername(b.LocalAdminUser), name) {
		return false, false
	}
	if strings.HasPrefix(b.LocalAdminPassword, "$2") {
		return true, bcrypt.CompareHashAndPassword([]byte(b.LocalAdminPassword), []byte(password)) == nil
	}
	return true, constEq(b.LocalAdminPassword, password)
}

// localAdminUser stores the break-glass admin as a Local user that is always
// an unblocked admin.
func (s *Service) localAdminUser(ctx context.Context, name string) (*core.User, error) {
	u, _, err := s.Users.Ensure(ctx, name, true, s.Clock.Now())
	if err != nil {
		return nil, err
	}
	if u.Role != core.RoleAdmin {
		if err := s.Users.SetRole(ctx, u.ID, core.RoleAdmin); err != nil {
			return nil, err
		}
		u.Role = core.RoleAdmin
	}
	if u.Blocked {
		if err := s.Users.SetBlocked(ctx, u.ID, false); err != nil {
			return nil, err
		}
		u.Blocked = false
	}
	return u, nil
}

func (s *Service) ldapUser(ctx context.Context, cfg *core.Config, name string) (*core.User, error) {
	u, _, err := s.Users.Ensure(ctx, name, false, s.Clock.Now())
	if err != nil {
		return nil, err
	}
	if u.Role != core.RoleAdmin && isBootstrapAdmin(cfg.Bootstrap.Admins, name) {
		if err := s.Users.SetRole(ctx, u.ID, core.RoleAdmin); err != nil {
			return nil, err
		}
		u.Role = core.RoleAdmin
	}
	return u, nil
}

func isBootstrapAdmin(admins []string, name string) bool {
	for _, a := range admins {
		if NormalizeUsername(a) == name {
			return true
		}
	}
	return false
}

// Session implements core.Authenticator.
func (s *Service) Session(ctx context.Context, token string) (*core.Session, *core.User, error) {
	if token == "" {
		return nil, nil, core.ErrNotFound
	}
	hash := core.HashToken(token)
	sess, err := s.Sessions.Get(ctx, hash)
	if err != nil {
		return nil, nil, err
	}
	now := s.Clock.Now()
	if !now.Before(sess.ExpiresAt) {
		if err := s.Sessions.Delete(ctx, hash); err != nil {
			return nil, nil, err
		}
		return nil, nil, core.ErrExpired
	}
	user, err := s.Users.Get(ctx, sess.UserID)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			_ = s.Sessions.Delete(ctx, hash)
		}
		return nil, nil, err
	}
	if now.Sub(sess.LastSeenAt) >= touchInterval {
		if err := s.Sessions.Touch(ctx, hash, now); err != nil {
			return nil, nil, err
		}
		sess.LastSeenAt = now
	}
	return sess, user, nil
}

// Logout implements core.Authenticator.
func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	hash := core.HashToken(token)
	sess, err := s.Sessions.Get(ctx, hash)
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		return err
	}
	if err := s.Sessions.Delete(ctx, hash); err != nil {
		return err
	}
	if sess != nil {
		ev := core.AuditEvent{Type: core.AuditLogout, Result: core.AuditResultOK, SourceIP: sess.SourceIP.String()}
		if u, err := s.Users.Get(ctx, sess.UserID); err == nil {
			ev.Username = u.Username
		}
		s.Audit.Record(ctx, ev)
	}
	return nil
}

// PurgeExpired deletes expired sessions and returns how many.
func (s *Service) PurgeExpired(ctx context.Context) (int, error) {
	return s.Sessions.DeleteExpired(ctx, s.Clock.Now())
}

// RunPurge purges expired sessions every interval until ctx is done.
func (s *Service) RunPurge(ctx context.Context, interval time.Duration) {
	for core.Sleep(ctx, s.Clock, interval) == nil {
		_, _ = s.PurgeExpired(ctx)
	}
}

func (s *Service) auditLogin(ctx context.Context, name string, src netip.Addr, ok bool, reason, method string) {
	if len(name) > maxAuditName {
		name = name[:maxAuditName]
	}
	ev := core.AuditEvent{
		Type:       core.AuditLogin,
		Visibility: core.AuditVisibilityAdmin,
		SourceIP:   src.String(),
		Username:   name,
		Result:     core.AuditResultOK,
		Detail:     method,
	}
	if !ok {
		ev.Result = core.AuditResultFailed
		ev.Reason = reason
	}
	s.Audit.Record(ctx, ev)
}
