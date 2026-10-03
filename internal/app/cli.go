package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tls-broker/internal/audit"
	"tls-broker/internal/auth"
	"tls-broker/internal/config"
	"tls-broker/internal/core"
	"tls-broker/internal/store"
)

// The functions below back the maintenance subcommands of cmd/tls-broker.
// They work on the data directory directly and are safe to run next to a
// running broker (SQLite serializes writers; configuration generations are
// numbered from the files present). Changes the running broker caches are
// called out per function.

// ConfigValidate parses and validates a configuration file the way the UI
// would before activating it, including the check that every secret it
// names exists in <data>/secrets (skipped when the data directory has no
// secrets yet). It writes the findings to out and returns an error when
// there are errors.
func ConfigValidate(ctx context.Context, env config.Env, path string, out io.Writer) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cfg, rep := config.Parse(data, env, 0)
	if cfg != nil {
		if _, err := os.Stat(filepath.Join(env.DataDir, "secrets")); err == nil {
			sec, err := config.NewFileSecrets(env.DataDir)
			if err != nil {
				return err
			}
			have, err := sec.List(ctx)
			if err != nil {
				return err
			}
			rep.Errors = append(rep.Errors, config.CheckSecrets(cfg, have)...)
		}
	}
	return report(out, rep.Errors.Strings(), rep.Warnings.Strings(), "valid")
}

// ConfigApply activates a configuration file as the next generation, with
// every check the UI runs (including the LDAP test when the LDAP settings
// changed). A running broker keeps its active configuration until it is
// restarted; then it starts on the new generation.
func ConfigApply(ctx context.Context, env config.Env, path string, out io.Writer, log *slog.Logger) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sec, err := config.NewFileSecrets(env.DataDir)
	if err != nil {
		return err
	}
	tester := &lazyLDAPTester{}
	cs, err := config.Open(config.Options{Env: env, Secrets: sec, LDAP: tester, Logger: log})
	if err != nil {
		return err
	}
	tester.set(auth.NewLDAP(cs, sec))
	n, check, err := cs.Activate(ctx, data)
	if err != nil {
		return err
	}
	if err := report(out, check.Errors, check.Warnings, ""); err != nil {
		return err
	}
	fmt.Fprintf(out, "activated generation %06d; restart the broker to use it\n", n)
	return nil
}

func report(out io.Writer, errs, warns []string, okText string) error {
	for _, w := range warns {
		fmt.Fprintln(out, "warning:", w)
	}
	for _, e := range errs {
		fmt.Fprintln(out, "error:", e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d error(s)", len(errs))
	}
	if okText != "" {
		fmt.Fprintln(out, okText)
	}
	return nil
}

// SetRole sets the role of an LDAP user (local: the break-glass user record)
// in the database, creating the user record when it does not exist yet, so
// an administrator can be appointed before their first login. A user listed
// in TLS_BROKER_ADMINS is made admin again at every login.
func SetRole(ctx context.Context, env config.Env, username string, local bool, role core.Role, out io.Writer) error {
	if !role.Valid() {
		return fmt.Errorf("unknown role %q (normal, wildcard_allowed, admin)", role)
	}
	return withUser(ctx, env, username, local, true, func(st *store.Store, u *core.User) (string, error) {
		if err := st.Users().SetRole(ctx, u.ID, role); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s: role=%s", u.Username, role), nil
	}, out)
}

// SetBlocked blocks or unblocks a user. Blocking takes effect on the user's
// next request; their sessions stay but carry no rights.
func SetBlocked(ctx context.Context, env config.Env, username string, local, blocked bool, out io.Writer) error {
	return withUser(ctx, env, username, local, false, func(st *store.Store, u *core.User) (string, error) {
		if err := st.Users().SetBlocked(ctx, u.ID, blocked); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s: blocked=%t", u.Username, blocked), nil
	}, out)
}

func withUser(ctx context.Context, env config.Env, username string, local, create bool,
	change func(*store.Store, *core.User) (string, error), out io.Writer) error {
	name := auth.NormalizeUsername(username)
	if name == "" {
		return errors.New("empty user name")
	}
	st, err := store.Open(filepath.Join(env.DataDir, "state.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	u, err := st.Users().GetByUsername(ctx, name, local)
	switch {
	case errors.Is(err, core.ErrNotFound) && create:
		if u, _, err = st.Users().Ensure(ctx, name, local, time.Now()); err != nil {
			return err
		}
	case errors.Is(err, core.ErrNotFound):
		return fmt.Errorf("no user %q (it appears after the first login)", name)
	case err != nil:
		return err
	}
	detail, err := change(st, u)
	if err != nil {
		return err
	}
	al, err := audit.Open(audit.Options{Dir: filepath.Join(env.DataDir, "audit")})
	if err != nil {
		return err
	}
	al.Record(ctx, core.AuditEvent{Type: core.AuditUserChange, Visibility: core.AuditVisibilityAdmin,
		Mode: core.ModeUI, Username: "cli", Result: core.AuditResultOK, Detail: detail + " (command line)"})
	if err := al.Close(); err != nil {
		return err
	}
	fmt.Fprintln(out, "saved:", detail)
	return nil
}

// Backup writes a consistent snapshot of the database to dest (which must
// not exist) with VACUUM INTO. Safe while the broker runs.
func Backup(ctx context.Context, env config.Env, dest string, out io.Writer) error {
	st, err := store.Open(filepath.Join(env.DataDir, "state.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Backup(ctx, dest); err != nil {
		return err
	}
	fmt.Fprintln(out, "database snapshot written to", dest)
	return nil
}

// HealthCheck asks the broker at env.Listen for /healthz and returns nil on
// 200. A wildcard listen host is probed on loopback. It is the container
// health check (the image has no shell or curl).
func HealthCheck(ctx context.Context, env config.Env) error {
	host, port, err := net.SplitHostPort(env.Listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
