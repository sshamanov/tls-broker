package config

import (
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"tls-broker/internal/core"
)

// Environment variable names.
const (
	EnvDataDir            = "TLS_BROKER_DATA_DIR"
	EnvListen             = "TLS_BROKER_LISTEN"
	EnvAdmins             = "TLS_BROKER_ADMINS"
	EnvLocalAdminUser     = "TLS_BROKER_LOCAL_ADMIN_USER"
	EnvLocalAdminPassword = "TLS_BROKER_LOCAL_ADMIN_PASSWORD"
	EnvLogLevel           = "TLS_BROKER_LOG_LEVEL"
)

// Env is the process-level configuration read from the environment. It is
// not part of the YAML generations.
type Env struct {
	// DataDir is the absolute data root.
	DataDir string
	// Listen is the TCP listen address "host:port".
	Listen string
	// Bootstrap holds the administrators (lower-case, de-duplicated).
	Bootstrap core.BootstrapConfig
	// LogLevel is the minimum level to log.
	LogLevel slog.Level
}

// DefaultEnv returns the settings used for every variable that is unset.
func DefaultEnv() Env {
	d := core.DefaultConfig()
	return Env{DataDir: d.DataDir, Listen: d.Server.Listen, LogLevel: slog.LevelInfo}
}

// LoadEnv reads and validates the environment through lookup (os.LookupEnv in
// production). Unset and empty variables take their defaults. All problems are
// returned together, each with the variable name as path.
func LoadEnv(lookup func(string) (string, bool)) (Env, Problems) {
	get := func(k string) string {
		v, _ := lookup(k)
		return strings.TrimSpace(v)
	}
	env := DefaultEnv()
	var c collector

	if v := get(EnvDataDir); v != "" {
		env.DataDir = v
	}
	if !filepath.IsAbs(env.DataDir) {
		c.errf(EnvDataDir, "must be an absolute path, got %q", env.DataDir)
	} else {
		env.DataDir = filepath.Clean(env.DataDir)
	}

	if v := get(EnvListen); v != "" {
		env.Listen = v
	}
	if err := checkListen(env.Listen); err != "" {
		c.errf(EnvListen, "%s", err)
	}

	seen := map[string]bool{}
	for _, raw := range strings.Split(get(EnvAdmins), ",") {
		u := strings.ToLower(strings.TrimSpace(raw))
		if u == "" || seen[u] {
			continue
		}
		if i := strings.IndexFunc(u, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }); i >= 0 {
			c.errf(EnvAdmins, "user name %q contains whitespace or control characters", u)
			continue
		}
		seen[u] = true
		env.Bootstrap.Admins = append(env.Bootstrap.Admins, u)
	}

	user := get(EnvLocalAdminUser)
	// The password is taken verbatim apart from surrounding newlines: spaces
	// may be part of a plain password.
	pass, _ := lookup(EnvLocalAdminPassword)
	pass = strings.Trim(pass, "\r\n")
	switch {
	case user == "" && pass == "":
	case user == "":
		c.errf(EnvLocalAdminUser, "required when %s is set", EnvLocalAdminPassword)
	case pass == "":
		c.errf(EnvLocalAdminPassword, "required when %s is set", EnvLocalAdminUser)
	default:
		if strings.ContainsFunc(user, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			c.errf(EnvLocalAdminUser, "must not contain whitespace or control characters")
		}
		if strings.HasPrefix(pass, "$2") {
			if _, err := bcrypt.Cost([]byte(pass)); err != nil {
				c.errf(EnvLocalAdminPassword, "starts with \"$2\" so it is treated as a bcrypt hash, but is not a valid one (%v); in a compose .env file write every \"$\" as \"$$\"", err)
			}
		}
		env.Bootstrap.LocalAdminUser = user
		env.Bootstrap.LocalAdminPassword = pass
	}

	if v := get(EnvLogLevel); v != "" {
		switch strings.ToLower(v) {
		case "debug":
			env.LogLevel = slog.LevelDebug
		case "info":
			env.LogLevel = slog.LevelInfo
		case "warn", "warning":
			env.LogLevel = slog.LevelWarn
		case "error":
			env.LogLevel = slog.LevelError
		default:
			c.errf(EnvLogLevel, "must be one of debug, info, warn, error, got %q", v)
		}
	}
	return env, c.problems
}

func checkListen(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "must be host:port (for example 127.0.0.1:8080): " + err.Error()
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "port must be a number between 1 and 65535"
	}
	if strings.ContainsAny(host, " \t/") {
		return "invalid host " + strconv.Quote(host)
	}
	return ""
}

// Apply returns cfg with the process-level settings (data directory, listen
// address, bootstrap administrators) filled in. cfg is modified and returned.
func (e Env) Apply(cfg *core.Config) *core.Config {
	cfg.DataDir = e.DataDir
	cfg.Server.Listen = e.Listen
	cfg.Bootstrap = e.Bootstrap
	return cfg
}
