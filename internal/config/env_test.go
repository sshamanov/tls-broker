package config

import (
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func lookupMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestLoadEnvDefaults(t *testing.T) {
	env, probs := LoadEnv(lookupMap(nil))
	if len(probs) != 0 {
		t.Fatal(probs)
	}
	if env.DataDir != "/var/lib/tls-broker" || env.Listen != "127.0.0.1:8080" || env.LogLevel != slog.LevelInfo {
		t.Fatalf("defaults: %+v", env)
	}
	if len(env.Bootstrap.Admins) != 0 || env.Bootstrap.LocalAdminUser != "" {
		t.Fatalf("bootstrap: %+v", env.Bootstrap)
	}
}

func TestLoadEnvValues(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	env, probs := LoadEnv(lookupMap(map[string]string{
		EnvDataDir: "/data/", EnvListen: "0.0.0.0:9000", EnvAdmins: " Alice, bob ,,alice",
		EnvLocalAdminUser: "root", EnvLocalAdminPassword: string(hash), EnvLogLevel: "DEBUG",
	}))
	if len(probs) != 0 {
		t.Fatal(probs)
	}
	if env.DataDir != "/data" || env.Listen != "0.0.0.0:9000" || env.LogLevel != slog.LevelDebug {
		t.Fatalf("%+v", env)
	}
	if got := strings.Join(env.Bootstrap.Admins, ","); got != "alice,bob" {
		t.Fatalf("admins %q", got)
	}
	if env.Bootstrap.LocalAdminUser != "root" || env.Bootstrap.LocalAdminPassword != string(hash) {
		t.Fatalf("local admin: %+v", env.Bootstrap)
	}
}

func TestLoadEnvPlainPasswordKeepsSpaces(t *testing.T) {
	env, probs := LoadEnv(lookupMap(map[string]string{EnvLocalAdminUser: "root", EnvLocalAdminPassword: " pa ss \n"}))
	if len(probs) != 0 || env.Bootstrap.LocalAdminPassword != " pa ss " {
		t.Fatalf("%v %q", probs, env.Bootstrap.LocalAdminPassword)
	}
}

func TestLoadEnvProblemsAllAtOnce(t *testing.T) {
	_, probs := LoadEnv(lookupMap(map[string]string{
		EnvDataDir: "relative/dir", EnvListen: "nonsense", EnvAdmins: "ok,bad name",
		EnvLocalAdminUser: "root", EnvLogLevel: "loud",
	}))
	want := map[string]bool{EnvDataDir: false, EnvListen: false, EnvAdmins: false, EnvLocalAdminPassword: false, EnvLogLevel: false}
	for _, p := range probs {
		want[p.Path] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing problem for %s (got %v)", k, probs)
		}
	}
}

func TestLoadEnvListenPorts(t *testing.T) {
	for _, bad := range []string{"127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:http"} {
		if _, probs := LoadEnv(lookupMap(map[string]string{EnvListen: bad})); len(probs) != 1 {
			t.Errorf("%q: %v", bad, probs)
		}
	}
	for _, good := range []string{":8080", "[::1]:8080", "localhost:80"} {
		if _, probs := LoadEnv(lookupMap(map[string]string{EnvListen: good})); len(probs) != 0 {
			t.Errorf("%q: %v", good, probs)
		}
	}
}

func TestLoadEnvLocalAdmin(t *testing.T) {
	cases := map[string]map[string]string{
		"password without user": {EnvLocalAdminPassword: "x"},
		"user without password": {EnvLocalAdminUser: "x"},
		"mangled bcrypt hash":   {EnvLocalAdminUser: "x", EnvLocalAdminPassword: "$2a$10$abc"},
	}
	for name, env := range cases {
		if _, probs := LoadEnv(lookupMap(env)); len(probs) != 1 {
			t.Errorf("%s: %v", name, probs)
		}
	}
}

func TestEnvApply(t *testing.T) {
	env, _ := LoadEnv(lookupMap(map[string]string{EnvDataDir: "/d", EnvListen: "127.0.0.1:1", EnvAdmins: "a"}))
	cfg := env.Apply(testConfig())
	if cfg.DataDir != "/d" || cfg.Server.Listen != "127.0.0.1:1" || cfg.Bootstrap.Admins[0] != "a" {
		t.Fatalf("%+v", cfg)
	}
}
