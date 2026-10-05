package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionAndUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "tls-broker ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"help"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "config validate") {
		t.Fatalf("help: %d", code)
	}
}

func TestCommands(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TLS_BROKER_DATA_DIR", dir)
	t.Setenv("TLS_BROKER_LOG_LEVEL", "error")
	var out, errOut bytes.Buffer
	for _, args := range [][]string{{"nonsense"}, {"config", "validate"}, {"user", "set-role", "x"}, {"user", "fly", "x"}, {"serve", "extra"},
		{"docs"}, {"docs", "pull"}, {"docs", "publish", "--nope"}, {"docs", "publish", "extra"}} {
		errOut.Reset()
		if code := run(args, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage") {
			t.Errorf("%v: %d %q", args, code, errOut.String())
		}
	}
	if code := run([]string{"user", "set-role", "--local", "Root", "admin"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "root: role=admin") {
		t.Fatalf("set-role: %d %q %q", code, out.String(), errOut.String())
	}
	if code := run([]string{"user", "block", "nobody"}, &out, &errOut); code != 1 {
		t.Fatalf("block unknown: %d", code)
	}

	// docs publish without the Confluence settings names them all.
	for _, k := range []string{"TLS_BROKER_CONFLUENCE_URL", "TLS_BROKER_CONFLUENCE_TOKEN", "TLS_BROKER_CONFLUENCE_PAGE_ID"} {
		t.Setenv(k, "")
	}
	errOut.Reset()
	if code := run([]string{"docs", "publish", "--dry-run"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "TLS_BROKER_CONFLUENCE_URL, TLS_BROKER_CONFLUENCE_TOKEN, TLS_BROKER_CONFLUENCE_PAGE_ID") {
		t.Fatalf("docs publish: %d %q", code, errOut.String())
	}

	t.Setenv("TLS_BROKER_LOG_LEVEL", "loud")
	errOut.Reset()
	if code := run([]string{"healthcheck"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "TLS_BROKER_LOG_LEVEL") {
		t.Fatalf("bad env: %d %q", code, errOut.String())
	}
}
