package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tls-broker/internal/config"
	"tls-broker/internal/confluence/confluencetest"
	"tls-broker/internal/guide"
)

const docsToken = "pat-0123456789-secret"

func docsEnv(srv *confluencetest.Server, rootID string) func(string) (string, bool) {
	m := map[string]string{EnvConfluenceURL: srv.URL, EnvConfluenceToken: docsToken, EnvConfluencePageID: rootID}
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestDocsPublish(t *testing.T) {
	ctx := context.Background()
	srv := confluencetest.New(docsToken, "123456", "admin", "TLS Broker")
	defer srv.Close()

	env := config.DefaultEnv()
	env.DataDir = t.TempDir()
	// The active configuration supplies the broker URL (the default
	// generation's external_url).
	cs, err := config.Open(config.Options{Env: env, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ext := cs.Current().Server.ExternalURL

	// What the multi-page publisher left behind, and a page of someone else.
	srv.Add(confluencetest.Page{ID: "501", Space: "admin", ParentID: "123456", Title: "TLS Broker: Getting started"})
	srv.Add(confluencetest.Page{ID: "502", Space: "admin", ParentID: "123456", Title: "TLS Broker: API reference"})
	srv.Add(confluencetest.Page{ID: "503", Space: "admin", ParentID: "123456", Title: "Meeting notes"})

	guideDir := filepath.Join("..", "..", "docs")
	outDir := filepath.Join(t.TempDir(), "xhtml")
	var out bytes.Buffer
	o := DocsOptions{DryRun: true, OutDir: outDir, Dir: guideDir, Lookup: docsEnv(srv, "123456")}
	if err := DocsPublish(ctx, env, o, &out); err != nil {
		t.Fatalf("dry run: %v\n%s", err, out.String())
	}
	for _, want := range []string{
		`update     "TLS Broker"  id 123456, version 1 -> 2  (guide.md, root page)`,
		`obsolete   "TLS Broker: Getting started"  id 501  (kept; pruning deletes it)`,
		`not from the guide, left alone: "Meeting notes"  id 503`,
		"obsolete pages are kept; run with --prune to delete them",
		"dry run: nothing was changed",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run output lacks %s", want)
		}
	}
	if srv.Writes() != 0 {
		t.Fatalf("dry run: %d writes\n%s", srv.Writes(), out.String())
	}
	b, err := os.ReadFile(filepath.Join(outDir, "guide.xhtml"))
	if err != nil || !strings.Contains(string(b), notePrefix+" (version dev)") || strings.Contains(string(b), guide.Placeholder) ||
		!strings.Contains(string(b), `<ac:link ac:anchor="getting-access">`) {
		t.Fatalf("written body: %v\n%s", err, b)
	}

	// Dry run with --prune: the deletions are planned, nothing is written.
	out.Reset()
	o.OutDir, o.Prune = "", true
	if err := DocsPublish(ctx, env, o, &out); err != nil || srv.Writes() != 0 ||
		!strings.Contains(out.String(), `delete     "TLS Broker: Getting started"  id 501`) ||
		!strings.Contains(out.String(), `delete     "TLS Broker: API reference"  id 502`) ||
		strings.Contains(out.String(), "run with --prune") {
		t.Fatalf("dry run with prune: %v, %d writes\n%s", err, srv.Writes(), out.String())
	}

	out.Reset()
	o.DryRun = false
	if err := DocsPublish(ctx, env, o, &out); err != nil {
		t.Fatalf("publish: %v\n%s", err, out.String())
	}
	if kids := srv.Children("123456"); len(kids) != 1 || kids[0].Title != "Meeting notes" {
		t.Fatalf("children %+v", kids)
	}
	root, _ := srv.Get("123456")
	if root.Title != "TLS Broker" || root.Messages[0] != "tls-broker dev" || !strings.Contains(root.Body, ext) ||
		!strings.Contains(root.Body, "API reference") {
		t.Errorf("root %+v", root)
	}

	// Again: nothing to do.
	out.Reset()
	w := srv.Writes()
	if err := DocsPublish(ctx, env, o, &out); err != nil || srv.Writes() != w || !strings.Contains(out.String(), "unchanged  ") || strings.Contains(out.String(), "update ") {
		t.Fatalf("second publish: %v, writes %d->%d\n%s", err, w, srv.Writes(), out.String())
	}

	// --broker-url wins over the configuration.
	out.Reset()
	o.DryRun, o.BrokerURL = true, "https://tls.example.org/"
	if err := DocsPublish(ctx, env, o, &out); err != nil || !strings.Contains(out.String(), "broker URL https://tls.example.org\n") ||
		!strings.Contains(out.String(), `update     "TLS Broker"`) {
		t.Fatalf("broker URL flag: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), docsToken) {
		t.Error("token in output")
	}
}

func TestDocsPublishErrors(t *testing.T) {
	ctx := context.Background()
	srv := confluencetest.New(docsToken, "123456", "admin", "TLS Broker")
	defer srv.Close()
	env := config.DefaultEnv()
	env.DataDir = t.TempDir()
	guideDir := filepath.Join("..", "..", "docs")

	err := DocsPublish(ctx, env, DocsOptions{Lookup: func(string) (string, bool) { return "", false }}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), EnvConfluenceURL+", "+EnvConfluenceToken+", "+EnvConfluencePageID) {
		t.Errorf("missing env: %v", err)
	}

	// No configuration yet and no flag: the broker URL is unknown.
	err = DocsPublish(ctx, env, DocsOptions{Dir: guideDir, Lookup: docsEnv(srv, "123456")}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--broker-url") {
		t.Errorf("no broker URL: %v", err)
	}
	if _, err := os.Stat(filepath.Join(env.DataDir, "config")); err == nil {
		t.Error("docs publish created the configuration directory")
	}

	for name, tc := range map[string]struct {
		lookup func(string) (string, bool)
		want   string
	}{
		"not found": {docsEnv(srv, "42"), "root page 42 does not exist"},
		"bad id":    {docsEnv(srv, "x42"), "numeric ID"},
		"bad token": {func(k string) (string, bool) {
			if k == EnvConfluenceToken {
				return "wrong-" + docsToken, true
			}
			return docsEnv(srv, "123456")(k)
		}, "authentication failed"},
	} {
		var out bytes.Buffer
		err := DocsPublish(ctx, env, DocsOptions{Dir: guideDir, BrokerURL: "https://tls.example.org", Lookup: tc.lookup}, &out)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		} else if strings.Contains(err.Error()+out.String(), docsToken) {
			t.Errorf("%s: token in error or output", name)
		}
	}
	if srv.Writes() != 0 {
		t.Errorf("%d writes", srv.Writes())
	}
}
