package confluence_test

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"tls-broker/internal/confluence"
	"tls-broker/internal/confluence/confluencetest"
)

const (
	token  = "secret-token-value"
	rootID = "123456"
)

func doc(version string) confluence.Doc {
	note := `<ac:structured-macro ac:name="info"><ac:rich-text-body><p>Generated (version ` + version + `).</p></ac:rich-text-body></ac:structured-macro>`
	return confluence.Doc{Source: "guide.md", Body: note +
		`<ul><li><ac:link ac:anchor="one"><ac:plain-text-link-body><![CDATA[One]]></ac:plain-text-link-body></ac:link></li></ul>` +
		`<h2><ac:structured-macro ac:name="anchor"><ac:parameter ac:name="">one</ac:parameter></ac:structured-macro>One</h2>` + "\n" +
		`<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">bash</ac:parameter><ac:plain-text-body><![CDATA[  echo two]]></ac:plain-text-body></ac:structured-macro>` +
		"<table><tbody><tr><th>a</th></tr><tr><td>1</td></tr></tbody></table>"}
}

const prefix = "TLS Broker: "

func setup(t *testing.T, tok string) (*confluencetest.Server, *confluence.Publisher) {
	t.Helper()
	srv := confluencetest.New(token, rootID, "admin", "TLS Broker")
	t.Cleanup(srv.Close)
	c, err := confluence.NewClient(srv.URL+"/", tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv, &confluence.Publisher{API: c, RootID: rootID, Message: "tls-broker v1",
		Volatile: regexp.MustCompile(`\(version [^)]*\)`), ObsoletePrefix: prefix}
}

// publish plans and (unless dry) applies; it returns everything printed.
func publish(t *testing.T, p *confluence.Publisher, d confluence.Doc, prune, dry bool) (*confluence.Plan, string) {
	t.Helper()
	ctx := context.Background()
	var out bytes.Buffer
	root, err := p.Root(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.Plan(ctx, root, d, prune)
	if err != nil {
		t.Fatal(err)
	}
	plan.Print(&out)
	if !dry {
		if err := p.Apply(ctx, plan, &out); err != nil {
			t.Fatalf("apply: %v\n%s", err, out.String())
		}
	}
	return plan, out.String()
}

func titles(ps []confluencetest.Page) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.Title)
	}
	return strings.Join(s, ",")
}

// confluenceSave imitates what Confluence does to a body it stores.
func confluenceSave(b string) string {
	b = strings.ReplaceAll(b, `ac:name="code">`, `ac:name="code" ac:schema-version="1" ac:macro-id="0b5c1c4e-1">`)
	b = strings.ReplaceAll(b, " />", "/>")
	b = strings.ReplaceAll(b, "\n", "")
	return b
}

func onlyReads(t *testing.T, srv *confluencetest.Server) {
	t.Helper()
	for _, r := range srv.Requests() {
		if !strings.HasPrefix(r, "GET ") {
			t.Errorf("sent %s", r)
		}
	}
}

func TestPublishUpdatesTheRootOnlyThenNoOps(t *testing.T) {
	srv, p := setup(t, token)
	srv.Store = confluenceSave

	plan, out := publish(t, p, doc("v1"), false, true)
	if plan.Action != confluence.Update || srv.Writes() != 0 {
		t.Fatalf("dry run: %s, %d writes\n%s", plan.Action, srv.Writes(), out)
	}
	onlyReads(t, srv)
	if !strings.Contains(out, `update     "TLS Broker"  id `+rootID+`, version 1 -> 2  (guide.md, root page)`) {
		t.Errorf("output:\n%s", out)
	}

	plan, out = publish(t, p, doc("v1"), false, false)
	if plan.Action != confluence.Update || !strings.Contains(out, `updated    "TLS Broker"  id `+rootID+`, version 2`) {
		t.Fatalf("first publish: %s\n%s", plan.Action, out)
	}
	root, _ := srv.Get(rootID)
	if root.Version != 2 || root.Title != "TLS Broker" || !strings.Contains(root.Body, `ac:anchor="one"`) || root.Messages[0] != "tls-broker v1" {
		t.Errorf("root %+v", root)
	}
	if kids := srv.Children(rootID); len(kids) != 0 {
		t.Errorf("child pages created: %s", titles(kids))
	}

	// Second run: nothing to do, although Confluence rewrote the body.
	w := srv.Writes()
	plan, out = publish(t, p, doc("v1"), false, false)
	if plan.Action != confluence.Unchanged || srv.Writes() != w {
		t.Fatalf("second publish: %s writes %d->%d\n%s", plan.Action, w, srv.Writes(), out)
	}
	if !strings.Contains(out, `unchanged  "TLS Broker"  id `+rootID+`, version 2  (guide.md, root page)`) {
		t.Errorf("output:\n%s", out)
	}
	// A new version alone is no change either; whitespace inside code is.
	if plan, _ = publish(t, p, doc("v2"), false, true); plan.Action != confluence.Unchanged {
		t.Errorf("version-only change: %s", plan.Action)
	}
	d := doc("v1")
	d.Body = strings.Replace(d.Body, "  echo two", "  echo  two", 1)
	if plan, _ = publish(t, p, d, false, true); plan.Action != confluence.Update {
		t.Errorf("code change: %s", plan.Action)
	}
}

// oldLayout adds what the multi-page publisher left behind, and pages
// others made.
func oldLayout(srv *confluencetest.Server) {
	srv.Add(confluencetest.Page{ID: "7", Space: "admin", ParentID: rootID, Title: "Notes by hand", Body: "<p>mine</p>"})
	srv.Add(confluencetest.Page{ID: "8", Space: "admin", ParentID: rootID, Title: "TLS Broker: Getting started", Body: "<p>old</p>"})
	srv.Add(confluencetest.Page{ID: "9", Space: "admin", ParentID: rootID, Title: "TLS Broker: API reference", Body: "<p>old</p>"})
	srv.Add(confluencetest.Page{ID: "10", Space: "admin", ParentID: rootID, Title: "TLS Broker: Kept", Body: "<p>has a child</p>"})
	srv.Add(confluencetest.Page{ID: "11", Space: "admin", ParentID: "10", Title: "TLS Broker: Grandchild"})
	srv.Add(confluencetest.Page{ID: "12", Space: "admin", ParentID: rootID, Title: "TLS Broker review notes"})
	srv.Add(confluencetest.Page{ID: "13", Space: "admin", ParentID: "", Title: "TLS Broker: Elsewhere"})
}

func TestPublishReportsObsoletePagesWithoutPrune(t *testing.T) {
	srv, p := setup(t, token)
	oldLayout(srv)
	plan, out := publish(t, p, doc("v1"), false, false)
	if len(plan.Obsolete) != 3 || len(plan.Extra) != 2 {
		t.Fatalf("obsolete %v extra %v\n%s", plan.Obsolete, plan.Extra, out)
	}
	for _, want := range []string{
		`obsolete   "TLS Broker: Getting started"  id 8  (kept; pruning deletes it)`,
		`obsolete   "TLS Broker: API reference"  id 9  (kept; pruning deletes it)`,
		`obsolete   "TLS Broker: Kept"  id 10: has 1 child pages, so it is kept; move them first`,
		`not from the guide, left alone: "Notes by hand"  id 7`,
		`not from the guide, left alone: "TLS Broker review notes"  id 12`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %s\n%s", want, out)
		}
	}
	if srv.Writes() != 1 || titles(srv.Children(rootID)) != "Notes by hand,TLS Broker: Getting started,TLS Broker: API reference,TLS Broker: Kept,TLS Broker review notes" {
		t.Errorf("%d writes, children %s", srv.Writes(), titles(srv.Children(rootID)))
	}
}

func TestPublishPruneDeletesOnlyPrefixedChildren(t *testing.T) {
	srv, p := setup(t, token)
	oldLayout(srv)

	// Dry run: says what it would delete, sends no write.
	plan, out := publish(t, p, doc("v1"), true, true)
	if !strings.Contains(out, `delete     "TLS Broker: Getting started"  id 8`) || !strings.Contains(out, `delete     "TLS Broker: API reference"  id 9`) ||
		strings.Contains(out, `delete     "TLS Broker: Kept"`) || !plan.Prune || srv.Writes() != 0 {
		t.Fatalf("dry run (%d writes):\n%s", srv.Writes(), out)
	}
	onlyReads(t, srv)

	_, out = publish(t, p, doc("v1"), true, false)
	if !strings.Contains(out, `deleted    "TLS Broker: Getting started"  id 8`) || !strings.Contains(out, `deleted    "TLS Broker: API reference"  id 9`) {
		t.Errorf("output:\n%s", out)
	}
	if got := titles(srv.Children(rootID)); got != "Notes by hand,TLS Broker: Kept,TLS Broker review notes" {
		t.Errorf("children left %s", got)
	}
	for _, id := range []string{"7", "10", "11", "12", "13"} {
		if pg, ok := srv.Get(id); !ok || pg.Version != 1 {
			t.Errorf("page %s touched: %+v", id, pg)
		}
	}
	// Again: nothing left to delete, nothing to update.
	w := srv.Writes()
	plan, out = publish(t, p, doc("v1"), true, false)
	if plan.Action != confluence.Unchanged || srv.Writes() != w || strings.Contains(out, "delete     ") || strings.Contains(out, "deleted") {
		t.Errorf("second run: %s, writes %d->%d\n%s", plan.Action, w, srv.Writes(), out)
	}
}

func TestPublishPruneToleratesDeletedMeanwhile(t *testing.T) {
	srv, p := setup(t, token)
	oldLayout(srv)
	ctx := context.Background()
	root, _ := p.Root(ctx)
	plan, err := p.Plan(ctx, root, doc("v1"), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.API.Delete(ctx, "8"); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := p.Apply(ctx, plan, &out); err != nil || !strings.Contains(out.String(), `gone       "TLS Broker: Getting started"  id 8`) {
		t.Errorf("apply: %v\n%s", err, out.String())
	}
}

func TestPublishRetriesOnceOnConflict(t *testing.T) {
	srv, p := setup(t, token)
	publish(t, p, doc("v1"), false, false)
	d := doc("v1")
	d.Body += "<p>more</p>"

	srv.Conflicts(1)
	if _, out := publish(t, p, d, false, false); !strings.Contains(out, "updated") {
		t.Fatalf("no update after a conflict:\n%s", out)
	}
	root, _ := srv.Get(rootID)
	if root.Version != 4 || !strings.HasSuffix(root.Body, "<p>more</p>") {
		t.Errorf("root %+v", root)
	}

	d.Body += "<p>again</p>"
	srv.Conflicts(2)
	ctx := context.Background()
	r, _ := p.Root(ctx)
	plan, _ := p.Plan(ctx, r, d, false)
	err := p.Apply(ctx, plan, &bytes.Buffer{})
	if confluence.StatusOf(err) != http.StatusConflict || !strings.Contains(err.Error(), "after one retry") {
		t.Errorf("second conflict: %v", err)
	}
}

func TestPublishErrors(t *testing.T) {
	ctx := context.Background()

	// Wrong token: 401, and the token is never part of the message.
	_, p := setup(t, "wrong-"+token)
	_, err := p.Root(ctx)
	if confluence.StatusOf(err) != http.StatusUnauthorized || !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("401: %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("token in error: %v", err)
	}

	// Missing root page.
	_, p = setup(t, token)
	p.RootID = "42"
	if _, err := p.Root(ctx); confluence.StatusOf(err) != http.StatusNotFound || !strings.Contains(err.Error(), "root page 42 does not exist") {
		t.Errorf("404: %v", err)
	}

	// Read-only token.
	srv, p := setup(t, token)
	srv.SetReadOnly(true)
	root, _ := p.Root(ctx)
	plan, _ := p.Plan(ctx, root, doc("v1"), false)
	err = p.Apply(ctx, plan, &bytes.Buffer{})
	if confluence.StatusOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "may read but not change") || strings.Contains(err.Error(), token) {
		t.Errorf("403: %v", err)
	}

	if _, err := confluence.NewClient("ftp://x", token, nil); err == nil {
		t.Error("ftp URL accepted")
	}
	if _, err := confluence.NewClient("https://x", "", nil); err == nil {
		t.Error("empty token accepted")
	}
	c, _ := confluence.NewClient("https://x", token, nil)
	if _, err := c.Page(ctx, "../admin"); err == nil {
		t.Error("non-numeric ID accepted")
	}
	if err := c.Delete(ctx, "1/../2"); err == nil {
		t.Error("non-numeric ID accepted for delete")
	}

	// A read-only token cannot prune either.
	srv, p = setup(t, token)
	oldLayout(srv)
	srv.SetReadOnly(true)
	root, _ = p.Root(ctx)
	plan, _ = p.Plan(ctx, root, doc("v1"), true)
	plan.Action = confluence.Unchanged
	err = p.Apply(ctx, plan, &bytes.Buffer{})
	if confluence.StatusOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "deleting") {
		t.Errorf("403 on delete: %v", err)
	}
}

func TestChildrenPaginates(t *testing.T) {
	srv, p := setup(t, token)
	for i := range 60 {
		srv.Add(confluencetest.Page{ID: string(rune('a'+i/26)) + string(rune('a'+i%26)), Space: "admin", ParentID: rootID, Title: "p" + string(rune(i))})
	}
	kids, err := p.API.Children(context.Background(), rootID)
	if err != nil || len(kids) != 60 {
		t.Fatalf("%d children, %v", len(kids), err)
	}
}

func TestNormalize(t *testing.T) {
	a := "<p>a  b\n c</p>\n<table><tbody><tr><td>x</td></tr></tbody></table>" +
		`<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[ x  y ]]></ac:plain-text-body></ac:structured-macro><ri:page ri:content-title="T" />`
	b := "<p>a b c</p><table><tbody><tr><td>x</td></tr></tbody></table>" +
		`<ac:structured-macro ac:macro-id="1" ac:name="code" ac:schema-version="1"><ac:plain-text-body><![CDATA[ x  y ]]></ac:plain-text-body></ac:structured-macro><ri:page ri:content-title="T"></ri:page>`
	na, ok1 := confluence.Normalize(a)
	nb, ok2 := confluence.Normalize(b)
	if !ok1 || !ok2 || na != nb {
		t.Errorf("not equal:\n%s\n%s", na, nb)
	}
	if nc, _ := confluence.Normalize(strings.Replace(b, " x  y ", " x y ", 1)); nc == na {
		t.Error("code whitespace ignored")
	}
	if n, _ := confluence.Normalize("<p>&nbsp;&amp;</p>"); n != "<root><p> &amp;</p></root>" {
		t.Errorf("entities: %q", n)
	}
	if _, ok := confluence.Normalize("<p>unclosed"); ok {
		t.Error("malformed body reported ok")
	}
}
