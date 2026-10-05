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

func docs(version string) []confluence.Doc {
	note := `<ac:structured-macro ac:name="info"><ac:rich-text-body><p>Generated (version ` + version + `).</p></ac:rich-text-body></ac:structured-macro>`
	return []confluence.Doc{
		{Source: "README.md", Title: "ignored", Body: note + `<p>Index <ac:link><ri:page ri:content-title="TLS Broker: One" /><ac:plain-text-link-body><![CDATA[one]]></ac:plain-text-link-body></ac:link></p>`},
		{Source: "one.md", Title: "TLS Broker: One", Body: note + "<h2>A</h2>\n<p>One.</p>"},
		{Source: "two.md", Title: "TLS Broker: Two", Body: note + `<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">bash</ac:parameter><ac:plain-text-body><![CDATA[  echo two]]></ac:plain-text-body></ac:structured-macro>`},
		{Source: "three.md", Title: "TLS Broker: Three", Body: note + "<table><tbody><tr><th>a</th></tr><tr><td>1</td></tr></tbody></table>"},
	}
}

func setup(t *testing.T, tok string) (*confluencetest.Server, *confluence.Publisher) {
	t.Helper()
	srv := confluencetest.New(token, rootID, "admin", "TLS Broker")
	t.Cleanup(srv.Close)
	c, err := confluence.NewClient(srv.URL+"/", tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv, &confluence.Publisher{API: c, RootID: rootID, Message: "tls-broker v1",
		Volatile: regexp.MustCompile(`\(version [^)]*\)`)}
}

// publish plans and (unless dry) applies; it returns everything printed.
func publish(t *testing.T, p *confluence.Publisher, d []confluence.Doc, dry bool) (*confluence.Plan, string) {
	t.Helper()
	ctx := context.Background()
	var out bytes.Buffer
	root, err := p.Root(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.Plan(ctx, root, d)
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

func actions(plan *confluence.Plan) string {
	var s []string
	for _, st := range plan.Steps {
		s = append(s, string(st.Action))
	}
	return strings.Join(s, ",")
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

func TestPublishCreatesThenNoOps(t *testing.T) {
	srv, p := setup(t, token)
	srv.Store = confluenceSave

	plan, out := publish(t, p, docs("v1"), true)
	if actions(plan) != "update,create,create,create" || srv.Writes() != 0 {
		t.Fatalf("dry run: %s, %d writes\n%s", actions(plan), srv.Writes(), out)
	}
	for _, r := range srv.Requests() {
		if !strings.HasPrefix(r, "GET ") {
			t.Errorf("dry run sent %s", r)
		}
	}

	plan, out = publish(t, p, docs("v1"), false)
	if actions(plan) != "update,create,create,create" {
		t.Fatalf("first publish: %s\n%s", actions(plan), out)
	}
	root, _ := srv.Get(rootID)
	if root.Version != 2 || root.Title != "TLS Broker" || !strings.Contains(root.Body, "Index") || root.Messages[0] != "tls-broker v1" {
		t.Errorf("root %+v", root)
	}
	if got := titles(srv.Children(rootID)); got != "TLS Broker: One,TLS Broker: Two,TLS Broker: Three" {
		t.Errorf("children %s", got)
	}

	// Second run: nothing to do, although Confluence rewrote the bodies.
	w := srv.Writes()
	plan, out = publish(t, p, docs("v1"), false)
	if actions(plan) != "unchanged,unchanged,unchanged,unchanged" || plan.Reorder || srv.Writes() != w {
		t.Fatalf("second publish: %s reorder=%v writes %d->%d\n%s", actions(plan), plan.Reorder, w, srv.Writes(), out)
	}
	// A new version alone is no change either.
	if plan, _ = publish(t, p, docs("v2"), true); actions(plan) != "unchanged,unchanged,unchanged,unchanged" {
		t.Errorf("version-only change: %s", actions(plan))
	}
}

func TestPublishUpdatesChangedPage(t *testing.T) {
	srv, p := setup(t, token)
	publish(t, p, docs("v1"), false)
	d := docs("v1")
	d[2].Body = strings.Replace(d[2].Body, "  echo two", "  echo  two", 1) // whitespace inside code counts
	plan, out := publish(t, p, d, false)
	if actions(plan) != "unchanged,unchanged,update,unchanged" {
		t.Fatalf("%s\n%s", actions(plan), out)
	}
	two := srv.Children(rootID)[1]
	if two.Version != 2 || len(two.Messages) != 1 || two.Messages[0] != "tls-broker v1" || !strings.Contains(two.Body, "echo  two") {
		t.Errorf("updated page %+v", two)
	}
	if !strings.Contains(out, `update     "TLS Broker: Two"  id `+two.ID+`, version 1 -> 2`) {
		t.Errorf("output:\n%s", out)
	}
}

func TestPublishRetriesOnceOnConflict(t *testing.T) {
	srv, p := setup(t, token)
	publish(t, p, docs("v1"), false)
	d := docs("v1")
	d[1].Body += "<p>more</p>"

	srv.Conflicts(1)
	if _, out := publish(t, p, d, false); !strings.Contains(out, "updated") {
		t.Fatalf("no update after a conflict:\n%s", out)
	}
	one := srv.Children(rootID)[0]
	if one.Version != 3 || !strings.HasSuffix(one.Body, "<p>more</p>") {
		t.Errorf("page %+v", one)
	}

	d[1].Body += "<p>again</p>"
	srv.Conflicts(2)
	ctx := context.Background()
	root, _ := p.Root(ctx)
	plan, _ := p.Plan(ctx, root, d)
	err := p.Apply(ctx, plan, &bytes.Buffer{})
	if confluence.StatusOf(err) != http.StatusConflict || !strings.Contains(err.Error(), "after one retry") {
		t.Errorf("second conflict: %v", err)
	}
}

func TestPublishReportsExtraPagesAndOrders(t *testing.T) {
	srv, p := setup(t, token)
	srv.Add(confluencetest.Page{ID: "7", Space: "admin", ParentID: rootID, Title: "Notes by hand", Body: "<p>mine</p>"})
	srv.Add(confluencetest.Page{ID: "8", Space: "admin", ParentID: rootID, Title: "TLS Broker: Three", Body: "<p>old</p>"})
	plan, out := publish(t, p, docs("v1"), false)
	if actions(plan) != "update,create,create,update" || !plan.Reorder {
		t.Fatalf("%s reorder=%v\n%s", actions(plan), plan.Reorder, out)
	}
	if !strings.Contains(out, `not in the guide, left alone: "Notes by hand"  id 7`) || !strings.Contains(out, "ordered") {
		t.Errorf("output:\n%s", out)
	}
	if n, ok := srv.Get("7"); !ok || n.Version != 1 || n.Body != "<p>mine</p>" {
		t.Errorf("extra page touched: %+v", n)
	}
	if got := titles(srv.Children(rootID)); got != "Notes by hand,TLS Broker: One,TLS Broker: Two,TLS Broker: Three" {
		t.Errorf("order %s", got)
	}
	if plan, _ := publish(t, p, docs("v1"), true); plan.Reorder || len(plan.Extra) != 1 {
		t.Errorf("second plan: reorder=%v extra=%v", plan.Reorder, plan.Extra)
	}
}

func TestPublishWithoutMoveAPIWarns(t *testing.T) {
	srv, p := setup(t, token)
	srv.NoMove()
	srv.Add(confluencetest.Page{ID: "8", Space: "admin", ParentID: rootID, Title: "TLS Broker: Three"})
	if _, out := publish(t, p, docs("v1"), false); !strings.Contains(out, "order the child pages by hand") {
		t.Errorf("output:\n%s", out)
	}
}

func TestPublishRefusesTakenTitle(t *testing.T) {
	srv, p := setup(t, token)
	srv.Add(confluencetest.Page{ID: "9", Space: "admin", ParentID: "", Title: "TLS Broker: Two"})
	ctx := context.Background()
	root, _ := p.Root(ctx)
	plan, err := p.Plan(ctx, root, docs("v1"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	plan.Print(&out)
	if !strings.Contains(out.String(), "BLOCKED: page 9") {
		t.Errorf("plan:\n%s", out.String())
	}
	if err := p.Apply(ctx, plan, &out); err == nil || !strings.Contains(err.Error(), "already has this title") || srv.Writes() != 0 {
		t.Errorf("apply: %v, %d writes", err, srv.Writes())
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
	plan, _ := p.Plan(ctx, root, docs("v1"))
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
