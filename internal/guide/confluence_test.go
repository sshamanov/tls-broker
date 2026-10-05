package guide

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

var testConfluence = ConfluenceOptions{
	ExternalURL: "https://tls.example.net:8443/",
	Note:        "Generated from the guide (version v1). Edit <the source>.",
}

// wellFormed parses body as XML inside a wrapper that declares the ac and ri
// namespaces (Confluence's storage format is XHTML with these prefixes).
func wellFormed(t *testing.T, name, body string) {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(`<root xmlns:ac="http://atlassian.com/content" xmlns:ri="http://atlassian.com/resource/identifier">` +
		body + `</root>`))
	d.Strict = true
	for {
		_, err := d.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("%s: not well-formed XML: %v\n%s", name, err, body)
		}
	}
}

func export(t *testing.T, fsys fstest.MapFS) string {
	t.Helper()
	body, err := ExportConfluence(fsys, testConfluence)
	if err != nil {
		t.Fatal(err)
	}
	wellFormed(t, File, body)
	return body
}

func TestExportConfluenceConversion(t *testing.T) {
	body := export(t, mapFS())
	for _, want := range []string{
		// Note on top, escaped.
		`<ac:structured-macro ac:name="info"><ac:rich-text-body><p>Generated from the guide (version v1). Edit &lt;the source&gt;.</p></ac:rich-text-body></ac:structured-macro>`,
		// Headings carry their GitHub slug as an anchor macro.
		`<h2><ac:structured-macro ac:name="anchor"><ac:parameter ac:name="">links-here</ac:parameter></ac:structured-macro>Links here</h2>`,
		`<h3><ac:structured-macro ac:name="anchor"><ac:parameter ac:name="">sub</ac:parameter></ac:structured-macro>Sub</h3>`,
		// The contents list stays, as links to the heading anchors.
		`<h2><ac:structured-macro ac:name="anchor"><ac:parameter ac:name="">contents</ac:parameter></ac:structured-macro>Contents</h2>`,
		`<li><ac:link ac:anchor="links-here"><ac:plain-text-link-body><![CDATA[Links here]]></ac:plain-text-link-body></ac:link>` +
			"\n<ul>\n" + `<li><ac:link ac:anchor="sub"><ac:plain-text-link-body><![CDATA[Sub]]></ac:plain-text-link-body></ac:link></li>`,
		// Other #anchor links too.
		`<ac:link ac:anchor="part-two"><ac:plain-text-link-body><![CDATA[two]]></ac:plain-text-link-body></ac:link>`,
		`<ac:link ac:anchor="links-here"><ac:plain-text-link-body><![CDATA[local]]></ac:plain-text-link-body></ac:link>`,
		// Repository files as text, like the reader.
		`reference (in the repository: <code>docs/acme-proxy.md</code>)`,
		`design (in the repository: <code>architecture.md</code>)`,
		`<a href="https://example.com/a">external</a>`,
		// Broker address substituted in text, links and code.
		`<code>https://tls.example.net:8443/acme/directory</code>`,
		`<a href="https://tls.example.net:8443/cert/x">https://tls.example.net:8443/cert/x</a>`,
		`<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">bash</ac:parameter><ac:plain-text-body><![CDATA[curl https://tls.example.net:8443/cert/www.example.com]]></ac:plain-text-body></ac:structured-macro>`,
		// Plain tables in Confluence's shape.
		"<table><tbody>\n<tr><th>a</th><th>b</th></tr>\n<tr><td>1</td><td>2</td></tr>\n</tbody></table>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s\n%s", want, body)
		}
	}
	for _, bad := range []string{"broker.example.com", ".md\"", "<img", "pic.png", "<h1", "User guide", " id=", "<pre", "<thead", "class=", "ri:page"} {
		if strings.Contains(body, bad) {
			t.Errorf("body contains %q\n%s", bad, body)
		}
	}
}

func TestExportConfluenceCode(t *testing.T) {
	fsys := mapFS()
	fsys[File].Data = []byte("# Guide\n\n" +
		"```json\n{\"a\": \"]]>\"}\n```\n\n" +
		"```nginx\nlocation / { }\n```\n\n" +
		"    indented & <raw>\n\n" +
		"Text with `inline <code>` and a\nline break.\n")
	body := export(t, fsys)
	for _, want := range []string{
		`<ac:parameter ac:name="language">js</ac:parameter><ac:plain-text-body><![CDATA[{"a": "]]]]><![CDATA[>"}]]></ac:plain-text-body>`,
		`<ac:parameter ac:name="language">text</ac:parameter><ac:plain-text-body><![CDATA[location / { }]]></ac:plain-text-body>`,
		`<ac:parameter ac:name="language">text</ac:parameter><ac:plain-text-body><![CDATA[indented & <raw>]]></ac:plain-text-body>`,
		`<code>inline &lt;code&gt;</code>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s\n%s", want, body)
		}
	}
	// The CDATA split must give back the original text.
	d := xml.NewDecoder(strings.NewReader(`<r xmlns:ac="a">` + body + `</r>`))
	var text strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		if cd, ok := tok.(xml.CharData); ok {
			text.Write(cd)
		}
	}
	if !strings.Contains(text.String(), `{"a": "]]>"}`) {
		t.Errorf("CDATA escaping lost text: %q", text.String())
	}
}

func TestExportConfluenceNeverPassesHTML(t *testing.T) {
	fsys := mapFS()
	fsys[File].Data = []byte("# Guide\n\n<script>alert(1)</script>\n\n" +
		"Inline <b onclick=\"x()\">bold</b> and [js](javascript:alert(1)) and <br>.\n\n- [x] done\n- [ ] open\n")
	body := export(t, fsys)
	for _, bad := range []string{"<script", "<b ", "onclick", "javascript:", "<input"} {
		if strings.Contains(body, bad) {
			t.Errorf("raw HTML passed through (%s):\n%s", bad, body)
		}
	}
	if !strings.Contains(body, "[x] done") || !strings.Contains(body, "[ ] open") {
		t.Errorf("task list:\n%s", body)
	}
}

func TestExportConfluenceErrors(t *testing.T) {
	if _, err := ExportConfluence(fstest.MapFS{File: {Data: []byte("No title.\n")}}, testConfluence); err == nil || !strings.Contains(err.Error(), "no level-1 heading") {
		t.Errorf("no title: %v", err)
	}
	if _, err := ExportConfluence(fstest.MapFS{}, testConfluence); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no guide: %v", err)
	}
	if _, err := ExportConfluence(nil, testConfluence); !errors.Is(err, ErrUnavailable) {
		t.Errorf("nil: %v", err)
	}
	// Without an external URL the placeholder stays.
	opts := testConfluence
	opts.ExternalURL = ""
	body, err := ExportConfluence(mapFS(), opts)
	if err != nil || !strings.Contains(body, Placeholder+"/cert/www.example.com") {
		t.Errorf("placeholder: %v", err)
	}
}

func TestRealGuideExportsToConfluence(t *testing.T) {
	fsys := os.DirFS(filepath.Join(repoRoot, guideDir))
	body, err := ExportConfluence(fsys, testConfluence)
	if err != nil {
		t.Fatal(err)
	}
	wellFormed(t, File, body)
	for _, bad := range []string{Placeholder, "raw HTML omitted", "<pre", ".md\"", "<h1", "ri:page"} {
		if strings.Contains(body, bad) {
			t.Errorf("the export contains %q", bad)
		}
	}
	// Every heading of the reader's navigation is an anchor, and the
	// contents list links to each.
	p, err := New(fsys, quiet).Document("")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range p.TOC {
		if !strings.Contains(body, `<ac:parameter ac:name="">`+h.ID+`</ac:parameter>`) ||
			!strings.Contains(body, `<ac:link ac:anchor="`+h.ID+`">`) {
			t.Errorf("heading %s: no anchor or no link to it", h.ID)
		}
	}
}
