package guide

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

var testConfluence = ConfluenceOptions{
	ExternalURL: "https://tls.example.net:8443/",
	IndexTitle:  "TLS Broker",
	TitlePrefix: "TLS Broker: ",
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

func exportPage(t *testing.T, fsys fstest.MapFS, name string) StoragePage {
	t.Helper()
	pages, err := ExportConfluence(fsys, testConfluence)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pages {
		if p.Name == name {
			wellFormed(t, p.File, p.Body)
			return p
		}
	}
	t.Fatalf("no page %q", name)
	return StoragePage{}
}

func TestExportConfluencePages(t *testing.T) {
	pages, err := ExportConfluence(mapFS(), testConfluence)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range pages {
		got = append(got, p.Name+"="+p.Title)
	}
	if strings.Join(got, ",") != "=TLS Broker,first=TLS Broker: First page,second=TLS Broker: Second page" {
		t.Fatalf("pages %v", got)
	}
	if !strings.Contains(pages[0].Body, `<ac:link><ri:page ri:content-title="TLS Broker: First page" /><ac:plain-text-link-body><![CDATA[the first page]]></ac:plain-text-link-body></ac:link>`) {
		t.Errorf("index lacks the page link:\n%s", pages[0].Body)
	}
}

func TestExportConfluenceConversion(t *testing.T) {
	p := exportPage(t, mapFS(), "first")
	for _, want := range []string{
		// Note on top, escaped.
		`<ac:structured-macro ac:name="info"><ac:rich-text-body><p>Generated from the guide (version v1). Edit &lt;the source&gt;.</p></ac:rich-text-body></ac:structured-macro>`,
		// Headings carry their GitHub slug as an anchor macro.
		`<h2><ac:structured-macro ac:name="anchor"><ac:parameter ac:name="">links-here</ac:parameter></ac:structured-macro>Links here</h2>`,
		`<h3><ac:structured-macro ac:name="anchor"><ac:parameter ac:name="">sub</ac:parameter></ac:structured-macro>Sub</h3>`,
		// Links between pages, with and without anchors; the index by its title.
		`<ac:link ac:anchor="part-two"><ri:page ri:content-title="TLS Broker: Second page" /><ac:plain-text-link-body><![CDATA[second]]></ac:plain-text-link-body></ac:link>`,
		`<ac:link><ri:page ri:content-title="TLS Broker" /><ac:plain-text-link-body><![CDATA[index]]></ac:plain-text-link-body></ac:link>`,
		`<ac:link ac:anchor="links-here"><ac:plain-text-link-body><![CDATA[local]]></ac:plain-text-link-body></ac:link>`,
		// Repository files as text, like the reader.
		`reference (in the repository: <code>docs/acme-proxy.md</code>)`,
		`unlisted (in the repository: <code>docs/guide/unlisted.md</code>)`,
		`<a href="https://example.com/a">external</a>`,
		// Broker address substituted in text, links and code.
		`<code>https://tls.example.net:8443/acme/directory</code>`,
		`<a href="https://tls.example.net:8443/cert/x">https://tls.example.net:8443/cert/x</a>`,
		`<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">bash</ac:parameter><ac:plain-text-body><![CDATA[curl https://tls.example.net:8443/cert/www.example.com]]></ac:plain-text-body></ac:structured-macro>`,
		// Plain tables in Confluence's shape.
		"<table><tbody>\n<tr><th>a</th><th>b</th></tr>\n<tr><td>1</td><td>2</td></tr>\n</tbody></table>",
	} {
		if !strings.Contains(p.Body, want) {
			t.Errorf("page lacks %s\n%s", want, p.Body)
		}
	}
	for _, bad := range []string{"broker.example.com", ".md\"", "<img", "pic.png", "<h1", " id=", "<pre", "<thead", "class="} {
		if strings.Contains(p.Body, bad) {
			t.Errorf("page contains %q\n%s", bad, p.Body)
		}
	}
}

func TestExportConfluenceCode(t *testing.T) {
	fsys := mapFS()
	fsys["second.md"].Data = []byte("# Second page\n\n" +
		"```json\n{\"a\": \"]]>\"}\n```\n\n" +
		"```nginx\nlocation / { }\n```\n\n" +
		"    indented & <raw>\n\n" +
		"Text with `inline <code>` and a\nline break.\n")
	p := exportPage(t, fsys, "second")
	for _, want := range []string{
		`<ac:parameter ac:name="language">js</ac:parameter><ac:plain-text-body><![CDATA[{"a": "]]]]><![CDATA[>"}]]></ac:plain-text-body>`,
		`<ac:parameter ac:name="language">text</ac:parameter><ac:plain-text-body><![CDATA[location / { }]]></ac:plain-text-body>`,
		`<ac:parameter ac:name="language">text</ac:parameter><ac:plain-text-body><![CDATA[indented & <raw>]]></ac:plain-text-body>`,
		`<code>inline &lt;code&gt;</code>`,
	} {
		if !strings.Contains(p.Body, want) {
			t.Errorf("page lacks %s\n%s", want, p.Body)
		}
	}
	// The CDATA split must give back the original text.
	d := xml.NewDecoder(strings.NewReader(`<r xmlns:ac="a">` + p.Body + `</r>`))
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
	fsys["second.md"].Data = []byte("# Second page\n\n<script>alert(1)</script>\n\n" +
		"Inline <b onclick=\"x()\">bold</b> and [js](javascript:alert(1)) and <br>.\n\n- [x] done\n- [ ] open\n")
	p := exportPage(t, fsys, "second")
	for _, bad := range []string{"<script", "<b ", "onclick", "javascript:", "<input"} {
		if strings.Contains(p.Body, bad) {
			t.Errorf("raw HTML passed through (%s):\n%s", bad, p.Body)
		}
	}
	if !strings.Contains(p.Body, "[x] done") || !strings.Contains(p.Body, "[ ] open") {
		t.Errorf("task list:\n%s", p.Body)
	}
}

func TestExportConfluenceErrors(t *testing.T) {
	fsys := mapFS()
	fsys["second.md"].Data = []byte("# First page\n")
	if _, err := ExportConfluence(fsys, testConfluence); err == nil || !strings.Contains(err.Error(), "both be titled") {
		t.Errorf("duplicate titles: %v", err)
	}
	fsys = mapFS()
	fsys["second.md"].Data = []byte("No title.\n")
	if _, err := ExportConfluence(fsys, testConfluence); err == nil || !strings.Contains(err.Error(), "no level-1 heading") {
		t.Errorf("no title: %v", err)
	}
	fsys = mapFS()
	delete(fsys, "second.md")
	if _, err := ExportConfluence(fsys, testConfluence); err == nil || !strings.Contains(err.Error(), "second.md") {
		t.Errorf("missing page: %v", err)
	}
	if _, err := ExportConfluence(fstest.MapFS{}, testConfluence); err == nil {
		t.Error("no index: no error")
	}
	// Without an external URL the placeholder stays.
	opts := testConfluence
	opts.ExternalURL = ""
	pages, err := ExportConfluence(mapFS(), opts)
	if err != nil || !strings.Contains(pages[1].Body, Placeholder+"/cert/www.example.com") {
		t.Errorf("placeholder: %v", err)
	}
}

func TestRealGuideExportsToConfluence(t *testing.T) {
	pages, err := ExportConfluence(os.DirFS(filepath.Join(repoRoot, guideDir)), testConfluence)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := New(os.DirFS(filepath.Join(repoRoot, guideDir)), quiet).Index()
	if len(pages) != len(x.Names())+1 {
		t.Fatalf("%d pages for %d index entries", len(pages), len(x.Names()))
	}
	for _, p := range pages {
		wellFormed(t, p.File, p.Body)
		for _, bad := range []string{Placeholder, "raw HTML omitted", "<pre", ".md\"", "<h1"} {
			if strings.Contains(p.Body, bad) {
				t.Errorf("%s contains %q", p.File, bad)
			}
		}
		if !strings.HasPrefix(p.Title, "TLS Broker") {
			t.Errorf("%s: title %q", p.File, p.Title)
		}
	}
}
