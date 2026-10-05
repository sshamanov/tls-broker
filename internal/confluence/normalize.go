package confluence

import (
	"encoding/xml"
	"html"
	"io"
	"slices"
	"strings"
)

// Normalize returns a canonical form of a storage-format body, so a body as
// sent and the same body as Confluence stores it compare equal: entities
// decoded, attributes sorted, the attributes Confluence adds on its own
// (ac:macro-id, ac:schema-version, local-id) dropped, whitespace-only text
// between elements dropped and other whitespace runs collapsed (except
// inside ac:plain-text-body, the code macro's text, which is kept exactly),
// comments dropped, and self-closing tags expanded. ok is false when the
// body is not well-formed; then it is only trimmed.
func Normalize(body string) (canon string, ok bool) {
	d := xml.NewDecoder(strings.NewReader("<root>" + body + "</root>"))
	d.Strict = true
	d.Entity = xml.HTMLEntity
	var b strings.Builder
	raw := 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return b.String(), true
		}
		if err != nil {
			return strings.TrimSpace(body), false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := qname(t.Name)
			if n == "ac:plain-text-body" {
				raw++
			}
			attrs := slices.DeleteFunc(slices.Clone(t.Attr), func(a xml.Attr) bool {
				switch qname(a.Name) {
				case "ac:macro-id", "ac:schema-version", "local-id", "ac:local-id":
					return true
				}
				return false
			})
			slices.SortFunc(attrs, func(a, b xml.Attr) int { return strings.Compare(qname(a.Name), qname(b.Name)) })
			b.WriteString("<" + n)
			for _, a := range attrs {
				b.WriteString(" " + qname(a.Name) + `="` + html.EscapeString(a.Value) + `"`)
			}
			b.WriteString(">")
		case xml.EndElement:
			n := qname(t.Name)
			if n == "ac:plain-text-body" && raw > 0 {
				raw--
			}
			b.WriteString("</" + n + ">")
		case xml.CharData:
			s := string(t)
			if raw == 0 {
				if strings.TrimSpace(s) == "" {
					continue
				}
				s = collapse(s)
			}
			b.WriteString(html.EscapeString(s))
		}
	}
}

func qname(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}

// collapse turns every run of white space into one space.
func collapse(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			space = true
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	if space {
		b.WriteByte(' ')
	}
	return b.String()
}
