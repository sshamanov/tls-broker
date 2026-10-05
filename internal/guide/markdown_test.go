package guide

import (
	"reflect"
	"testing"
)

func TestHeadingIDsMatchGitHub(t *testing.T) {
	src := []byte("# Title\n\n## Install the certificate and reload the service\n\n## What's new?\n\n" +
		"## The `--server` option\n\n## snake_case and CAPS\n\n## Über größe\n\n## 1. Step\n\n" +
		"## See [the API](api.md)\n\n## Repeat\n\n## Repeat\n\n## Repeat-1\n\n## Repeat\n")
	_, hs := parse(newMarkdown(), src)
	var got []string
	for _, h := range hs {
		got = append(got, h.ID)
	}
	want := []string{"title", "install-the-certificate-and-reload-the-service", "whats-new",
		"the---server-option", "snake_case-and-caps", "über-größe", "1-step", "see-the-api",
		"repeat", "repeat-1", "repeat-1-1", "repeat-2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ids\n got %q\nwant %q", got, want)
	}
	if hs[3].Text != "The --server option" {
		t.Errorf("heading text %q", hs[3].Text)
	}
}

func TestParseIndex(t *testing.T) {
	src := []byte(`# User guide

Intro with a [link](getting-started.md) outside a list, which is not an entry.

- [Getting started](getting-started.md)
- [External](https://example.com/x.md)

## Modes

Text.

- [ACME proxy](acme-proxy.md#certbot)
- [Again](getting-started.md)
- [Reference](../acme-proxy.md)
- [Index](README.md)

## Empty

## More

1. [API reference](api.md)
`)
	x, err := ParseIndex(src)
	if err != nil {
		t.Fatal(err)
	}
	want := Index{Title: "User guide", Groups: []Group{
		{Entries: []Entry{{"getting-started", "Getting started"}}},
		{Title: "Modes", Entries: []Entry{{"acme-proxy", "ACME proxy"}}},
		{Title: "More", Entries: []Entry{{"api", "API reference"}}},
	}}
	if !reflect.DeepEqual(x, want) {
		t.Errorf("index\n got %+v\nwant %+v", x, want)
	}
	if !x.Has("api") || x.Has("README") || x.Has("dns-proxy") {
		t.Error("Has")
	}
	if _, err := ParseIndex([]byte("- [a](a.md)\n")); err == nil {
		t.Error("index without title accepted")
	}
}

func TestClassify(t *testing.T) {
	for dest, want := range map[string]link{
		"#x":                     {kind: linkAnchor, fragment: "x"},
		"https://example.com/":   {kind: linkExternal},
		"mailto:ops@example.com": {kind: linkExternal},
		"//example.com/a.md":     {kind: linkExternal},
		"acme-proxy.md":          {kind: linkGuide, name: "acme-proxy", repoPath: "docs/guide/acme-proxy.md"},
		"acme-proxy.md#certbot":  {kind: linkGuide, name: "acme-proxy", repoPath: "docs/guide/acme-proxy.md", fragment: "certbot"},
		"README.md":              {kind: linkGuide, repoPath: "docs/guide/README.md"},
		"../acme-proxy.md#x":     {kind: linkRepo, repoPath: "docs/acme-proxy.md", fragment: "x"},
		"../../architecture.md":  {kind: linkRepo, repoPath: "architecture.md"},
		"Upper.md":               {kind: linkRepo, repoPath: "docs/guide/Upper.md"},
		"sub/page.md":            {kind: linkRepo, repoPath: "docs/guide/sub/page.md"},
		"image.png":              {kind: linkRepo, repoPath: "docs/guide/image.png"},
	} {
		if got := classify(dest); got != want {
			t.Errorf("classify(%q) = %+v, want %+v", dest, got, want)
		}
	}
}
