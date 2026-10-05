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

func TestClassify(t *testing.T) {
	for dest, want := range map[string]link{
		"#x":                     {kind: linkAnchor, fragment: "x"},
		"https://example.com/":   {kind: linkExternal},
		"mailto:ops@example.com": {kind: linkExternal},
		"//example.com/a.md":     {kind: linkExternal},
		"acme-proxy.md#certbot":  {kind: linkRepo, repoPath: "docs/acme-proxy.md", fragment: "certbot"},
		"guide.md#x":             {kind: linkRepo, repoPath: "docs/guide.md", fragment: "x"},
		"../architecture.md":     {kind: linkRepo, repoPath: "architecture.md"},
		"../../outside.md":       {kind: linkRepo, repoPath: "../outside.md"},
		"sub/page.md":            {kind: linkRepo, repoPath: "docs/sub/page.md"},
		"image.png":              {kind: linkRepo, repoPath: "docs/image.png"},
	} {
		if got := classify(dest); got != want {
			t.Errorf("classify(%q) = %+v, want %+v", dest, got, want)
		}
	}
}
