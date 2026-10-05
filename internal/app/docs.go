package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"tls-broker/internal/config"
	"tls-broker/internal/confluence"
	"tls-broker/internal/guide"
	"tls-broker/internal/version"
)

// Environment of "tls-broker docs publish". Only that command reads them;
// the broker itself (serve) never does.
const (
	EnvConfluenceURL    = "TLS_BROKER_CONFLUENCE_URL"
	EnvConfluenceToken  = "TLS_BROKER_CONFLUENCE_TOKEN"
	EnvConfluencePageID = "TLS_BROKER_CONFLUENCE_PAGE_ID"
)

// ObsoleteTitlePrefix started the titles of the child pages the guide was
// published to while it was split into several pages. The guide is one
// root page now; --prune deletes child pages with this prefix.
const ObsoleteTitlePrefix = "TLS Broker: "

// notePrefix starts the note at the top of the published page; the
// version after it is ignored when deciding whether a page changed.
const notePrefix = "Generated from the TLS broker user guide"

var noteVersion = regexp.MustCompile(regexp.QuoteMeta(notePrefix) + ` \(version [^)]*\)`)

// DocsOptions are the flags of "tls-broker docs publish".
type DocsOptions struct {
	DryRun bool
	// Prune deletes the obsolete child pages (ObsoleteTitlePrefix) of the
	// root; without it they are only reported.
	Prune bool
	// OutDir, when set, receives the storage-format XHTML as guide.xhtml.
	OutDir string
	// Dir is the directory holding guide.File; "" is guide.DefaultDir (the
	// image's copy).
	Dir string
	// BrokerURL replaces https://broker.example.com; "" takes
	// server.external_url from the active configuration generation.
	BrokerURL string
	// Lookup reads the TLS_BROKER_CONFLUENCE_* variables (os.LookupEnv).
	Lookup func(string) (string, bool)
	// HTTPClient talks to Confluence; nil is a default client.
	HTTPClient *http.Client
}

// DocsPublish copies the user guide to Confluence: the whole document to
// the root page (updated when its content changed, otherwise left alone). It
// creates no pages. Child pages of the root titled ObsoleteTitlePrefix + ...
// are left over from the multi-page guide: Prune deletes them (unless they
// have children of their own), otherwise they are reported; other child
// pages are reported and left alone. With DryRun it only reads and prints
// the plan.
func DocsPublish(ctx context.Context, env config.Env, o DocsOptions, out io.Writer) error {
	get := func(k string) string {
		if o.Lookup == nil {
			return ""
		}
		v, _ := o.Lookup(k)
		return strings.TrimSpace(v)
	}
	base, token, rootID := get(EnvConfluenceURL), get(EnvConfluenceToken), get(EnvConfluencePageID)
	var missing []string
	for _, kv := range [][2]string{{EnvConfluenceURL, base}, {EnvConfluenceToken, token}, {EnvConfluencePageID, rootID}} {
		if kv[1] == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("docs publish needs %s in the environment (see docs/operations.md)", strings.Join(missing, ", "))
	}
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(rootID) {
		return fmt.Errorf("%s must be the numeric ID of the root page, got %q", EnvConfluencePageID, rootID)
	}
	brokerURL, err := docsBrokerURL(env, o.BrokerURL)
	if err != nil {
		return err
	}
	dir := o.Dir
	if dir == "" {
		dir = guide.DefaultDir
	}
	client, err := confluence.NewClient(base, token, o.HTTPClient)
	if err != nil {
		return fmt.Errorf("%s: %w", EnvConfluenceURL, err)
	}
	ver := version.String()
	pub := &confluence.Publisher{API: client, RootID: rootID, Message: "tls-broker " + ver, Volatile: noteVersion,
		ObsoletePrefix: ObsoleteTitlePrefix}

	root, err := pub.Root(ctx)
	if err != nil {
		return err
	}
	body, err := guide.ExportConfluence(os.DirFS(dir), guide.ConfluenceOptions{
		ExternalURL: brokerURL,
		Note: fmt.Sprintf("%s (version %s). Edit the source in the repository (docs/%s), not here.",
			notePrefix, ver, guide.File),
	})
	if err != nil {
		return fmt.Errorf("reading the guide in %s: %w", dir, err)
	}
	if o.OutDir != "" {
		if err := writeStorage(o.OutDir, body, out); err != nil {
			return err
		}
	}
	plan, err := pub.Plan(ctx, root, confluence.Doc{Source: guide.File, Body: body}, o.Prune)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Confluence %s, space %s, root page %s %q; broker URL %s\n", base, root.SpaceKey, root.ID, root.Title, brokerURL)
	plan.Print(out)
	if !o.Prune {
		for _, ob := range plan.Obsolete {
			if ob.Children == 0 {
				fmt.Fprintln(out, "obsolete pages are kept; run with --prune to delete them")
				break
			}
		}
	}
	if o.DryRun {
		fmt.Fprintln(out, "dry run: nothing was changed in Confluence")
		return nil
	}
	if err := pub.Apply(ctx, plan, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "done")
	return nil
}

// docsBrokerURL is the flag, or server.external_url of the active
// configuration generation, read without changing anything in the data
// directory.
func docsBrokerURL(env config.Env, flag string) (string, error) {
	if flag != "" {
		u, err := url.Parse(flag)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", fmt.Errorf("--broker-url %q must be an http(s) URL", flag)
		}
		return strings.TrimRight(flag, "/"), nil
	}
	path := filepath.Join(env.DataDir, "config", "current")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("no active configuration at %s to take server.external_url from; pass --broker-url", path)
		}
		return "", err
	}
	cfg, rep := config.Parse(data, env, 0)
	if cfg == nil {
		return "", fmt.Errorf("the active configuration %s is invalid (%v); pass --broker-url", path, rep.Errors)
	}
	if cfg.Server.ExternalURL == "" {
		return "", errors.New("the active configuration has no server.external_url; pass --broker-url")
	}
	return cfg.Server.ExternalURL, nil
}

// writeStorage writes the body as guide.xhtml.
func writeStorage(dir, body string, out io.Writer) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	file := filepath.Join(dir, strings.TrimSuffix(guide.File, ".md")+".xhtml")
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote the storage-format body to %s\n", file)
	return nil
}
