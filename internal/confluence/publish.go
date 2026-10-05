package confluence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Doc is what to publish to the root page.
type Doc struct {
	Source string // where it comes from, for messages (a file name)
	Body   string // storage format
}

// Action is what publishing does to the root page.
type Action string

// Actions.
const (
	Update    Action = "update"
	Unchanged Action = "unchanged"
)

// Obsolete is a child page of the root whose title starts with the
// publisher's ObsoletePrefix: a page an earlier publisher created.
type Obsolete struct {
	Page
	// Children is how many child pages it has itself; such a page is never
	// deleted.
	Children int
}

// Plan is what a publish would do.
type Plan struct {
	Root   Page
	Action Action
	Doc    Doc
	// Obsolete pages are deleted with Prune, otherwise only reported.
	Obsolete []Obsolete
	// Extra are the other child pages of the root. They are reported and
	// never changed or deleted.
	Extra []Page
	// Prune: Apply deletes the obsolete pages that have no children.
	Prune bool
}

// Publisher publishes a Doc to an existing root page. With Prune it also
// deletes the root's child pages titled ObsoletePrefix + anything (and only
// those) that have no child pages of their own. It never creates pages and
// never touches pages that are not the root or its children.
type Publisher struct {
	API    API
	RootID string
	// Message is the version comment of the update.
	Message string
	// Volatile, when set, matches text that does not count as a change
	// (the generator note's version) when bodies are compared.
	Volatile *regexp.Regexp
	// ObsoletePrefix starts the titles of the child pages that are
	// obsolete; "" means none are.
	ObsoletePrefix string
}

// Root reads the root page; a 404 says plainly that the page is missing or
// hidden from the token's user.
func (p *Publisher) Root(ctx context.Context) (*Page, error) {
	root, err := p.API.Page(ctx, p.RootID)
	switch StatusOf(err) {
	case 0:
	case http.StatusNotFound:
		return nil, fmt.Errorf("root page %s does not exist or the token's user cannot see it: %w", p.RootID, err)
	case http.StatusForbidden:
		return nil, fmt.Errorf("the token's user may not read root page %s: %w", p.RootID, err)
	}
	if err != nil {
		return nil, err
	}
	if root.SpaceKey == "" {
		return nil, fmt.Errorf("root page %s: Confluence did not say which space it is in", p.RootID)
	}
	return root, nil
}

// Same reports whether two storage bodies are the same content.
func (p *Publisher) Same(have, want string) bool {
	h, _ := Normalize(have)
	w, _ := Normalize(want)
	if p.Volatile != nil {
		h = p.Volatile.ReplaceAllString(h, "")
		w = p.Volatile.ReplaceAllString(w, "")
	}
	return h == w
}

// Plan compares root (from Root) with doc and sorts the root's child pages
// into obsolete and extra ones. It only reads.
func (p *Publisher) Plan(ctx context.Context, root *Page, doc Doc, prune bool) (*Plan, error) {
	if doc.Body == "" {
		return nil, errors.New("nothing to publish")
	}
	kids, err := p.API.Children(ctx, root.ID)
	if err != nil {
		return nil, fmt.Errorf("listing the child pages of %s: %w", root.ID, err)
	}
	plan := &Plan{Root: *root, Action: Unchanged, Doc: doc, Prune: prune}
	if !p.Same(root.Body, doc.Body) {
		plan.Action = Update
	}
	for _, k := range kids {
		if p.ObsoletePrefix == "" || !strings.HasPrefix(k.Title, p.ObsoletePrefix) {
			plan.Extra = append(plan.Extra, k)
			continue
		}
		grand, err := p.API.Children(ctx, k.ID)
		if err != nil {
			return nil, fmt.Errorf("listing the child pages of %q (id %s): %w", k.Title, k.ID, err)
		}
		plan.Obsolete = append(plan.Obsolete, Obsolete{Page: k, Children: len(grand)})
	}
	return plan, nil
}

// Print writes the plan, one line per page.
func (plan *Plan) Print(w io.Writer) {
	r := plan.Root
	if plan.Action == Update {
		fmt.Fprintf(w, "%-9s  %q  id %s, version %d -> %d  (%s, root page)\n", plan.Action, r.Title, r.ID, r.Version, r.Version+1, plan.Doc.Source)
	} else {
		fmt.Fprintf(w, "%-9s  %q  id %s, version %d  (%s, root page)\n", plan.Action, r.Title, r.ID, r.Version, plan.Doc.Source)
	}
	for _, o := range plan.Obsolete {
		switch {
		case o.Children > 0:
			fmt.Fprintf(w, "obsolete   %q  id %s: has %d child pages, so it is kept; move them first\n", o.Title, o.ID, o.Children)
		case plan.Prune:
			fmt.Fprintf(w, "delete     %q  id %s  (obsolete page from an earlier publish)\n", o.Title, o.ID)
		default:
			fmt.Fprintf(w, "obsolete   %q  id %s  (kept; pruning deletes it)\n", o.Title, o.ID)
		}
	}
	for _, e := range plan.Extra {
		fmt.Fprintf(w, "not from the guide, left alone: %q  id %s\n", e.Title, e.ID)
	}
}

// Apply carries the plan out: the root update (an update that meets a
// version conflict reads the page again and retries once), then, with
// Prune, the deletions. It stops at the first error; what was done stays
// done and a second run continues from there.
func (p *Publisher) Apply(ctx context.Context, plan *Plan, w io.Writer) error {
	if plan.Action == Update {
		v, err := p.update(ctx, plan)
		if err != nil {
			return fmt.Errorf("updating %q (id %s): %w", plan.Root.Title, plan.Root.ID, writeHint(err))
		}
		if v == 0 {
			fmt.Fprintf(w, "unchanged  %q  id %s (changed meanwhile to the same content)\n", plan.Root.Title, plan.Root.ID)
		} else {
			fmt.Fprintf(w, "updated    %q  id %s, version %d\n", plan.Root.Title, plan.Root.ID, v)
		}
	}
	if !plan.Prune {
		return nil
	}
	for _, o := range plan.Obsolete {
		if o.Children > 0 {
			continue
		}
		if err := p.API.Delete(ctx, o.ID); err != nil {
			if StatusOf(err) == http.StatusNotFound {
				fmt.Fprintf(w, "gone       %q  id %s (deleted meanwhile)\n", o.Title, o.ID)
				continue
			}
			return fmt.Errorf("deleting %q (id %s): %w", o.Title, o.ID, writeHint(err))
		}
		fmt.Fprintf(w, "deleted    %q  id %s\n", o.Title, o.ID)
	}
	return nil
}

func writeHint(err error) error {
	if StatusOf(err) == http.StatusForbidden {
		return fmt.Errorf("the token's user may read but not change these pages: %w", err)
	}
	return err
}

// update writes the root page; it returns the new version, or 0 when a
// conflict turned out to be someone writing the same content.
func (p *Publisher) update(ctx context.Context, plan *Plan) (int, error) {
	r := plan.Root
	pg, err := p.API.Update(ctx, r.ID, r.Title, plan.Doc.Body, r.Version+1, p.Message)
	if StatusOf(err) != http.StatusConflict {
		if err != nil {
			return 0, err
		}
		return pg.Version, nil
	}
	cur, rerr := p.API.Page(ctx, r.ID)
	if rerr != nil {
		return 0, fmt.Errorf("%w; reading it again: %v", err, rerr)
	}
	if p.Same(cur.Body, plan.Doc.Body) {
		return 0, nil
	}
	pg, err = p.API.Update(ctx, r.ID, cur.Title, plan.Doc.Body, cur.Version+1, p.Message)
	if err != nil {
		return 0, fmt.Errorf("after one retry: %w", err)
	}
	return pg.Version, nil
}
