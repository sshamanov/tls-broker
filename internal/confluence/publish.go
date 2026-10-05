package confluence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
)

// Doc is one page to publish.
type Doc struct {
	Source string // where it comes from, for messages (a file name)
	Title  string // Confluence title; ignored for the root, which keeps its own
	Body   string // storage format
}

// Action is what publishing does to one page.
type Action string

// Actions.
const (
	Create    Action = "create"
	Update    Action = "update"
	Unchanged Action = "unchanged"
)

// Step is the plan for one Doc.
type Step struct {
	Action  Action
	Doc     Doc
	Root    bool   // the root page
	ID      string // existing page; "" for Create
	Title   string // the title the page has or gets
	Version int    // existing version (0 for Create)
	// Taken, for Create: the title is used by another page of the space
	// (its ID), so Confluence would refuse the page.
	Taken string
}

// Plan is what a publish would do.
type Plan struct {
	Root  Page
	Steps []Step // the root first, then the children in order
	// Extra are child pages of the root that are not in the guide. They
	// are reported and never changed or deleted.
	Extra []Page
	// Reorder: the children are not (or will not be) in guide order.
	Reorder bool
}

// Publisher publishes a root Doc to an existing page and the other Docs as
// its child pages, matched by title. It never deletes anything and never
// touches pages that are not the root or its children.
type Publisher struct {
	API    API
	RootID string
	// Message is the version comment of every create and update.
	Message string
	// Volatile, when set, matches text that does not count as a change
	// (the generator note's version) when bodies are compared.
	Volatile *regexp.Regexp
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

// Plan compares root (from Root) and its children with the docs: docs[0]
// goes to the root, the others are children in that order. It only reads.
func (p *Publisher) Plan(ctx context.Context, root *Page, docs []Doc) (*Plan, error) {
	if len(docs) == 0 {
		return nil, errors.New("nothing to publish")
	}
	kids, err := p.API.Children(ctx, root.ID)
	if err != nil {
		return nil, fmt.Errorf("listing the child pages of %s: %w", root.ID, err)
	}
	byTitle := map[string]Page{}
	for _, k := range kids {
		byTitle[k.Title] = k
	}
	plan := &Plan{Root: *root}
	st := Step{Action: Unchanged, Doc: docs[0], Root: true, ID: root.ID, Title: root.Title, Version: root.Version}
	if !p.Same(root.Body, docs[0].Body) {
		st.Action = Update
	}
	plan.Steps = append(plan.Steps, st)
	want := map[string]bool{}
	for _, d := range docs[1:] {
		want[d.Title] = true
		k, ok := byTitle[d.Title]
		if !ok {
			st := Step{Action: Create, Doc: d, Title: d.Title}
			others, err := p.API.FindTitle(ctx, root.SpaceKey, d.Title)
			if err != nil {
				return nil, fmt.Errorf("looking for %q in space %s: %w", d.Title, root.SpaceKey, err)
			}
			if len(others) > 0 {
				st.Taken = others[0].ID
			}
			plan.Steps = append(plan.Steps, st)
			plan.Reorder = true
			continue
		}
		st := Step{Action: Unchanged, Doc: d, ID: k.ID, Title: k.Title, Version: k.Version}
		if !p.Same(k.Body, d.Body) {
			st.Action = Update
		}
		plan.Steps = append(plan.Steps, st)
	}
	var order []string
	for _, k := range kids {
		if want[k.Title] {
			order = append(order, k.Title)
		} else {
			plan.Extra = append(plan.Extra, Page{ID: k.ID, Title: k.Title, Version: k.Version})
		}
	}
	var guideOrder []string
	for _, d := range docs[1:] {
		if _, ok := byTitle[d.Title]; ok {
			guideOrder = append(guideOrder, d.Title)
		}
	}
	if !slices.Equal(order, guideOrder) {
		plan.Reorder = true
	}
	return plan, nil
}

// Print writes the plan, one line per page.
func (plan *Plan) Print(w io.Writer) {
	for _, s := range plan.Steps {
		where := s.Doc.Source
		if s.Root {
			where += ", root page"
		}
		switch {
		case s.Action == Create && s.Taken != "":
			fmt.Fprintf(w, "%-9s  %q  (%s) BLOCKED: page %s elsewhere in space %s has this title\n", s.Action, s.Title, where, s.Taken, plan.Root.SpaceKey)
		case s.Action == Create:
			fmt.Fprintf(w, "%-9s  %q  (%s)\n", s.Action, s.Title, where)
		case s.Action == Update:
			fmt.Fprintf(w, "%-9s  %q  id %s, version %d -> %d  (%s)\n", s.Action, s.Title, s.ID, s.Version, s.Version+1, where)
		default:
			fmt.Fprintf(w, "%-9s  %q  id %s, version %d  (%s)\n", s.Action, s.Title, s.ID, s.Version, where)
		}
	}
	for _, e := range plan.Extra {
		fmt.Fprintf(w, "not in the guide, left alone: %q  id %s\n", e.Title, e.ID)
	}
	if plan.Reorder {
		fmt.Fprintln(w, "order: child pages are put in guide order")
	}
}

// Apply carries the plan out: creates, then updates (an update that meets
// a version conflict reads the page again and retries once), then the
// child order. It stops at the first error; what was done stays done and a
// second run continues from there.
func (p *Publisher) Apply(ctx context.Context, plan *Plan, w io.Writer) error {
	for _, s := range plan.Steps {
		if s.Action == Create && s.Taken != "" {
			return fmt.Errorf("cannot create %q: page %s in space %s already has this title (titles are unique per space); rename or move it first",
				s.Title, s.Taken, plan.Root.SpaceKey)
		}
	}
	created := 0
	for _, s := range plan.Steps {
		switch s.Action {
		case Create:
			pg, err := p.API.Create(ctx, plan.Root.SpaceKey, plan.Root.ID, s.Title, s.Doc.Body)
			if err != nil {
				return fmt.Errorf("creating %q: %w", s.Title, writeHint(err))
			}
			created++
			fmt.Fprintf(w, "created    %q  id %s\n", s.Title, pg.ID)
		case Update:
			v, err := p.update(ctx, s)
			if err != nil {
				return fmt.Errorf("updating %q (id %s): %w", s.Title, s.ID, writeHint(err))
			}
			if v == 0 {
				fmt.Fprintf(w, "unchanged  %q  id %s (changed meanwhile to the same content)\n", s.Title, s.ID)
			} else {
				fmt.Fprintf(w, "updated    %q  id %s, version %d\n", s.Title, s.ID, v)
			}
		}
	}
	if plan.Reorder {
		if err := p.order(ctx, plan, w); err != nil {
			return err
		}
	}
	return nil
}

func writeHint(err error) error {
	if StatusOf(err) == http.StatusForbidden {
		return fmt.Errorf("the token's user may read but not change these pages: %w", err)
	}
	return err
}

// update writes one page; it returns the new version, or 0 when a conflict
// turned out to be someone writing the same content.
func (p *Publisher) update(ctx context.Context, s Step) (int, error) {
	title := s.Title
	pg, err := p.API.Update(ctx, s.ID, title, s.Doc.Body, s.Version+1, p.Message)
	if StatusOf(err) != http.StatusConflict {
		if err != nil {
			return 0, err
		}
		return pg.Version, nil
	}
	cur, rerr := p.API.Page(ctx, s.ID)
	if rerr != nil {
		return 0, fmt.Errorf("%w; reading it again: %v", err, rerr)
	}
	if p.Same(cur.Body, s.Doc.Body) {
		return 0, nil
	}
	pg, err = p.API.Update(ctx, s.ID, title, s.Doc.Body, cur.Version+1, p.Message)
	if err != nil {
		return 0, fmt.Errorf("after one retry: %w", err)
	}
	return pg.Version, nil
}

// order moves the guide's child pages into guide order, each after the one
// before it. Pages not in the guide stay where they are relative to the
// first guide page.
func (p *Publisher) order(ctx context.Context, plan *Plan, w io.Writer) error {
	kids, err := p.API.Children(ctx, plan.Root.ID)
	if err != nil {
		return fmt.Errorf("listing the child pages again: %w", err)
	}
	ids := map[string]string{}
	for _, k := range kids {
		ids[k.Title] = k.ID
	}
	var want []string
	for _, s := range plan.Steps[1:] {
		want = append(want, ids[s.Title])
	}
	var have []string
	for _, k := range kids {
		for _, id := range want {
			if k.ID == id {
				have = append(have, id)
			}
		}
	}
	if slices.Equal(have, want) {
		return nil
	}
	for i := 1; i < len(want); i++ {
		if want[i] == "" || want[i-1] == "" {
			continue
		}
		if err := p.API.MoveAfter(ctx, want[i], want[i-1]); err != nil {
			if s := StatusOf(err); s == http.StatusNotFound || s == http.StatusMethodNotAllowed {
				fmt.Fprintf(w, "warning: this Confluence cannot reorder pages through the REST API (%v); order the child pages by hand\n", err)
				return nil
			}
			return fmt.Errorf("ordering the child pages: %w", writeHint(err))
		}
	}
	fmt.Fprintln(w, "ordered    child pages in guide order")
	return nil
}
