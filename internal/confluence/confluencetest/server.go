// Package confluencetest is an in-memory Confluence Server/Data Center for
// tests: an httptest server answering the REST endpoints confluence.Client
// uses, with bearer-token checks, unique titles per space, version checks
// and fault injection.
package confluencetest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Page is a stored page.
type Page struct {
	ID       string
	Space    string
	ParentID string
	Title    string
	Version  int
	Body     string
	Messages []string // version messages of the updates, oldest first
}

// Server is the fake. Lock-free fields are set before use; the rest is
// guarded by its mutex.
type Server struct {
	*httptest.Server
	// Token is the only accepted bearer token.
	Token string
	// Store, when set, is applied to every body written, imitating the
	// normalization Confluence does on save.
	Store func(string) string

	mu        sync.Mutex
	pages     map[string]*Page
	order     []string // page IDs in sibling order (one global list suffices)
	readOnly  bool
	conflicts int
	writes    int
	reqs      []string
}

// New starts a server holding one root page.
func New(token, rootID, space, rootTitle string) *Server {
	s := &Server{Token: token, pages: map[string]*Page{}}
	s.pages[rootID] = &Page{ID: rootID, Space: space, Title: rootTitle, Version: 1}
	s.order = append(s.order, rootID)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /rest/api/content/{id}", s.get)
	mux.HandleFunc("GET /rest/api/content/{id}/child/page", s.children)
	mux.HandleFunc("PUT /rest/api/content/{id}", s.update)
	mux.HandleFunc("DELETE /rest/api/content/{id}", s.delete)
	s.Server = httptest.NewServer(s.auth(mux))
	return s
}

// Add stores a page directly (not counted as a write).
func (s *Server) Add(p Page) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Version == 0 {
		p.Version = 1
	}
	s.pages[p.ID] = &p
	s.order = append(s.order, p.ID)
}

// Get returns a copy of a page.
func (s *Server) Get(id string) (Page, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pages[id]
	if !ok {
		return Page{}, false
	}
	return *p, true
}

// Children returns the child pages of id in order.
func (s *Server) Children(id string) []Page {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Page
	for _, cid := range s.order {
		if p := s.pages[cid]; p.ParentID == id {
			out = append(out, *p)
		}
	}
	return out
}

// Writes counts successful updates and deletes.
func (s *Server) Writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

// Requests lists "METHOD path" of every request, in order.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

// SetReadOnly makes every write answer 403.
func (s *Server) SetReadOnly(v bool) { s.mu.Lock(); s.readOnly = v; s.mu.Unlock() }

// Conflicts makes the next n updates meet a concurrent edit.
func (s *Server) Conflicts(n int) { s.mu.Lock(); s.conflicts = n; s.mu.Unlock() }

func (s *Server) auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+s.Token {
			// Confluence answers a bad token with 401 and a short text.
			http.Error(w, "Basic Authentication Failure - Reason : AUTHENTICATED_FAILED", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Atlassian-Token") != "no-check" {
			fail(w, http.StatusForbidden, "XSRF check failed")
			return
		}
		h.ServeHTTP(w, r)
	})
}

func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": status, "message": msg})
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (p *Page) json(expand string) map[string]any {
	m := map[string]any{"id": p.ID, "type": "page", "title": p.Title, "status": "current"}
	if strings.Contains(expand, "space") {
		m["space"] = map[string]any{"key": p.Space}
	}
	if strings.Contains(expand, "version") {
		m["version"] = map[string]any{"number": p.Version}
	}
	if strings.Contains(expand, "body.storage") {
		m["body"] = map[string]any{"storage": map[string]any{"value": p.Body, "representation": "storage"}}
	}
	return m
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pages[r.PathValue("id")]
	if !ok {
		fail(w, http.StatusNotFound, "No content found with id: ContentId{id="+r.PathValue("id")+"}")
		return
	}
	reply(w, p.json(r.URL.Query().Get("expand")))
}

func (s *Server) children(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := r.PathValue("id")
	if _, ok := s.pages[id]; !ok {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	q := r.URL.Query()
	start, _ := strconv.Atoi(q.Get("start"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 25
	}
	var all []map[string]any
	for _, cid := range s.order {
		if p := s.pages[cid]; p.ParentID == id {
			all = append(all, p.json(q.Get("expand")))
		}
	}
	res := []map[string]any{}
	for i := start; i < len(all) && i < start+limit; i++ {
		res = append(res, all[i])
	}
	reply(w, map[string]any{"results": res, "start": start, "limit": limit, "size": len(res)})
}

type body struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Title   string `json:"title"`
	Version struct {
		Number  int    `json:"number"`
		Message string `json:"message"`
	} `json:"version"`
	Body struct {
		Storage struct {
			Value          string `json:"value"`
			Representation string `json:"representation"`
		} `json:"storage"`
	} `json:"body"`
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request) (*body, bool) {
	var b body
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return nil, false
	}
	if b.Type != "page" || b.Title == "" || b.Body.Storage.Representation != "storage" {
		fail(w, http.StatusBadRequest, "type page, title and a storage body are required")
		return nil, false
	}
	if s.readOnly {
		fail(w, http.StatusForbidden, "Not permitted to edit this content")
		return nil, false
	}
	return &b, true
}

func (s *Server) store(v string) string {
	if s.Store != nil {
		return s.Store(v)
	}
	return v
}

func (s *Server) titleTaken(space, title, except string) bool {
	for id, p := range s.pages {
		if id != except && p.Space == space && p.Title == title {
			return true
		}
	}
	return false
}

func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pages[r.PathValue("id")]
	if !ok {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	b, ok := s.decode(w, r)
	if !ok {
		return
	}
	if s.conflicts > 0 {
		s.conflicts--
		p.Version++
		p.Body += "<p>edited meanwhile</p>"
	}
	if b.Version.Number != p.Version+1 {
		fail(w, http.StatusConflict, fmt.Sprintf("Version must be incremented on update. Current version is: %d", p.Version))
		return
	}
	if s.titleTaken(p.Space, b.Title, p.ID) {
		fail(w, http.StatusBadRequest, "A page with this title already exists")
		return
	}
	p.Title, p.Body, p.Version = b.Title, s.store(b.Body.Storage.Value), b.Version.Number
	p.Messages = append(p.Messages, b.Version.Message)
	s.writes++
	reply(w, p.json("version,space"))
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := r.PathValue("id")
	if _, ok := s.pages[id]; !ok {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	if s.readOnly {
		fail(w, http.StatusForbidden, "Not permitted to delete this content")
		return
	}
	delete(s.pages, id)
	s.order = slices.DeleteFunc(s.order, func(x string) bool { return x == id })
	s.writes++
	w.WriteHeader(http.StatusNoContent)
}
