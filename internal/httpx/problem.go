package httpx

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"tls-broker/internal/core"
)

// WriteJSON writes v as a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(b)+1))
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

// WriteProblem writes p as an application/problem+json response. The status
// is p.Status, or the default for its type when zero. A positive RetryAfter
// becomes a Retry-After header in whole seconds, rounded up.
func WriteProblem(w http.ResponseWriter, p *core.Problem) {
	if p == nil {
		p = core.NewProblem(core.ProblemServerInternal, "internal error")
	}
	status := p.Status
	if status == 0 {
		status = core.ProblemStatus(p.Type)
	}
	b, err := json.Marshal(p)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", core.ProblemContentType)
	h.Set("Content-Length", strconv.Itoa(len(b)+1))
	if p.RetryAfter > 0 {
		h.Set("Retry-After", strconv.FormatInt(int64((p.RetryAfter+time.Second-1)/time.Second), 10))
	}
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

// WriteProblemStatus writes a problem of the given type and detail with an
// explicit HTTP status.
func WriteProblemStatus(w http.ResponseWriter, status int, typ, detail string) {
	WriteProblem(w, core.NewProblem(typ, "%s", detail).WithStatus(status))
}

// WriteError maps err with core.ProblemFromError (never leaking internal
// error text) and writes the result. A nil err writes a generic 500.
func WriteError(w http.ResponseWriter, err error) {
	WriteProblem(w, core.ProblemFromError(err))
}
