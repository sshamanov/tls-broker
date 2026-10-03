package httpx

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"
)

// HealthPath is where the app mounts Health; AccessLog logs successful
// requests to it at debug.
const HealthPath = "/healthz"

// Health serves /healthz: process readiness, not upstream CA health.
//
// 200 {"status":"ok"} once SetReady(true) was called and Ping (if any)
// succeeds; 503 {"status":"starting"} before that or {"status":"shutting_down"}
// after SetReady(false); 503 {"status":"unavailable","reason":"database"}
// when Ping fails. Error text is never exposed.
type Health struct {
	// Ping checks the local database (cheap, e.g. PingContext). Nil skips.
	Ping func(ctx context.Context) error
	// PingTimeout bounds Ping; 0 means 2 s.
	PingTimeout time.Duration

	ready    atomic.Bool
	draining atomic.Bool
}

// SetReady marks startup complete (true) or shutdown begun (false).
func (h *Health) SetReady(ready bool) {
	h.ready.Store(ready)
	h.draining.Store(!ready)
}

// ServeHTTP implements http.Handler.
func (h *Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "method_not_allowed"})
		return
	}
	status, body := http.StatusOK, map[string]string{"status": "ok"}
	switch {
	case h.draining.Load():
		status, body = http.StatusServiceUnavailable, map[string]string{"status": "shutting_down"}
	case !h.ready.Load():
		status, body = http.StatusServiceUnavailable, map[string]string{"status": "starting"}
	case h.Ping != nil:
		d := h.PingTimeout
		if d <= 0 {
			d = 2 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), d)
		err := h.Ping(ctx)
		cancel()
		if err != nil {
			status, body = http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "reason": "database"}
		}
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}
	WriteJSON(w, status, body)
}
