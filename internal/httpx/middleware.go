package httpx

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"context"

	"tls-broker/internal/core"
)

// RequestIDHeader carries the request ID on requests (from a trusted proxy)
// and responses.
const RequestIDHeader = "X-Request-ID"

// RequestIDFrom returns the request ID stored by RequestID, or "".
func RequestIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(requestIDKey).(string)
	return s
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// RequestID assigns every request an ID, stores it in the context and sets it
// on the response. A well-formed X-Request-ID from a trusted proxy (see
// RealIP, which must run first) is kept; otherwise a random one is generated.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := ""
		if ClientFrom(r.Context()).Trusted {
			if v := r.Header.Get(RequestIDHeader); validID(v) {
				id = v
			}
		}
		if id == "" {
			id = newID()
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// statusWriter records the status and size of a response.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status, s.wrote = http.StatusOK, true
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("httpx: hijacking not supported")
}

// Unwrap lets http.ResponseController reach the real writer.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// AccessLog logs one structured line per request after it finishes: method,
// path (never the query string), status, bytes, duration, source IP, request
// ID and user agent. 5xx logs at error level, 4xx at warn, successful
// HealthPath probes at debug, the rest at info. logger nil means
// slog.Default().
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log := logger
			if log == nil {
				log = slog.Default()
			}
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				c := ClientFrom(r.Context())
				attrs := []any{
					"method", r.Method, "path", r.URL.Path, "status", sw.status, "bytes", sw.bytes,
					"duration_ms", float64(time.Since(start).Microseconds()) / 1000,
					"source_ip", c.IP.String(), "request_id", RequestIDFrom(r.Context()),
					"user_agent", r.UserAgent(),
				}
				if c.Flag != FlagNone {
					attrs = append(attrs, "ip_flag", c.Flag)
				}
				level := slog.LevelInfo
				switch {
				case sw.status >= 500:
					level = slog.LevelError
				case sw.status >= 400:
					level = slog.LevelWarn
				case r.URL.Path == HealthPath:
					// Liveness probes every few seconds are noise at info.
					level = slog.LevelDebug
				}
				log.Log(r.Context(), level, "request", attrs...)
			}()
			next.ServeHTTP(sw, r)
		})
	}
}

// Recover turns a handler panic into a 500 serverInternal problem and an
// error log with the stack. http.ErrAbortHandler is passed on. If the
// response has already started nothing more is written. logger nil means
// slog.Default().
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w}
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log := logger
				if log == nil {
					log = slog.Default()
				}
				log.Error("handler panic", "panic", v, "method", r.Method, "path", r.URL.Path,
					"request_id", RequestIDFrom(r.Context()), "stack", string(debug.Stack()))
				if !sw.wrote {
					WriteProblem(w, core.NewProblem(core.ProblemServerInternal, "internal error"))
				}
			}()
			next.ServeHTTP(sw, r)
		})
	}
}

// MaxBody limits request bodies to n bytes; reading more fails with
// *http.MaxBytesError, which handlers should map to a 413 problem (see
// IsBodyTooLarge).
func MaxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > n {
				WriteProblemStatus(w, http.StatusRequestEntityTooLarge, core.ProblemMalformed, "request body too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// IsBodyTooLarge reports whether err comes from the MaxBody limit.
func IsBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// TimeoutRule gives requests whose path starts with Prefix a time budget.
type TimeoutRule struct {
	Prefix  string
	Timeout time.Duration // 0 leaves the request bounded only by the server
}

// writeSlack is how long the response write deadline outlives the context
// deadline, so a handler that reacts to the cancelled context can still write
// its error.
const writeSlack = 5 * time.Second

// PathTimeouts applies the budget of the longest matching rule (default when
// none matches): the request context gets that deadline and the connection's
// write deadline is moved to deadline+slack with http.ResponseController, so a
// path may be given more time than the server-wide WriteTimeout. Long-held
// requests (ACME finalize waiting for admission, direct-mode synchronous
// issuance) get a generous rule; everything else a short one. Unlike
// http.TimeoutHandler it does not buffer responses.
func PathTimeouts(def time.Duration, rules ...TimeoutRule) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d, best := def, -1
			for _, rule := range rules {
				if strings.HasPrefix(r.URL.Path, rule.Prefix) && len(rule.Prefix) > best {
					d, best = rule.Timeout, len(rule.Prefix)
				}
			}
			if d <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d + writeSlack))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
