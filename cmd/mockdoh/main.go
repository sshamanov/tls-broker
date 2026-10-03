// Command mockdoh is a DEVELOPMENT-ONLY DNS-over-HTTPS server (RFC 8484, GET
// and POST wire format) answering from a static record table. Point the
// broker at it with TLS_BROKER_DOH_ENDPOINTS to make LAN test names resolve
// to LAN addresses for the DNS gate. Never use it in production: whoever
// controls its table controls the gate's view of DNS.
//
//	mockdoh --listen 127.0.0.1:8053 \
//	  --record 'text2.example.com A 192.0.2.10' \
//	  --record 'www.example.com CNAME text2.example.com' \
//	  --file records.yaml \
//	  --upstream https://cloudflare-dns.com/dns-query
//
// A record is "<name> <type> <value>" in zone-file syntax for A, CNAME, TXT
// and CAA (for example `example.com CAA 0 issue "letsencrypt.org"`). The YAML
// file holds the same strings under "records:". CNAMEs are followed inside
// the table. A name that is not in the table is NXDOMAIN, or, with
// --upstream, forwarded to that DoH server (use it with a real Route53 so
// DNS-01 propagation checks and CAA lookups still see public DNS).
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const (
	contentType = "application/dns-message"
	maxMsg      = 65535
	maxChase    = 16
)

// records is the static table: canonical FQDN -> type -> records.
type records map[string]map[uint16][]dns.RR

// add parses one "<name> <type> <value>" line.
func (rs records) add(line string, ttl uint32) error {
	f := strings.Fields(line)
	if len(f) < 3 {
		return fmt.Errorf("record %q: want \"<name> <type> <value>\"", line)
	}
	typ := strings.ToUpper(f[1])
	switch typ {
	case "A", "CNAME", "TXT", "CAA":
	default:
		return fmt.Errorf("record %q: type %s not supported (A, CNAME, TXT, CAA)", line, f[1])
	}
	// The value is everything after the second field, spacing preserved.
	rest := strings.TrimSpace(line)
	for range 2 {
		rest = strings.TrimLeft(rest[strings.IndexFunc(rest, isSpace):], " \t")
	}
	value := rest
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(f[0]), ttl, typ, value))
	if err != nil || rr == nil {
		return fmt.Errorf("record %q: %v", line, err)
	}
	name := dns.CanonicalName(rr.Header().Name)
	rr.Header().Name = name
	if c, ok := rr.(*dns.CNAME); ok {
		c.Target = dns.CanonicalName(c.Target)
	}
	if rs[name] == nil {
		rs[name] = map[uint16][]dns.RR{}
	}
	rs[name][rr.Header().Rrtype] = append(rs[name][rr.Header().Rrtype], rr)
	return nil
}

// loadFile reads a YAML file with a "records:" list of record strings.
func (rs records) loadFile(path string, ttl uint32) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc struct {
		Records []string `yaml:"records"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, r := range doc.Records {
		if err := rs.add(r, ttl); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

// server answers DoH queries.
type server struct {
	table    records
	upstream string
	client   *http.Client
	log      *slog.Logger
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var wire []byte
	switch r.Method {
	case http.MethodGet:
		b, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil || len(b) == 0 {
			http.Error(w, "missing or invalid dns parameter", http.StatusBadRequest)
			return
		}
		wire = b
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, contentType) {
			http.Error(w, "content type must be "+contentType, http.StatusUnsupportedMediaType)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, maxMsg+1))
		if err != nil || len(b) > maxMsg {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		wire = b
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := new(dns.Msg)
	if err := q.Unpack(wire); err != nil || len(q.Question) != 1 {
		http.Error(w, "malformed DNS query", http.StatusBadRequest)
		return
	}
	resp, how := s.answer(r.Context(), q, wire)
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "cannot pack answer", http.StatusInternalServerError)
		return
	}
	s.log.Info("query", "name", q.Question[0].Name, "type", dns.TypeToString[q.Question[0].Qtype],
		"rcode", dns.RcodeToString[resp.Rcode], "answers", len(resp.Answer), "source", how)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "max-age=0")
	_, _ = w.Write(out)
}

// answer resolves q from the table, following CNAMEs inside it. A name the
// table does not know is forwarded when an upstream is set, else NXDOMAIN.
func (s *server) answer(ctx context.Context, q *dns.Msg, wire []byte) (*dns.Msg, string) {
	m := new(dns.Msg)
	m.SetReply(q)
	m.RecursionAvailable = true
	qt := q.Question[0].Qtype
	cur := dns.CanonicalName(q.Question[0].Name)
	if q.Question[0].Qclass != dns.ClassINET {
		m.Rcode = dns.RcodeRefused
		return m, "table"
	}
	for range maxChase {
		node, known := s.table[cur]
		if !known {
			if len(m.Answer) == 0 && s.upstream != "" {
				if fwd, err := s.forward(ctx, wire); err == nil {
					return fwd, "upstream"
				} else {
					s.log.Warn("upstream failed", "name", cur, "err", err)
					m.Rcode = dns.RcodeServerFailure
					return m, "upstream"
				}
			}
			if len(m.Answer) == 0 {
				m.Rcode = dns.RcodeNameError
			}
			// A CNAME target outside the table: the client asks for it next.
			return m, "table"
		}
		if rrs := node[qt]; len(rrs) > 0 {
			m.Answer = append(m.Answer, copyRRs(rrs)...)
			return m, "table"
		}
		cn := node[dns.TypeCNAME]
		if len(cn) == 0 || qt == dns.TypeCNAME {
			return m, "table" // NODATA
		}
		m.Answer = append(m.Answer, dns.Copy(cn[0]))
		cur = cn[0].(*dns.CNAME).Target
	}
	m.Rcode = dns.RcodeServerFailure
	return m, "table"
}

func copyRRs(in []dns.RR) []dns.RR {
	out := make([]dns.RR, len(in))
	for i, rr := range in {
		out[i] = dns.Copy(rr)
	}
	return out
}

// forward sends the query unchanged to the upstream DoH server.
func (s *server) forward(ctx context.Context, wire []byte) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.upstream, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", contentType)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMsg))
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		return nil, err
	}
	return m, nil
}

func isSpace(r rune) bool { return r == ' ' || r == '\t' }

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, "; ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	fs := flag.NewFlagSet("mockdoh", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8053", "listen address; queries are served at /dns-query")
	file := fs.String("file", "", "YAML file with a \"records:\" list")
	upstream := fs.String("upstream", "", "DoH URL to forward names the table does not know (default: answer NXDOMAIN)")
	ttl := fs.Uint("ttl", 60, "TTL of answers from the table")
	var recs multiFlag
	fs.Var(&recs, "record", "record \"<name> <type> <value>\" (A, CNAME, TXT, CAA); repeatable")
	_ = fs.Parse(os.Args[1:])

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	table := records{}
	if *file != "" {
		if err := table.loadFile(*file, uint32(*ttl)); err != nil {
			log.Error("load records", "err", err)
			os.Exit(1)
		}
	}
	for _, r := range recs {
		if err := table.add(r, uint32(*ttl)); err != nil {
			log.Error("bad --record", "err", err)
			os.Exit(2)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/dns-query", &server{table: table, upstream: *upstream, client: &http.Client{Timeout: 5 * time.Second}, log: log})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Warn("mockdoh is for development only: it fakes public DNS for the broker's gate",
		"listen", *listen, "names", len(table), "upstream", *upstream)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
