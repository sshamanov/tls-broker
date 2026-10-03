// Command r53mock is test infrastructure for `make compat` (test/compat):
// it lets the real broker binary run DNS-01 against Pebble without AWS.
//
// It serves the four Route53 REST-XML operations the broker's DNS-01 engine
// uses (ChangeResourceRecordSets, GetChange, ListResourceRecordSets,
// GetHostedZone) over the in-memory dns01.FakeRoute53, mirrors every TXT
// change to pebble-challtestsrv (the DNS server Pebble validates against),
// and answers DoH TXT queries at /dns-query from the same records so the
// broker's propagation check sees them (chain it behind mockdoh with
// --upstream). Point the broker at it with
// AWS_ENDPOINT_URL_ROUTE_53=http://127.0.0.1:<port> and dummy AWS keys.
//
//	r53mock --listen 127.0.0.1:18454 --zone compat.test=ZCOMPAT \
//	  --challtestsrv http://127.0.0.1:8055
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tls-broker/internal/dns01"
	"tls-broker/test/challtest"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	fs := flag.NewFlagSet("r53mock", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:18454", "listen address")
	chall := fs.String("challtestsrv", "", "challtestsrv management URL to mirror TXT records to (empty: no mirroring)")
	var zones multiFlag
	fs.Var(&zones, "zone", "hosted zone \"<name>=<id>\"; repeatable")
	_ = fs.Parse(os.Args[1:])
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	fake := dns01.NewFakeRoute53(nil)
	for _, z := range zones {
		name, id, ok := strings.Cut(z, "=")
		if !ok || name == "" || id == "" {
			log.Error("bad --zone, want name=id", "zone", z)
			os.Exit(2)
		}
		fake.AddZone(id, name)
	}
	var api dns01.Route53API = fake
	if *chall != "" {
		api = &challtest.Route53{FakeRoute53: fake, Chall: challtest.NewClient(*chall)}
	}
	s := &server{api: api, fake: fake, log: log}
	srv := &http.Server{Addr: *listen, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("r53mock listening", "listen", *listen, "zones", zones.String(), "challtestsrv", *chall)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
