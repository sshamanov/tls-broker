// Package dnsproxy is the DNS proxy front end (architecture §3.2, §24): the
// client stays its own ACME client and delegates only the DNS-01 TXT handling
// to the broker.
//
//	POST   /dns/present            {"identifier","value"} -> 201 {"challenge_id","record","value"}
//	POST   /dns/present            {"fqdn","value"}       -> 201 {"challenge_id","record","value"}
//	POST   /dns/cleanup            {"challenge_id"}       -> 204
//	POST   /dns/cleanup            {"fqdn","value"}       -> 200 {"fqdn","value"}
//	DELETE /dns/challenges/{id}                           -> 204
//	GET    /dns/challenges                                -> the caller's active challenges
//
// The fqdn form ("_acme-challenge.<name>", optional trailing dot) is what the
// stock acme.sh dns_acmeproxy and lego httpreq hooks send; it means identifier
// <name>. Its cleanup is idempotent and answers 200 with the value even when
// nothing was left to remove, because those hooks check the body for it. The
// body is read as JSON whatever the Content-Type, so curl -d works.
//
// Present is gated like every mode (core.ModeDNSProxy, including the CAA
// wildcard protection), limited per source address, and returns only once the
// value is publicly visible. Cleanup is accepted only from the address that
// presented. The broker cannot protect upstream CA limits in this mode, so the
// per-source limiter is the only brake. Sweep removes abandoned values.
//
// The Handler never reads the clock or DNS itself; everything goes through the
// core ports. The caller installs httpx.RealIP in front of it.
package dnsproxy
