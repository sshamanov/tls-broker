// Package acmesrv is the downstream ACMEv2 server of the clean ACME proxy
// (architecture §3.1, §6, §7, §24): RFC 8555 for vanilla clients such as
// Certbot and acme.sh, plus RFC 9773 renewal information.
//
// The server is protocol only. It verifies JWS requests, keeps downstream
// accounts (protocol state, never identity), normalizes identifiers, checks
// managed zones, asks the core.Gate for the authorization decision and hands
// admitted work to the core.Issuer. Authorizations are synthetic: one per
// identifier, already valid, with one synthetic valid dns-01 challenge.
//
// URLs are absolute and derived from core.ServerConfig.ExternalURL plus
// PathPrefix, read from the configuration on every request. The handler
// expects the httpx.RealIP middleware in front of it (the source address
// is part of every authorization decision).
//
// docs/acme-proxy.md is the operator and client documentation.
package acmesrv
