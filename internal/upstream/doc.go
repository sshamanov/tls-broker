// Package upstream talks to the public ACME certificate authorities
// (architecture §9): ACMEProvider implements core.Provider for any RFC 8555
// CA and Registry implements core.Providers from the configuration.
//
// The adapter is built on the low-level acme/api package of lego. lego does
// not expose response headers on errors and silently retries a newOrder
// without `replaces` when the CA answers alreadyReplaced; both are handled by
// a per-call capture installed in the HTTP transport (see transport.go), so
// Retry-After is available for every answer and an alreadyReplaced newOrder
// never turns into a second order.
//
// Every error a Provider method returns is either the context's error or a
// *core.ProviderError classified as in docs/providers.md ("Error classes").
package upstream
