// Package issuance is the issuance engine: it implements core.Issuer and
// orchestrates everything between a gate-approved request and a stored
// certificate (architecture §7, §8, §9, §10, §11, §20).
//
// The engine does not authorize (front ends run the Gate and pass the
// Decision; Finalize re-checks it for the current source address) and does
// not talk to the network itself: upstream CAs are core.Provider, Route53 is
// core.DNSEngine, admission is core.Scheduler, state is the core stores.
//
// What it decides:
//
//   - whether a request is a new issuance, a renewal, an ARI-qualified
//     renewal or an emergency (architecture §8, from the certificate lineage
//     and the observed check interval);
//   - which provider serves it and when a fallback may be tried;
//   - what `replaces` to send upstream (client-supplied or inferred);
//   - whether an abandoned upstream order can be adopted instead of creating
//     another;
//   - how an order resumes after a restart.
//
// The order state machine, the timing budget and the recovery table are
// documented in docs/issuance.md.
package issuance
