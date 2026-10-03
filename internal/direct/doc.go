// Package direct is the direct certificate cache and API (architecture §3.3,
// §11, §12, §20, §24): GET /cert/{name} and /cert/wildcard/{base} return a
// tar of privkey.pem and fullchain.pem for one identifier.
//
// The broker owns each identifier's RSA key and certificate. Key and chain
// live on disk in numbered generation directories with an atomically
// switched "current" link (Files); SQLite holds only metadata
// (core.DirectEntry). Renewal is request-driven: a fetch of a certificate
// whose renewal is due starts one background job; an identifier nobody
// fetches is never renewed. Every issuance and renewal of one identifier
// runs as a single job, so concurrent misses collapse into one upstream
// issuance; a hit that finds maintenance due while a job runs makes it run
// once more, so its trigger is never lost. docs/direct-api.md is the
// operator and device documentation.
package direct
