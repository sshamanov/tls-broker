// Package core is the vocabulary every other package shares: domain types,
// the ports (interfaces) between subsystems, the store interfaces, error
// types, ACME problem documents and the configuration view.
//
// Packages depend on core and on names, not on each other. core itself
// contains no I/O and no policy beyond small pure helpers whose formula is
// fixed by architecture.md (emergency window, lineage interval, ARI
// certificate identifier).
//
// # Conventions used by every contract in this package
//
// Time. Nothing below core reads the wall clock. Stores never look at the
// time themselves: every time-dependent store method takes the current time
// as an argument and compares it with stored values exactly as documented.
// Everything else takes time from a Clock. All stored times are UTC with at
// least millisecond precision; a zero time.Time means "not set".
//
// Not found. A lookup of something that does not exist returns an error that
// matches ErrNotFound (errors.Is) and a nil/zero value. Lists return an empty
// slice and a nil error.
//
// Conflicts. A write that would break uniqueness, or that finds the row in a
// state the method does not allow, returns an error matching ErrConflict and
// changes nothing.
//
// Atomicity. Each store method is one transaction: it either happens entirely
// or not at all, and is durable when it returns. Methods documented as
// "atomically" touching several entities do so in that single transaction.
// There is no cross-method transaction API; flows are built so that a crash
// between two methods leaves a state that recovery understands
// (architecture §20).
//
// Ownership. Pointers returned by stores are fresh copies; callers may modify
// them freely and nothing is saved until a store method is called. Stores do
// not retain pointers passed to them.
//
// Identifiers. Orders, certificates, ACME accounts and challenges have
// string IDs chosen by the caller with NewID. Users and grants have int64 IDs
// assigned by the store. DNS names are always in the normalized form of
// package names.
//
// Contexts. Every method that can block takes a context and returns promptly
// with ctx.Err() (possibly wrapped) once it is done.
//
// Concurrency. Every implementation of every interface here is safe for
// concurrent use.
package core
