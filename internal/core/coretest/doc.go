// Package coretest provides fakes for the ports of package core, for use in
// tests of every other package:
//
//	FakeClock        core.Clock        manual time, deterministic timers
//	FakeResolver     core.Resolver     A/CNAME/TXT/CAA tables, injectable failures
//	FakeCA           core.Provider     a small real CA: root, intermediate, signs CSRs
//	FakeDNSEngine    core.DNSEngine    in-memory TXT values, optionally visible in a FakeResolver
//	FakeDirectory    core.Directory    username/password table
//	FakeAuditor      core.Auditor      records events
//	FakeGate         core.Gate         scripted decisions
//	FakeScheduler    core.Scheduler    admits everything unless told otherwise, records settlement
//	FakeProviders    core.Providers    fixed list of providers
//	FakeConfig       core.ConfigSource settable configuration
//	FakeSecrets      core.SecretStore  in-memory secrets
//
// plus helpers to generate keys and CSRs. Stores have no fakes: tests use the
// real SQLite store on a t.TempDir() file.
//
// All fakes are safe for concurrent use and need no cleanup.
package coretest
