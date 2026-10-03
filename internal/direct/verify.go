package direct

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"tls-broker/internal/core"
)

// Verify is the startup check of architecture §20, run once before the API
// serves requests. For every cache entry it chooses the active generation:
//
//  1. the generation the "current" link points at, if it is complete and
//     consistent (it is newer than the entry when the broker stopped between
//     switching the link and saving the entry);
//  2. otherwise the generation the entry references, if complete;
//  3. otherwise the newest complete generation on disk.
//
// "Complete" means both files exist, the key is PKCS#1 RSA, it matches the
// leaf, the leaf names the identifier and the chain parses and links up.
// When the choice differs from the entry, the entry is repaired (generation,
// validity, certificate ID and provider when the certificate store knows the
// leaf, renewal schedule reset) and the "current" link is pointed at it.
// When nothing usable is left the entry is reset to "no certificate" and the
// next fetch issues a new one. Every repair is logged and audited
// (admin-only error event). Leftover temporary files are removed and old
// generations pruned. The expiry gauge is seeded for every entry.
//
// The error is non-nil only when the entries could not be listed; per-entry
// failures are logged and the remaining entries are still checked.
func (s *Service) Verify(ctx context.Context) error {
	list, err := s.entries.List(ctx)
	if err != nil {
		return fmt.Errorf("direct: listing cache entries: %w", err)
	}
	cfg := s.cfg.Current()
	f := s.Files()
	seen := map[string]bool{}
	for i := range list {
		e := &list[i]
		seen[e.Identifier] = true
		if err := s.verifyEntry(ctx, cfg, f, e); err != nil {
			s.log.Error("direct: verifying cache entry failed", "identifier", e.Identifier, "err", err)
		}
	}
	// The files are the truth: a generation written while the entry could
	// not be saved (or a restored certs directory without its database) is
	// adopted instead of being re-issued at the next fetch.
	ids, err := f.Identifiers()
	if err != nil {
		s.log.Error("direct: listing cache directories failed", "root", f.Root(), "err", err)
		return nil
	}
	now := s.clock.Now()
	for _, id := range ids {
		if seen[id] {
			continue
		}
		e := &core.DirectEntry{Identifier: id, CreatedAt: now}
		if err := s.verifyEntry(ctx, cfg, f, e); err != nil {
			s.log.Error("direct: adopting cache directory failed", "identifier", id, "err", err)
		}
	}
	return nil
}

func (s *Service) verifyEntry(ctx context.Context, cfg *core.Config, f *Files, e *core.DirectEntry) error {
	id := e.Identifier
	now := s.clock.Now()
	var chosen *Generation
	cur, curErr := f.Current(id)
	if curErr == nil {
		chosen, _ = f.Load(id, cur)
	}
	if chosen == nil && e.Generation > 0 {
		chosen, _ = f.Load(id, e.Generation)
	}
	if chosen == nil {
		g, err := f.Newest(id)
		if err == nil {
			chosen = g
		}
	}

	var repairs []string
	switch {
	case chosen == nil && e.Generation == 0:
		// Never issued (an entry that only records failures): nothing to do.
		return nil
	case chosen == nil:
		repairs = append(repairs, fmt.Sprintf("generation %d is missing or damaged and no complete generation is on disk; the next fetch issues a new certificate", e.Generation))
		e.Generation, e.CertificateID = 0, ""
		e.NotBefore, e.NotAfter, e.RenewAt, e.NextARICheckAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	default:
		leaf := chosen.Leaf()
		if chosen.Number != e.Generation {
			if e.Generation == 0 {
				repairs = append(repairs, fmt.Sprintf("entry referenced no generation; adopted generation %d", chosen.Number))
			} else {
				repairs = append(repairs, fmt.Sprintf("entry referenced generation %d; adopted generation %d", e.Generation, chosen.Number))
			}
			e.Generation = chosen.Number
			e.CertificateID = ""
			e.RenewAt, e.NextARICheckAt = fractionRenewAt(cfg, leaf), time.Time{}
			s.lookupCertificate(ctx, e, chosen)
		}
		if !e.NotBefore.Equal(leaf.NotBefore) || !e.NotAfter.Equal(leaf.NotAfter) {
			if len(repairs) == 0 {
				repairs = append(repairs, "validity dates corrected from the certificate on disk")
			}
			e.NotBefore, e.NotAfter = leaf.NotBefore, leaf.NotAfter
		}
		if curErr != nil || cur != chosen.Number {
			if err := f.Activate(id, chosen.Number); err != nil {
				return fmt.Errorf("pointing current at generation %d: %w", chosen.Number, err)
			}
			repairs = append(repairs, fmt.Sprintf("current link set to generation %d", chosen.Number))
		}
		s.mu.Lock()
		s.gens[id] = chosen
		s.mu.Unlock()
		s.metrics.CertExpiry(id, leaf.NotAfter)
		if !now.Before(leaf.NotAfter) {
			s.log.Info("direct: cached certificate has expired; the next fetch issues a new one",
				"identifier", id, "not_after", leaf.NotAfter)
		}
		if err := f.Prune(id); err != nil {
			s.log.Warn("direct: pruning generations failed", "identifier", id, "err", err)
		}
	}
	if len(repairs) == 0 {
		return nil
	}
	e.UpdatedAt = now
	if err := s.entries.Put(ctx, e); err != nil {
		return fmt.Errorf("saving repaired entry: %w", err)
	}
	detail := "direct cache repaired: " + strings.Join(repairs, "; ")
	s.log.Warn("direct: "+detail, "identifier", id)
	s.audit(ctx, core.AuditEvent{Type: core.AuditError, Mode: core.ModeDirect, Names: []string{id},
		Visibility: core.AuditVisibilityAdmin, Result: core.AuditResultOK, Detail: detail})
	return nil
}

// lookupCertificate fills CertificateID and Provider of a repaired entry from
// the certificate store, matched by the leaf's ARI identifier.
func (s *Service) lookupCertificate(ctx context.Context, e *core.DirectEntry, g *Generation) {
	if s.certs == nil {
		return
	}
	ariID, err := core.ARICertID(g.Leaf())
	if err != nil {
		return
	}
	c, err := s.certs.GetByARICertID(ctx, ariID)
	if err != nil {
		if !errors.Is(err, core.ErrNotFound) {
			s.log.Warn("direct: certificate lookup failed", "identifier", e.Identifier, "err", err)
		}
		return
	}
	e.CertificateID, e.Provider = c.ID, c.Provider
}
