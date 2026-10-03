-- Certificates record who obtained them: the requesting address and the grant
-- that authorized the order (0 when the names resolved to the requester).
-- Orders are pruned, so the certificate keeps its own copy. Certificates whose
-- order still exists are backfilled from it; older ones stay unknown ('', 0).
ALTER TABLE certificates ADD COLUMN source_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE certificates ADD COLUMN grant_id INTEGER NOT NULL DEFAULT 0;
UPDATE certificates
   SET source_ip = (SELECT o.source_ip FROM orders o WHERE o.id = certificates.order_id),
       grant_id  = (SELECT o.grant_id  FROM orders o WHERE o.id = certificates.order_id)
 WHERE EXISTS (SELECT 1 FROM orders o WHERE o.id = certificates.order_id);
