-- M6c scope B: logging device (ECS observer.hostname) as a typed column so the
-- entity resolver can attribute the on-path firewall from flow provenance
-- instead of the L2-topology heuristic. Idempotent.
ALTER TABLE ssdf.events
  ADD COLUMN IF NOT EXISTS observer_hostname LowCardinality(String) DEFAULT '';
