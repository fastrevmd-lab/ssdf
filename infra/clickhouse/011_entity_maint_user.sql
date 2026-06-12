-- infra/clickhouse/011_entity_maint_user.sql
-- Edge hardening L4: split mutation rights out of the always-on resolver identity.
-- reconcile_assets (manual/occasional twin cleanup) issues ALTER TABLE ... DELETE
-- mutations; the 5-minute ssdf-entity.timer resolver only ever SELECTs+INSERTs.
-- After this migration:
--   * reconcile runs as the new user: CH_USER=ssdf_entity_maint python -m ssdf_entity.reconcile_assets
--   * the resolver keeps CH_USER=ssdf_entity, which LOSES ALTER DELETE here.
-- Run as CH admin. ClickHouse does NOT expand {name:Type} params inside
-- CREATE USER ... BY '...', so inject the password before applying (never
-- commit the real value):
--   ENTITY_MAINT_PW="$CH_ENTITY_MAINT_PASSWORD" envsubst < 011_entity_maint_user.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE USER IF NOT EXISTS ssdf_entity_maint IDENTIFIED WITH sha256_password BY '${ENTITY_MAINT_PW}';
-- reconcile reads twins, merges edge attrs (INSERT), then mutates-deletes them.
GRANT SELECT, INSERT ON ssdf.entities TO ssdf_entity_maint;
GRANT SELECT, INSERT ON ssdf.entity_edges TO ssdf_entity_maint;
GRANT ALTER DELETE ON ssdf.entities TO ssdf_entity_maint;
GRANT ALTER DELETE ON ssdf.entity_edges TO ssdf_entity_maint;
-- reconcile builds its (segment, ip) -> mac binding map from topo observations.
GRANT SELECT ON ssdf.topo_observations TO ssdf_entity_maint;
-- Tighten the resolver: revoke the mutation grant added by 005_entity_user.sql.
REVOKE ALTER DELETE ON ssdf.entities FROM ssdf_entity;
REVOKE ALTER DELETE ON ssdf.entity_edges FROM ssdf_entity;
