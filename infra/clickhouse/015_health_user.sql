-- infra/clickhouse/015_health_user.sql
-- Least-privilege writer for the M13a health poller. Run as CH admin.
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   HEALTH_PW="$CH_HEALTH_PASSWORD" envsubst < 015_health_user.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE USER IF NOT EXISTS ssdf_health IDENTIFIED WITH sha256_password BY '${HEALTH_PW}';
GRANT INSERT ON ssdf.health_metrics TO ssdf_health;
