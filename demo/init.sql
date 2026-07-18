CREATE SCHEMA IF NOT EXISTS analytics;

CREATE TABLE IF NOT EXISTS analytics.orders (
    order_id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    net_amount NUMERIC(18, 2) NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    channel TEXT NOT NULL,
    country TEXT NOT NULL,
    customer_email TEXT NOT NULL
);

TRUNCATE analytics.orders RESTART IDENTITY;
INSERT INTO analytics.orders (
    tenant_id, net_amount, completed_at, status, channel, country, customer_email
) VALUES
    ('tenant-a', 1250000, '2026-06-03T10:00:00Z', 'completed', 'organic', 'VN', 'a1@example.test'),
    ('tenant-a', 750000,  '2026-06-09T11:00:00Z', 'completed', 'paid',    'VN', 'a2@example.test'),
    ('tenant-a', 300000,  '2026-06-10T11:00:00Z', 'pending',   'paid',    'VN', 'a3@example.test'),
    ('tenant-b', 9900000, '2026-06-12T12:00:00Z', 'completed', 'partner', 'SG', 'b1@example.test');

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'queryattest_reader') THEN
        CREATE ROLE queryattest_reader LOGIN PASSWORD 'queryattest_reader';
    END IF;
END
$$;

ALTER ROLE queryattest_reader
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE queryattest_reader SET default_transaction_read_only = on;
REVOKE TEMPORARY ON DATABASE queryattest FROM PUBLIC;
GRANT CONNECT ON DATABASE queryattest TO queryattest_reader;
GRANT USAGE ON SCHEMA analytics TO queryattest_reader;
GRANT SELECT ON analytics.orders TO queryattest_reader;
REVOKE ALL ON analytics.orders FROM PUBLIC;

ALTER TABLE analytics.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics.orders FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON analytics.orders;
CREATE POLICY tenant_isolation ON analytics.orders
    FOR SELECT
    TO queryattest_reader
    USING (tenant_id = current_setting('app.tenant_id', true));
