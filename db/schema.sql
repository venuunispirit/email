-- Tenants are isolated with row-level security, not app-level WHERE clauses.
-- One forgotten WHERE tenant_id = $1 would leak a client's leads across the
-- whole platform; RLS makes that leak impossible to write.

CREATE TABLE tenants (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name              text NOT NULL,
  sending_domain    text NOT NULL UNIQUE,     -- client's own domain, e.g. acme.com
                    -- Unique on purpose: two clients sharing a domain would
                    -- also share its sender reputation, so one bad list would
                    -- blacklist the other.
  daily_cap         int  NOT NULL DEFAULT 50,   -- per tenant, across all mailboxes
  monthly_cap      int,                        -- NULL = unlimited; hard stop
  -- Suspension is the kill switch for an abusive client. It stops sending
  -- immediately and blocks new campaigns, which is the response you need when
  -- complaints are landing on your IP.
  suspended        boolean NOT NULL DEFAULT false,
  suspended_reason text,
  warmup_started_at timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- Access codes live here, hashed, and deliberately outside RLS. Logging in means
-- answering "which tenant is this?" before any tenant context exists, so this is
-- the one lookup that cannot be tenant-scoped. Storing only a sha256 hash keeps
-- a database leak from handing over working sessions for every client.
CREATE TABLE tenant_codes (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  code_hash  text NOT NULL
);

-- Mailboxes are the pacing unit. Cold email is ~20-50/mailbox/day, so scale
-- comes from adding mailboxes, never from turning one mailbox up.
CREATE TABLE mailboxes (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  local_part   text NOT NULL,              -- "john"
  domain       text NOT NULL,              -- usually same as tenants.sending_domain
  display_name text NOT NULL,
  daily_cap    int  NOT NULL DEFAULT 30,
  paused       boolean NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, local_part, domain)
);

CREATE TABLE leads (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email      text NOT NULL,
  first_name text NOT NULL DEFAULT '',
  last_name  text NOT NULL DEFAULT '',
  company    text NOT NULL DEFAULT '',
  -- valid: domain has MX. invalid: bad syntax or no MX, never sent.
  -- risky: role address (info@, sales@), still sendable. unknown: unchecked.
  status     text NOT NULL DEFAULT 'unknown'
             CHECK (status IN ('valid','invalid','risky','unknown')),
  checked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);
CREATE INDEX ON leads (tenant_id, status);


CREATE TABLE campaigns (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name       text NOT NULL,
  subject    text NOT NULL,
  body       text NOT NULL,                -- contains {{first_name}} etc.
  from_email text NOT NULL,
  status     text NOT NULL DEFAULT 'draft'
             CHECK (status IN ('draft','queued','sending','done','paused')),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- The send queue. scheduled_at in the future is how pacing is enforced: the
-- worker only ever claims rows that are due, so back-pressure is automatic.
-- Test sends go to seed mailboxes you control. Deliberately not deliveries:
-- they must never count toward campaign stats or sender volume.
CREATE TABLE test_sends (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  campaign_id uuid NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  email       text NOT NULL,
  in_inbox    boolean,
  checked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE deliveries (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  campaign_id  uuid NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  lead_id      uuid NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
  mailbox_id   uuid NOT NULL REFERENCES mailboxes(id),
  status       text NOT NULL DEFAULT 'queued'
               CHECK (status IN ('queued','sending','sent','failed','skipped')),
  scheduled_at timestamptz NOT NULL DEFAULT now(),
  sent_at      timestamptz,
  error        text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (campaign_id, lead_id)
);
CREATE INDEX ON deliveries (status, scheduled_at) WHERE status = 'queued';

-- Global per-tenant suppression. Honours unsubscribe and hard bounces before
-- the worker ever reaches them, so a complained-about address cannot be mailed
-- twice regardless of which campaign queued it.
CREATE TABLE suppressions (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email      text NOT NULL,
  reason     text NOT NULL CHECK (reason IN ('unsubscribe','bounce','complaint','manual')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);

CREATE TABLE events (
  id         bigserial PRIMARY KEY,
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind       text NOT NULL,                -- sent | bounce | complaint | reply | open
  email      text,
  campaign_id uuid REFERENCES campaigns(id) ON DELETE SET NULL,
  detail     text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON events (tenant_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

-- app.tenant_id is set per-request by src/db.js. Absent value => no rows.
CREATE OR REPLACE FUNCTION current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

ALTER TABLE tenants      ENABLE ROW LEVEL SECURITY;
ALTER TABLE mailboxes    ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads        ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns    ENABLE ROW LEVEL SECURITY;
ALTER TABLE deliveries   ENABLE ROW LEVEL SECURITY;
ALTER TABLE suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE events       ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_sends   ENABLE ROW LEVEL SECURITY;

-- Strict everywhere. Creating a tenant is deliberately NOT a thing the app can
-- do: provisioning runs as the table owner via bin/provision.js. Keeping the
-- exception out of the policy means there is no unauthenticated write path.
CREATE POLICY tenant_isolation ON tenants USING (id = current_tenant());

CREATE POLICY tenant_isolation ON mailboxes    USING (tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON leads        USING (tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON campaigns    USING (tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON deliveries   USING (tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON suppressions USING (tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON events       USING (tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON test_sends   USING (tenant_id = current_tenant());

-- Superusers and table owners bypass RLS by default, which would make this
-- whole scheme untestable. FORCE makes the policy apply to everyone.
ALTER TABLE tenants      FORCE ROW LEVEL SECURITY;
ALTER TABLE mailboxes    FORCE ROW LEVEL SECURITY;
ALTER TABLE leads        FORCE ROW LEVEL SECURITY;
ALTER TABLE campaigns    FORCE ROW LEVEL SECURITY;
ALTER TABLE deliveries   FORCE ROW LEVEL SECURITY;
ALTER TABLE suppressions FORCE ROW LEVEL SECURITY;
ALTER TABLE events       FORCE ROW LEVEL SECURITY;
ALTER TABLE test_sends   FORCE ROW LEVEL SECURITY;
-- Run this file ONCE as a superuser. The app connects as `outreach`, which is
-- deliberately not a superuser: superusers bypass RLS, FORCE or not, so using
-- one would silently disable tenant isolation.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='outreach') THEN
    CREATE ROLE outreach LOGIN PASSWORD 'outreach';
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO outreach;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public TO outreach;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO outreach;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO outreach;
