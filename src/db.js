import crypto from 'node:crypto';
import pg from 'pg';

// postgres://outreach:outreach@localhost:5432/outreach
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

export const sql = (text, params) => pool.query(text, params);

// Every tenant-scoped query goes through here. SET LOCAL is transaction-scoped,
// so a connection returned to the pool can never carry another tenant's id.
export function withTenant(tenantId, fn) {
  // Fail loudly: a missing tenant id would otherwise set an empty app.tenant_id,
  // which RLS reads as "no context" -- and reads succeed, just returning nothing.
  // That is a silent wrong-answer, not an error, and it hides bugs like a
  // mismatched token key.
  if (!tenantId) throw new Error('withTenant requires a tenant id');
  return (async () => {
    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      await c.query('SELECT set_config($1, $2, true)', ['app.tenant_id', tenantId]);
      const out = await fn({ query: (t, p) => c.query(t, p) });
      await c.query('COMMIT');
      return out;
    } catch (e) {
      await c.query('ROLLBACK');
      throw e;
    } finally {
      c.release();
    }
  })();
}

// Only used for tenant login/lookup and background jobs that legitimately span
// tenants. Everything else must go through withTenant.
export const asPlatform = (fn) => fn({ query: (t, p) => pool.query(t, p) });

// Admin pool, for bin/provision.js only. Connects as the table owner so tenant
// creation is possible at all -- the app role cannot insert tenants by design.
const admin = process.env.ADMIN_DATABASE_URL
  ? new pg.Pool({ connectionString: process.env.ADMIN_DATABASE_URL, max: 2 })
  : null;

export const asAdmin = (fn) => {
  if (!admin) throw new Error('ADMIN_DATABASE_URL is required for admin actions');
  return fn({ query: (t, p) => admin.query(t, p) });
};

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

// Shared by bin/provision.js and the admin panel so both onboard a client the
// same way. Runs on the owner connection: the app role may not create tenants.
export async function createTenant({ name, domain, dailyCap = 50, accessCode }) {
  if (!name || !name.trim()) throw new Error('Client name is required');
  domain = String(domain ?? '').toLowerCase().trim();
  if (!DOMAIN_RE.test(domain)) throw new Error(`"${domain}" is not a valid domain`);
  const cap = Number(dailyCap);
  if (!Number.isInteger(cap) || cap < 1 || cap > 100000)
    throw new Error('Daily cap must be a whole number between 1 and 100000');
  // Generated unless the operator supplies one, so a client can never end up
  // with a guessable code.
  const code = accessCode?.trim() || crypto.randomBytes(9).toString('base64url');

  const tenant = await asAdmin(async ({ query }) => {
    if ((await query('SELECT 1 FROM tenants WHERE sending_domain=$1', [domain])).rowCount)
      throw new Error(`${domain} already belongs to a client. Each client needs its own domain so their sender reputation stays separate.`);
    const { rows } = await query(
      `INSERT INTO tenants (name, sending_domain, daily_cap) VALUES ($1,$2,$3) RETURNING id, name, sending_domain`,
      [name.trim(), domain, cap],
    );
    await query(`INSERT INTO tenant_codes (tenant_id, code_hash) VALUES ($1,$2)`, [rows[0].id, sha256(code)]);
    return rows[0];
  });
  return { ...tenant, accessCode: code };
};

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');