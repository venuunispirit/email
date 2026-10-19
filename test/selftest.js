import { test } from 'node:test';
import assert from 'node:assert/strict';
import { warmupCap, render, runOnce, setTransport, sendTest } from '../src/send.js';
import { classify, domainOf, verifyEmails } from '../src/verify.js';
import { sign, verify } from '../src/token.js';
import { asPlatform, asAdmin, withTenant, createTenant } from '../src/db.js';

process.env.DATABASE_URL ??= 'postgres://outreach:outreach@localhost:5432/outreach';
process.env.APP_SECRET ??= 'test-secret';

async function seed() {
  // Seeding runs as the table owner, mirroring bin/provision.js: the app role
  // cannot create tenants, by design.
  return asAdmin(async ({ query }) => {
    await query('TRUNCATE tenants CASCADE');
    const a = (await query(
      `INSERT INTO tenants (name,sending_domain,daily_cap) VALUES ('A','a.test',50) RETURNING id`)).rows[0];
    const b = (await query(
      `INSERT INTO tenants (name,sending_domain,daily_cap) VALUES ('B','b.test',50) RETURNING id`)).rows[0];
    await query(`INSERT INTO tenant_codes (tenant_id,code_hash) VALUES ($1,'a'),($2,'b')`, [a.id, b.id]);
    await query(
      `INSERT INTO mailboxes (tenant_id,local_part,domain,display_name,daily_cap)
       VALUES ($1,'jane','a.test','Jane',50),($2,'jane','b.test','Jane',50)`, [a.id, b.id]);
    await withTenant(a.id, async ({ query }) =>
      query(`UPDATE tenants SET warmup_started_at = now() - interval '3 days' WHERE id=$1`, [a.id]));
    const ma = (await query(`SELECT id FROM mailboxes WHERE tenant_id=$1`, [a.id])).rows[0];
    const mb = (await query(`SELECT id FROM mailboxes WHERE tenant_id=$1`, [b.id])).rows[0];
    const la = (await query(
      `INSERT INTO leads (tenant_id,email,first_name) VALUES ($1,'x@a.test','Xan') RETURNING id`, [a.id])).rows[0];
    const lb = (await query(
      `INSERT INTO leads (tenant_id,email,first_name) VALUES ($1,'x@b.test','Xan') RETURNING id`, [b.id])).rows[0];
    const ca = (await query(
      `INSERT INTO campaigns (tenant_id,name,subject,body,from_email,status)
       VALUES ($1,'c','Hi {{first_name}}','Hello {{first_name}}','jane@a.test','sending') RETURNING id`, [a.id])).rows[0];
    const cb = (await query(
      `INSERT INTO campaigns (tenant_id,name,subject,body,from_email,status)
       VALUES ($1,'c','Hi {{first_name}}','Hello {{first_name}}','jane@b.test','sending') RETURNING id`, [b.id])).rows[0];
    await query(
      `INSERT INTO deliveries (tenant_id,campaign_id,lead_id,mailbox_id) VALUES ($1,$2,$3,$4)`,
      [a.id, ca.id, la.id, ma.id]);
    await query(
      `INSERT INTO deliveries (tenant_id,campaign_id,lead_id,mailbox_id) VALUES ($1,$2,$3,$4)`,
      [b.id, cb.id, lb.id, mb.id]);
    return { a, b, ma, mb, ca, cb };
  });
}

test('warmupCap doubles daily and never exceeds tenant cap', () => {
  const d = (n) => new Date(Date.now() - n * 86_400_000).toISOString();
  assert.equal(warmupCap({ daily_cap: 50, warmup_started_at: null }), 5, 'no warmup start = 5/day');
  assert.equal(warmupCap({ daily_cap: 50, warmup_started_at: d(0) }), 5);
  assert.equal(warmupCap({ daily_cap: 50, warmup_started_at: d(1) }), 10);
  assert.equal(warmupCap({ daily_cap: 50, warmup_started_at: d(3) }), 40);
  assert.equal(warmupCap({ daily_cap: 50, warmup_started_at: d(30) }), 50, 'capped at tenant cap');
  assert.equal(warmupCap({ daily_cap: 1, warmup_started_at: d(30) }), 1, 'ramp floor never overrides a lower cap');
  // Before warm-up has started, the same clamp must apply: this early return
  // used to hand an unwarmed tenant 5 regardless of a cap of 3.
  assert.equal(warmupCap({ daily_cap: 3, warmup_started_at: null }), 3);
  assert.equal(warmupCap({ daily_cap: 50, warmup_started_at: null }), 5);
});

test('render substitutes and leaves unknown vars empty', () => {
  assert.equal(render('Hi {{first_name}} {{nope}}', { first_name: 'Ana' }), 'Hi Ana ');
});

test('token survives round-trip and rejects tampering/expiry', () => {
  const tok = sign({ tid: 't1', e: 'a@b.c' });
  assert.equal(verify(tok).tid, 't1');
  assert.equal(verify(tok.slice(0, -1) + 'X'), null, 'tampered signature rejected');
  assert.equal(verify(tok.split('.')[0]), null, 'signature-less token rejected');
  assert.equal(verify('garbage'), null, 'malformed token does not throw');
  assert.equal(verify(sign({ tid: 't1' }, -1)), null, 'expired rejected');
});

test('RLS: tenant A cannot read tenant B leads', async () => {
  const { a, b } = await seed();
  const seenByA = await withTenant(a.id, async ({ query }) =>
    (await query('SELECT email FROM leads')).rows.map((r) => r.email));
  assert.deepEqual(seenByA, ['x@a.test']);
  const seenByB = await withTenant(b.id, async ({ query }) =>
    (await query('SELECT email FROM leads')).rows.map((r) => r.email));
  assert.deepEqual(seenByB, ['x@b.test']);
});

test('RLS: no tenant context means no rows', async () => {
  await seed();
  const n = await asPlatform(async ({ query }) => (await query('SELECT count(*)::int n FROM leads')).rows[0].n);
  assert.equal(n, 0, 'a connection without app.tenant_id sees nothing');
});

test('worker sends each tenant its own lead only, with unsubscribe headers', async () => {
  const { a, b } = await seed();
  const sent = [];
  setTransport({ async sendMail(m) { sent.push(m); return { messageId: 'x' }; } });
  const n = await runOnce();
  assert.equal(n, 2);
  assert.equal(sent.length, 2);
  assert.deepEqual(sent.map((m) => m.to).sort(), ['x@a.test', 'x@b.test']);
  for (const m of sent) {
    // Assert the headers nodemailer will actually emit, not just the options
    // object: listUnsubscribe* are not real nodemailer options and silently
    // dropped there, which is invisible until a mailbox rejects the campaign.
    assert.ok(m.headers['List-Unsubscribe']?.includes('/u/'), 'List-Unsubscribe header present');
    assert.equal(m.headers['List-Unsubscribe-Post'], 'List-Unsubscribe=One-Click');
    assert.match(m.subject, /Hi Xan/, 'template rendered into subject');
  }
  // Each lead must be sent from its own tenant's mailbox, never crossed.
  const byTo = Object.fromEntries(sent.map((m) => [m.to, m.from.address]));
  assert.equal(byTo['x@a.test'], 'jane@a.test');
  assert.equal(byTo['x@b.test'], 'jane@b.test');
});

test('suppressed addresses are never sent', async () => {
  const { a } = await seed();
  await withTenant(a.id, async ({ query }) => {
    await query(`INSERT INTO suppressions (tenant_id,email,reason) VALUES ($1,'x@a.test','unsubscribe')`, [a.id]);
  });
  const sent = [];
  setTransport({ async sendMail(m) { sent.push(m); return { messageId: 'x' }; } });
  await runOnce();
  assert.ok(!sent.some((m) => m.to === 'x@a.test'), 'suppressed lead skipped');
  assert.ok(sent.some((m) => m.to === 'x@b.test'), 'other tenant unaffected');
});

test('queueing spreads a campaign across one day, not weeks', async () => {
  const { a } = await seed();
  await withTenant(a.id, async ({ query }) => {
    // 1000 leads on purpose: a fixed 120s-per-lead step (the old formula) would
    // push the last send to ~33 hours out. Smaller lists would not catch it.
    await query(
      `INSERT INTO leads (tenant_id,email)
       SELECT $1, 'bulk' || n || '@a.test' FROM generate_series(1,1000) n`, [a.id]);
    const n = (await query('SELECT count(*)::int n FROM leads', [])).rows[0].n;
    const step = Math.floor(86400 / n);
    assert.equal(step, 86, 'step is derived from list size, not fixed');
    assert.ok((n - 1) * step <= 86400, 'last send must land within the day');

    // The bug it guards: a fixed step per lead.
    assert.ok((n - 1) * 120 > 86400, 'a fixed 120s step would blow past a day');
  });
});

test('withTenant refuses a missing tenant id instead of silently reading nothing', async () => {
  // A bad token key once turned into withTenant(undefined) here, which RLS
  // treats as "no context": no error, just zero rows. That hides bugs.
  assert.throws(() => withTenant(undefined, async () => {}), /requires a tenant id/);
  assert.throws(() => withTenant('', async () => {}), /requires a tenant id/);
});

test('admin session and tenant session are not interchangeable', async () => {
  // Both cookies are HMAC-signed with the same secret, so the only thing keeping
  // a tenant out of /admin is that their token carries no `adm` claim.
  const tenantCookie = sign({ tid: '11111111-1111-1111-1111-111111111111' });
  const adminCookie = sign({ adm: true });
  assert.equal(verify(tenantCookie).adm, undefined, 'tenant token grants nothing');
  assert.equal(verify(adminCookie).tid, undefined, 'admin token is not a tenant id');
  assert.notEqual(tenantCookie, adminCookie);
});

test('createTenant validates input and generates a code when none is given', async () => {
  await seed();
  await assert.rejects(() => createTenant({ name: 'X', domain: 'not a domain' }), /not a valid domain/);
  await assert.rejects(() => createTenant({ name: '', domain: 'x.test' }), /name is required/);
  await assert.rejects(() => createTenant({ name: 'X', domain: 'x.test', dailyCap: 0 }), /between 1 and/);

  // Sharing a domain would share sender reputation across two clients.
  await assert.rejects(
    () => createTenant({ name: 'Copycat', domain: 'a.test' }), /already belongs to a client/);

  const t = await createTenant({ name: 'New Co', domain: 'New.Test' });
  assert.equal(t.sending_domain, 'new.test', 'domain is normalised to lowercase');
  assert.ok(t.accessCode && t.accessCode.length >= 12, 'code is generated, not blank');
  const dup = await createTenant({ name: 'Another', domain: 'other.test' });
  assert.notEqual(dup.accessCode, t.accessCode, 'each client gets a distinct code');

  // The stored value must be a hash, never the code itself.
  const row = await asAdmin(async ({ query }) =>
    (await query('SELECT code_hash FROM tenant_codes WHERE tenant_id=$1', [t.id])).rows[0]);
  assert.notEqual(row.code_hash, t.accessCode, 'code is not stored in plaintext');
  assert.match(row.code_hash, /^[0-9a-f]{64}$/, 'stored as sha256 hex');
});

test('classify separates syntax errors, role addresses and normal leads', () => {
  assert.equal(classify('bob@acme.test'), 'unknown');
  assert.equal(classify('info@acme.test'), 'risky');
  assert.equal(classify('sales@acme.test'), 'risky');
  assert.equal(classify('not-an-email'), 'invalid');
  assert.equal(classify('a@b'), 'invalid', 'no TLD is invalid');
  assert.equal(classify('two@at@acme.test'), 'invalid');
  assert.equal(classify('sp ace@acme.test'), 'invalid');
  assert.equal(domainOf('Bob.Smith@ACME.test'), 'acme.test', 'domain normalised');
});

test('verifyEmails marks domains with no MX as invalid and keeps role addresses sendable', async () => {
  const rows = await verifyEmails([
    'bob@gmail.com',          // real MX
    'info@acme-roles.test',    // no MX, but a role address either way
    'bob@definitely-not-real-9x.test',
    'garbage',
  ]);
  const by = Object.fromEntries(rows);
  assert.equal(by['bob@gmail.com'], 'valid');
  assert.equal(by['garbage'], 'invalid', 'malformed is rejected on syntax alone');
  assert.equal(by['bob@definitely-not-real-9x.test'], 'invalid', 'no MX record');
  // Role address on a dead domain is still invalid: deliverability wins.
  assert.equal(by['info@acme-roles.test'], 'invalid');
});

test('worker never sends a lead marked invalid', async () => {
  const { a } = await seed();
  await withTenant(a.id, async ({ query }) => {
    await query(`UPDATE leads SET status='invalid' WHERE tenant_id=$1`, [a.id]);
  });
  const sent = [];
  setTransport({ async sendMail(m) { sent.push(m); return { messageId: 'x' }; } });
  await runOnce();
  assert.ok(!sent.some((m) => m.to.endsWith('@a.test')), 'invalid lead skipped');
  assert.ok(sent.some((m) => m.to.endsWith('@b.test')), 'other tenant unaffected');

  // It stays queued rather than vanishing, so a wrongly-flagged lead is recoverable.
  const queued = await withTenant(a.id, async ({ query }) =>
    (await query(`SELECT count(*)::int n FROM deliveries WHERE status='queued'`)).rows[0].n);
  assert.equal(queued, 1, 'invalid lead remains queued, not deleted');
});

test('test sends bypass caps and never touch delivery stats', async () => {
  const { a, ca } = await seed();
  const sent = [];
  setTransport({ async sendMail(m) { sent.push(m); return { messageId: 'x' }; } });
  await sendTest({
    tenantId: a.id,
    campaign: { ...ca, subject: 'Hi {{first_name}}', body: 'Hello {{first_name}}',
                from_email: 'jane@a.test', display_name: 'Jane', domain: 'a.test' },
    to: 'seed@gmail.com',
  });
  assert.equal(sent.length, 1, 'one test send');
  assert.equal(sent[0].to, 'seed@gmail.com');
  assert.ok(sent[0].headers['List-Unsubscribe'].includes('/u/'), 'test send also carries one-click');

  const counts = await withTenant(a.id, async ({ query }) => ({
    tests: (await query('SELECT count(*)::int n FROM test_sends')).rows[0].n,
    deliveries: (await query('SELECT count(*)::int n FROM deliveries')).rows[0].n,
    events: (await query('SELECT count(*)::int n FROM events')).rows[0].n,
  }));
  assert.equal(counts.tests, 1, 'recorded for the client to check');
  assert.equal(counts.events, 0, 'a test send is not a campaign event');
  assert.equal(counts.deliveries, 1, 'no extra delivery row created');
});

test('tenant daily cap is a tenant-wide ceiling, not a per-mailbox one', async () => {
  // Regression: the cap used to be applied to each mailbox independently, so a
  // tenant with 3 mailboxes sent 3x the limit their dashboard advertised.
  const { a } = await seed();
  await withTenant(a.id, async ({ query }) => {
    await query(`UPDATE tenants SET daily_cap=3, warmup_started_at=now() WHERE id=$1`, [a.id]);
    await query(`UPDATE mailboxes SET paused=false WHERE tenant_id=$1`, [a.id]);
    // Three mailboxes, each with its own leads. Deliveries are unique on
    // (campaign_id, lead_id), so reusing a lead across mailboxes would silently
    // collapse the rows and make the cap look like it was working.
    for (const lp of ['bob', 'cat']) {
      await query(
        `INSERT INTO mailboxes (tenant_id,local_part,domain,display_name,daily_cap)
         VALUES ($1,$2,'a.test',$2,50)`, [a.id, lp]);
    }
    const c = (await query('SELECT id FROM campaigns WHERE tenant_id=$1', [a.id])).rows[0];
    const mbs = (await query('SELECT id FROM mailboxes WHERE tenant_id=$1 ORDER BY created_at', [a.id])).rows;
    for (const mb of mbs) {
      const lp = (await query('SELECT local_part FROM mailboxes WHERE id=$1', [mb.id])).rows[0].local_part;
      const { rows } = await query(
        `INSERT INTO leads (tenant_id,email,status)
         SELECT $1, $2 || n || '@a.test', 'valid' FROM generate_series(1,2) n
         RETURNING id`, [a.id, lp + '-']);
      for (const l of rows) {
        await query(
          `INSERT INTO deliveries (tenant_id,campaign_id,lead_id,mailbox_id)
           VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, [a.id, c.id, l.id, mb.id]);
      }
    }
    const n = (await query('SELECT count(*)::int n FROM deliveries WHERE status=\'queued\'', [])).rows[0].n;
    assert.ok(n > 3, `need more deliverable rows than the cap, got ${n}`);
  });

  const sent = [];
  setTransport({ async sendMail(m) { sent.push(m); return { messageId: 'x' }; } });
  await runOnce();
  const mine = sent.filter((m) => m.to.endsWith('@a.test'));
  assert.equal(mine.length, 3,
    `tenant cap of 3 must hold across all its mailboxes, sent ${mine.length}`);
  assert.equal(new Set(mine.map((m) => m.from.address)).size, 3,
    'work should have spread across the three mailboxes');
});

test('monthly cap stops sending even when daily budget remains', async () => {
  const { a } = await seed();
  await withTenant(a.id, async ({ query }) => {
    await query(`UPDATE tenants SET daily_cap=50, monthly_cap=1, warmup_started_at=now() WHERE id=$1`, [a.id]);
    await query(`INSERT INTO leads (tenant_id,email) VALUES ($1,'m1@a.test'),($1,'m2@a.test'),($1,'m3@a.test')`, [a.id]);
    const c = (await query('SELECT id FROM campaigns WHERE tenant_id=$1', [a.id])).rows[0];
    const leads = (await query('SELECT id FROM leads WHERE tenant_id=$1', [a.id])).rows;
    const mb = (await query('SELECT id FROM mailboxes WHERE tenant_id=$1', [a.id])).rows[0];
    for (const l of leads) {
      await query(
        `INSERT INTO deliveries (tenant_id,campaign_id,lead_id,mailbox_id) VALUES ($1,$2,$3,$4)
         ON CONFLICT DO NOTHING`, [a.id, c.id, l.id, mb.id]);
    }
  });
  const sent = [];
  setTransport({ async sendMail(m) { sent.push(m); return { messageId: 'x' }; } });
  await runOnce();
  assert.equal(sent.filter((m) => m.to.endsWith('@a.test')).length, 1,
    'monthly cap of 1 allows exactly one send even though daily cap is 50');
});

test('a suspended tenant sends nothing', async () => {
  const { a, b } = await seed();
  await withTenant(a.id, async ({ query }) =>
    query(`UPDATE tenants SET suspended=true, suspended_reason='abuse' WHERE id=$1`, [a.id]));
  const sent = [];
  setTransport({ async sendMail(m) { sent.push(m); return { messageId: 'x' }; } });
  const n = await runOnce();
  assert.ok(!sent.some((m) => m.to.endsWith('@a.test')), 'suspended tenant sent nothing');
  assert.ok(sent.some((m) => m.to.endsWith('@b.test')), 'other tenants keep sending');
  assert.ok(n > 0, 'worker still processes other tenants');

  // Resuming restores service.
  await withTenant(a.id, async ({ query }) =>
    query(`UPDATE tenants SET suspended=false WHERE id=$1`, [a.id]));
  sent.length = 0;
  await runOnce();
  assert.ok(sent.some((m) => m.to.endsWith('@a.test')), 'sending resumes after lift');
});

test('mailbox daily cap stops the worker but leaves work queued', async () => {
  const { a } = await seed();
  // Note: updating a tenant via asPlatform would silently match 0 rows under
  // RLS. Everything tenant-scoped must go through withTenant.
  await withTenant(a.id, async ({ query }) => {
    await query(`UPDATE tenants SET daily_cap=1, warmup_started_at=now() WHERE id=$1`, [a.id]);
    await query(`INSERT INTO leads (tenant_id,email) VALUES ($1,'y@a.test'),($1,'z@a.test')`, [a.id]);
    const c = (await query(`SELECT id FROM campaigns WHERE tenant_id=$1`, [a.id])).rows[0];
    const leads = (await query(`SELECT id FROM leads WHERE tenant_id=$1`, [a.id])).rows;
    const mb = (await query(`SELECT id FROM mailboxes WHERE tenant_id=$1`, [a.id])).rows[0];
    for (const l of leads) {
      await query(
        `INSERT INTO deliveries (tenant_id,campaign_id,lead_id,mailbox_id) VALUES ($1,$2,$3,$4)
         ON CONFLICT DO NOTHING`, [a.id, c.id, l.id, mb.id]);
    }
  });
  const sent = [];
  setTransport({ async sendMail(m) { sent.push(m); return { messageId: 'x' }; } });
  await runOnce();
  // Tenant B still sends freely; only A is capped, so count only A's recipients.
  assert.equal(sent.filter((m) => m.to.endsWith('@a.test')).length, 1, 'only one send on a cap of 1');
  assert.equal(sent.filter((m) => m.to.endsWith('@b.test')).length, 1, 'B unaffected by A\'s cap');
  const queued = await withTenant(a.id, async ({ query }) =>
    (await query(`SELECT count(*)::int n FROM deliveries WHERE status='queued'`)).rows[0].n);
  assert.equal(queued, 2, 'the rest stay queued for tomorrow');
});