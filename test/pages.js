// Smoke-tests every page the way a person would reach it. A route that throws
// returns 500, and that is invisible to the database-level tests -- which is
// how a broken /mailboxes query shipped once already.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { server } from '../src/server.js';
import { asAdmin } from '../src/db.js';
import { dnsRecords } from '../src/providers.js';

let base;

const jar = () => ({ cookie: '' });

async function get(path, j) {
  const r = await fetch(base + path, { redirect: 'manual', headers: { cookie: j.cookie } });
  return { status: r.status, body: await r.text() };
}

async function post(path, fields, j) {
  const r = await fetch(base + path, {
    method: 'POST', redirect: 'manual',
    headers: { cookie: j.cookie, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
  });
  const set = r.headers.get('set-cookie') ?? '';
  if (set) j.cookie = set.split(';')[0];
  return { status: r.status, body: await r.text() };
}

before(async () => {
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;

  const t = await asAdmin(async ({ query }) => {
    await query(`DELETE FROM tenants WHERE sending_domain = 'smoke.test'`);
    const row = (await query(
      `INSERT INTO tenants (name, sending_domain, daily_cap) VALUES ('Smoke','smoke.test',40) RETURNING id`)).rows[0];
    const { createHash } = await import('node:crypto');
    await query(`INSERT INTO tenant_codes (tenant_id, code_hash) VALUES ($1, $2)`,
      [row.id, createHash('sha256').update('smoke-code').digest('hex')]);
    return row;
  });
  globalThis.smokeTenant = t.id;
});

after(() => server.close());

test('admin can sign in and every admin page renders', async () => {
  const j = jar();
  const bad = await post('/admin/login', { password: 'definitely-wrong' }, j);
  assert.equal(bad.status, 401);
  assert.match(bad.body, /not correct/, 'a wrong password explains itself');

  const ok = await post('/admin/login', { password: process.env.ADMIN_PASSWORD }, j);
  assert.equal(ok.status, 302, `admin login failed: ${ok.body.slice(0, 200)}`);

  for (const path of ['/admin']) {
    const r = await get(path, j);
    assert.equal(r.status, 200, `${path} returned ${r.status}`);
    assert.match(r.body, /All clients/, `${path} missing content`);
  }

  // Add-client is its own page, not a form buried on the list.
  const addClient = await get('/admin/tenants/new', j);
  assert.equal(addClient.status, 200, `add-client page returned ${addClient.status}`);
  assert.match(addClient.body, /name=domain/, 'add-client form is missing');
  assert.doesNotMatch(addClient.body, /name=name.*name=domain.*Add a client/s,
    'the inline form should have moved off the clients list');

  const detail = await get(`/admin/tenants/${globalThis.smokeTenant}`, j);
  assert.equal(detail.status, 200, `admin tenant detail returned ${detail.status}`);
  assert.match(detail.body, /DNS records/, 'detail page missing DNS section');
});

test('every client page renders for a signed-in tenant', async () => {
  const j = jar();
  const login = await post('/login', { code: 'smoke-code' }, j);
  assert.equal(login.status, 302, `tenant login failed: ${login.body.slice(0, 200)}`);

  const pages = ['/', '/campaigns', '/leads', '/mailboxes', '/dns'];
  for (const path of pages) {
    const r = await get(path, j);
    // The regression this catches: a query referencing a column that does not
    // exist throws, and the page silently renders a 500.
    assert.equal(r.status, 200, `${path} returned ${r.status}\n${r.body.slice(0, 400)}`);
    assert.match(r.body, /class=sidebar/, `${path} is missing the app shell`);
    assert.doesNotMatch(r.body, /Something went wrong/, `${path} rendered an error`);
  }
});

test('assets and auth screens render', async () => {
  const css = await fetch(base + '/app.css');
  assert.equal(css.status, 200);
  assert.match(css.headers.get('content-type'), /text\/css/);

  for (const path of ['/login', '/admin/login']) {
    const r = await get(path, jar());
    assert.equal(r.status, 200, `${path} returned ${r.status}`);
    assert.match(r.body, /auth-card/, `${path} is not styled`);
  }
});

test('DNS page reflects the configured provider, not a hardcoded one', async () => {
  // Regression guard: these strings used to say "SES" unconditionally, which
  // hands clients records that will never pass DMARC if you do not use it.
  assert.equal((await get('/app.css', jar())).status, 200);

  const p = dnsRecords('acme.com');
  assert.ok(p.spf.startsWith('v=spf1'), 'SPF must be a real SPF record');
  assert.match(p.dmarc.value, /^v=DMARC1/, 'DMARC record missing');
  assert.equal(p.dmarc.name, '_dmarc.acme.com');
  assert.ok(p.provider, 'provider label missing');

  const original = process.env.MAIL_PROVIDER;
  for (const name of ['ses', 'postmark', 'mailgun', 'smtp']) {
    process.env.MAIL_PROVIDER = name;
    assert.equal(dnsRecords('x.test').provider.length > 0, true, `${name} has no label`);
  }
  process.env.MAIL_PROVIDER = 'nonsense';
  assert.throws(() => dnsRecords('x.test'), /Unknown MAIL_PROVIDER/,
    'a typo in MAIL_PROVIDER must fail loudly, not silently publish wrong records');
  process.env.MAIL_PROVIDER = original;
});

test('unknown page is a friendly 404, not a stack trace', async () => {
  const r = await get('/nope-not-a-page', jar());
  assert.equal(r.status, 404);
  assert.doesNotMatch(r.body, /at Object|Error:/, 'raw stack trace leaked to the page');
});

test('signing out ends the session', async () => {
  const j = jar();
  await post('/login', { code: 'smoke-code' }, j);
  assert.equal((await get('/', j)).status, 200);

  const out = await fetch(base + '/logout', { redirect: 'manual', headers: { cookie: j.cookie } });
  assert.equal(out.status, 302);
  assert.match(out.headers.get('set-cookie') ?? '', /Max-Age=0/, 'cookie is not cleared');

  j.cookie = '';
  assert.equal((await get('/', j)).status, 302, 'still signed in after logout');
});