import http from 'node:http';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { withTenant, asPlatform, asAdmin, createTenant } from './db.js';
import { sign, verify } from './token.js';
import { runForever, sendTest } from './send.js';
import { verifyEmails } from './verify.js';
import { dnsRecords, provider } from './providers.js';

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s ?? '');

const PORT = Number(process.env.PORT || 3000);
const BOUNCE_SECRET = process.env.BOUNCE_WEBHOOK_SECRET;
// Single shared password for the agency operator. Deliberately not a table:
// there is one admin, and a hardcoded credential is not worth a join table.
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
// Queued mail is spread over a day so a campaign never lands as one burst,
// which is indistinguishable from a spam run.
const DAY_SECONDS = Number(process.env.SPREAD_SECONDS || 86400);

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const TENANT_NAV = [
  ['/', 'Dashboard'],
  ['/campaigns', 'Campaigns'],
  ['/leads', 'Leads'],
  ['/mailboxes', 'Mailboxes'],
  ['/dns', 'DNS setup'],
];

const ADMIN_NAV = [
  ['/admin', 'All clients'],
];

const shell = ({ title, text = '', action = '', active, nav, brand, body, footer }) => `<!doctype html>
<html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(title)} &middot; ${esc(brand[1])}</title>
<link rel=stylesheet href=/app.css></head>
<body><div class=shell>
<aside class=sidebar>
  <div class=brand><span class=brand-dot>${esc(brand[0])}</span>${esc(brand[1])}</div>
  <nav class=nav>
    ${nav.map(([href, label]) => `<a href="${href}"${href === active ? ' class=on' : ''}>${esc(label)}</a>`).join('')}
  </nav>
  <div class=sidebar-foot>${footer}</div>
</aside>
<main class=main>
  <div class=page-head>
    <div><h1>${esc(title)}</h1>${text ? `<p class=sub>${text}</p>` : ''}</div>
    ${action}
  </div>
  ${body}
</main></div></body></html>`;

// Wraps content in the sidebar shell and marks the active nav item.
const page = (title, body, opts = {}) => {
  const {
    nav = TENANT_NAV, active = '/', brand = ['O', 'Outreach'],
    text = '', action = '', foot = '',
  } = opts;
  return shell({
    title, text, action, active, nav, brand, body,
    footer: foot || `<a href="/logout" style="color:#9ca3af;font-size:.86rem">Sign out</a>`,
  });
};

// Centred card for sign-in screens.
const authPage = (title, brand, body, foot = '') => `<!doctype html>
<html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><link rel=stylesheet href=/app.css></head>
<body><div class=auth><div class=auth-card>
<div class=brand><span class=brand-dot>${esc(brand[0])}</span>${esc(brand[1])}</div>
${body}${foot ? `<div class=foot>${foot}</div>` : ''}
</div></div></body></html>`;

// --- plumbing -------------------------------------------------------------

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie ?? '').split(';').map((c) => {
    const i = c.indexOf('=');
    return i < 0 ? [c.trim(), ''] : [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1))];
  }).filter(([k]) => k));
}

async function body(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString();
}

function tenantFrom(req) {
  const t = verify(parseCookies(req).t);
  return t?.tid ?? null;
}

// Admin lives on its own cookie with its own claim, so a tenant session can
// never be replayed as an admin one (and vice versa) even though both are
// signed with the same secret.
const isAdmin = (req) => verify(parseCookies(req).adm)?.adm === true;

const routes = [];
const route = (method, path, fn) => routes.push({ method, path, fn });

// --- admin ----------------------------------------------------------------

const adminLogin = (bad = false) => authPage('Agency admin', ['A', 'Agency'], `
    <h1>Agency admin</h1>
    <p class="muted small">Sign in to manage your clients.</p>
    ${bad ? '<div class="note bad">That password is not correct.</div>' : ''}
    <form method=post action=/admin/login>
      <div class=field><label for=password>Password</label>
        <input id=password name=password type=password autofocus autocomplete=current-password></div>
      <button class="btn btn-primary" style="width:100%">Sign in</button>
    </form>`,
    `<a href="/login">Client? Sign in here</a>`);

route('GET', '/admin/login', (req, res) => send(res, adminLogin()));

route('POST', '/admin/login', async (req, res) => {
  const password = new URLSearchParams(await body(req)).get('password');
  if (!ADMIN_PASSWORD || !timingSafe(password, ADMIN_PASSWORD))
    return send(res, adminLogin(true), 401);
  res.writeHead(302, {
    'Set-Cookie': `adm=${encodeURIComponent(sign({ adm: true }))}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=28800`,
    Location: '/admin',
  });
  res.end();
});

route('GET', '/admin', async (req, res) => {
  if (!isAdmin(req)) return redirect(res, '/admin/login');
  const rows = await asAdmin(async ({ query }) => (await query(`
    SELECT t.id, t.name, t.sending_domain, t.daily_cap, t.created_at, t.warmup_started_at,
           (SELECT count(*)::int FROM leads        WHERE tenant_id = t.id) AS leads,
           (SELECT count(*)::int FROM mailboxes    WHERE tenant_id = t.id) AS mailboxes,
           (SELECT count(*)::int FROM campaigns    WHERE tenant_id = t.id) AS campaigns,
           (SELECT count(*)::int FROM deliveries   WHERE tenant_id = t.id
              AND sent_at >= date_trunc('day', now()))                        AS sent_today,
           (SELECT count(*)::int FROM deliveries   WHERE tenant_id = t.id
              AND status = 'queued')                                            AS queued,
           (SELECT count(*)::int FROM suppressions WHERE tenant_id = t.id)      AS suppressed
      FROM tenants t ORDER BY t.created_at DESC`)).rows);

  const total = rows.reduce((a, r) => ({
    clients: a.clients + 1,
    sent_today: a.sent_today + r.sent_today,
    queued: a.queued + r.queued,
    suppressed: a.suppressed + r.suppressed,
  }), { clients: 0, sent_today: 0, queued: 0, suppressed: 0 });

  return send(res, page('All clients', `
    <div class=stats>
      ${stat('Clients', total.clients)}
      ${stat('Sent today', total.sent_today)}
      ${stat('Queued', total.queued)}
      ${stat('Suppressed', total.suppressed)}
    </div>

    ${card('Clients', rows.length ? `
      <table>
        <tr><th>Client</th><th>Domain</th><th class=num>Cap</th><th>Warm-up</th>
          <th class=num>Mailboxes</th><th class=num>Leads</th><th class=num>Campaigns</th>
          <th class=num>Sent today</th><th></th></tr>
        ${rows.map((t) => `<tr>
          <td><a href="/admin/tenants/${t.id}"><strong>${esc(t.name)}</strong></a></td>
          <td class=muted>${esc(t.sending_domain)}</td>
          <td class=num>${t.daily_cap}</td>
          <td>${t.warmup_started_at
              ? `<span class="badge ok">day ${Math.max(1, Math.floor((Date.now() - new Date(t.warmup_started_at)) / 86400000) + 1)}</span>`
              : '<span class="badge grey">not started</span>'}</td>
          <td class=num>${t.mailboxes}</td><td class=num>${t.leads}</td><td class=num>${t.campaigns}</td>
          <td class=num>${t.sent_today}</td>
          <td><div class=actions><form method=post action="/admin/tenants/${t.id}/rotate">
            <button class="btn btn-secondary btn-sm">New code</button></form></div></td>
        </tr>`).join('')}
      </table>` : empty('👥', 'No clients yet', 'Add your first client below to give them their own dashboard.'))}

,
    <div class=actions><a href="/admin/tenants/new" class="btn btn-primary">Add a client</a></div>`,
    { active: '/admin', nav: ADMIN_NAV, brand: ['A', 'Agency'], text: 'Every client runs their own campaigns, leads and reputation' }));
});

route('GET', '/admin/tenants/new', async (req, res) => {
  if (!isAdmin(req)) return redirect(res, '/admin/login');
  return send(res, page('Add a client', `
    ${card('Client details', `
      <form method=post action=/admin/tenants class=form-narrow>
        <div class=field><label for=name>Client name</label>
          <input id=name name=name required placeholder="Acme Corp" autofocus></div>
        <div class=field><label for=domain>Sending domain</label>
          <input id=domain name=domain required placeholder="acme.com">
          <div class=hint>The client's own domain. Each client must use a different one,
            so sender reputation is never shared between them.</div></div>
        <div class=field><label for=daily_cap>Daily cap</label>
          <input id=daily_cap name=daily_cap type=number value=40 min=1>
          <div class=hint>Ceiling per mailbox per day during warm-up. You can raise it later.</div></div>
        <div class=field><label for=access_code>Access code</label>
          <input id=access_code name=access_code placeholder="leave blank to generate">
          <div class=hint>The client signs in with this. Shown once after creation and
            stored hashed, never in plain text.</div></div>
        <div class=btn-row>
          <button class="btn btn-primary">Create client</button>
          <a href="/admin" class="btn btn-secondary">Cancel</a>
        </div>
      </form>`,
      `<a href="/admin" class="btn btn-ghost btn-sm">&larr; All clients</a>`)}

    ${card('What happens next', `
      <ol class=steps>
        <li><div><div class=t>You get an access code, shown once</div>
          <div class=d>Send it to the client. Store it somewhere safe &mdash; you can issue
            a new one from the clients list at any time.</div></div></li>
        <li><div><div class=t>They sign in and see a setup checklist</div>
          <div class=d>Publish DNS records, add a mailbox, import leads, send a campaign.</div></div></li>
        <li><div><div class=t>Their sends are paced and warmed up automatically</div>
          <div class=d>Starting at 5 per mailbox per day, doubling until their cap.</div></div></li>
      </ol>`)}`,
    { active: '/admin', nav: ADMIN_NAV, brand: ['A', 'Agency'], text: 'Onboard a new client' }));
});

route('POST', '/admin/tenants', async (req, res) => {
  if (!isAdmin(req)) return redirect(res, '/admin/login');
  const f = new URLSearchParams(await body(req));
  try {
    const t = await createTenant({
      name: f.get('name'), domain: f.get('domain'),
      dailyCap: f.get('daily_cap'), accessCode: f.get('access_code'),
    });
    return send(res, page('Client created', `
      <h1>${esc(t.name)} is ready</h1>
      <p>Send your client this sign-in code. It is stored hashed and shown only once:</p>
      <p style="font:700 1.6rem ui-monospace"><code>${esc(t.accessCode)}</code></p>
      <p>They sign in at <code>/login</code>, then follow the setup checklist:
         add the DNS records, create a mailbox, import leads, send.</p>
      <p><a href="/admin/tenants/${t.id}">Open client dashboard</a> &middot;
         <a href="/admin">All clients</a></p>`));
  } catch (e) {
    return send(res, page('Could not create client', `<p>${esc(e.message)}</p>
      <p><a href="/admin">Back</a></p>`), 400);
  }
});

route('GET', '/admin/tenants/:id', async (req, res, p) => {
  if (!isAdmin(req)) return redirect(res, '/admin/login');
  const t = await asAdmin(async ({ query }) => (await query(
    `SELECT t.*,
            (SELECT count(*)::int FROM deliveries WHERE tenant_id=t.id
               AND sent_at >= date_trunc('day', now()))                     AS used_today,
            (SELECT count(*)::int FROM deliveries WHERE tenant_id=t.id
               AND sent_at >= date_trunc('month', now()))                   AS used_month,
            (SELECT count(*)::int FROM mailboxes WHERE tenant_id=t.id AND paused) AS paused_boxes,
            (SELECT count(*)::int FROM leads WHERE tenant_id=t.id) AS leads,
            (SELECT count(*)::int FROM mailboxes WHERE tenant_id=t.id) AS mailboxes,
            (SELECT count(*)::int FROM campaigns WHERE tenant_id=t.id) AS campaigns,
            (SELECT count(*)::int FROM deliveries WHERE tenant_id=t.id
               AND sent_at >= date_trunc('day', now())) AS sent_today,
            (SELECT count(*)::int FROM suppressions WHERE tenant_id=t.id) AS suppressed
       FROM tenants t WHERE id=$1`, [p.id])).rows[0]);
  if (!t) return send(res, page('Not found', '<p>No such client.</p>'), 404);

  const recent = await asAdmin(async ({ query }) => (await query(
    `SELECT kind, email, created_at FROM events WHERE tenant_id=$1
      ORDER BY created_at DESC LIMIT 15`, [p.id])).rows);
  const suppressed = await asAdmin(async ({ query }) => (await query(
    `SELECT email, reason, created_at FROM suppressions WHERE tenant_id=$1
      ORDER BY created_at DESC LIMIT 15`, [p.id])).rows);

  const ts = (d) => new Date(d).toISOString().slice(0, 16).replace('T', ' ');
  return send(res, page(t.name, `
    <div class=stats>
      ${stat('Mailboxes', t.mailboxes)}
      ${stat('Leads', t.leads)}
      ${stat('Campaigns', t.campaigns)}
      ${stat('Sent today', t.sent_today, `cap ${t.daily_cap}/day`)}
    </div>

    ${t.suspended ? `<div class="note bad"><strong>This client is suspended.</strong>
      ${esc(t.suspended_reason ?? '')} &mdash; all sending is stopped and new campaigns
      cannot be queued.</div>` : ''}

    ${card('Sending limits', `
      <div class=stats style="margin-bottom:16px">
        ${stat('Used today', `${t.used_today} / ${t.daily_cap}`, 'tenant-wide, all mailboxes')}
        ${stat('Used this month', t.monthly_cap == null
          ? `${t.used_month} &middot; no cap`
          : `${t.used_month} / ${t.monthly_cap}`)}
        ${stat('Mailboxes', t.mailboxes, `${t.paused_boxes} paused`)}
      </div>
      <form method=post action="/admin/tenants/${t.id}/limits" class=form-narrow>
        <div class=grid-2>
          <div class=field><label for=cap>Daily cap (per tenant)</label>
            <input id=cap name=daily_cap type=number value="${t.daily_cap}" min=1 required></div>
          <div class=field><label for=mcap>Monthly cap</label>
            <input id=mcap name=monthly_cap type=number value="${t.monthly_cap ?? ''}" min=1
                   placeholder="blank = unlimited"></div>
        </div>
        <p class=hint style="margin:-4px 0 14px">The daily cap is shared across every
          mailbox this client owns, and warm-up starts well below it.</p>
        <button class="btn btn-primary">Save limits</button>
      </form>`)}

    ${suspendPanel(t)}

    ${card('DNS records they must add', dnsBlock(t.sending_domain))}

    ${card('Recent activity', recent.length ? `
      <table><tr><th>When</th><th>Event</th><th>Email</th></tr>
      ${recent.map((e) => `<tr><td class=muted>${ts(e.created_at)}</td>
        <td>${badge(e.kind)}</td><td>${esc(e.email ?? '')}</td></tr>`).join('')}</table>`
      : empty('◷', 'No activity yet', 'Sent emails, bounces and complaints will appear here.'))}

    ${card(`Suppressed addresses (${t.suppressed})`, suppressed.length ? `
      <table><tr><th>When</th><th>Reason</th><th>Email</th></tr>
      ${suppressed.map((s) => `<tr><td class=muted>${ts(s.created_at)}</td>
        <td>${badge(s.reason === 'bounce' ? 'failed' : s.reason)}</td>
        <td>${esc(s.email)}</td></tr>`).join('')}</table>`
      : empty('✓', 'Nothing suppressed', 'Unsubscribes and hard bounces are blocked from future sends.'))}`,
    {
      active: '/admin', nav: ADMIN_NAV, brand: ['A', 'Agency'],
      text: `domain <code>${esc(t.sending_domain)}</code> &middot; cap ${t.daily_cap}/day
             &middot; warm-up ${t.warmup_started_at ? 'started ' + ts(t.warmup_started_at) : 'not started'}`,
      foot: `<a href="/admin" style="color:#9ca3af;font-size:.86rem">&larr; All clients</a>`,
    }));
});

route('POST', '/admin/tenants/:id/limits', async (req, res, p) => {
  if (!isAdmin(req)) return redirect(res, '/admin/login');
  const f = new URLSearchParams(await body(req));
  const daily = Number(f.get('daily_cap'));
  const monthly = String(f.get('monthly_cap')).trim();

  if (!Number.isInteger(daily) || daily < 1 || daily > 100000)
    return send(res, page('Invalid limit', card('', empty('!', 'Invalid daily cap',
      'The daily cap must be a whole number between 1 and 100000.'),
      `<a href="/admin/tenants/${p.id}" class="btn btn-secondary btn-sm">Back</a>`)), 400);

  if (monthly !== '' && (!Number.isInteger(Number(monthly)) || Number(monthly) < 1))
    return send(res, page('Invalid limit', card('', empty('!', 'Invalid monthly cap',
      'Leave it blank for no limit, or enter a whole number.'),
      `<a href="/admin/tenants/${p.id}" class="btn btn-secondary btn-sm">Back</a>`)), 400);

  await asAdmin(async ({ query }) => query(
    `UPDATE tenants SET daily_cap=$2, monthly_cap=$3 WHERE id=$1`,
    [p.id, daily, monthly === '' ? null : Number(monthly)]));
  return redirect(res, `/admin/tenants/${p.id}`);
});

// Suspension is the abuse kill switch: stops sending now, blocks new campaigns.
route('POST', '/admin/tenants/:id/suspension', async (req, res, p) => {
  if (!isAdmin(req)) return redirect(res, '/admin/login');
  const f = new URLSearchParams(await body(req));
  const suspend = f.get('action') === 'suspend';
  const reason = String(f.get('reason') ?? '').trim().slice(0, 500);

  if (suspend && !reason)
    return send(res, page('Reason required', card('', empty('!', 'Give a reason',
      'Record why this client was suspended. You will need it if they ask.'),
      `<a href="/admin/tenants/${p.id}" class="btn btn-secondary btn-sm">Back</a>`)), 400);

  await asAdmin(async ({ query }) => query(
    `UPDATE tenants SET suspended=$2, suspended_reason=$3 WHERE id=$1`,
    [p.id, suspend, suspend ? reason : null]));
  return redirect(res, `/admin/tenants/${p.id}`);
});

route('POST', '/admin/tenants/:id/rotate', async (req, res, p) => {
  if (!isAdmin(req)) return redirect(res, '/admin/login');
  const code = crypto.randomBytes(9).toString('base64url');
  await asAdmin(async ({ query }) =>
    query('UPDATE tenant_codes SET code_hash=$2 WHERE tenant_id=$1', [p.id, sha256(code)]));
  return send(res, page('New access code', `
    <p>New sign-in code for this client. The old one stopped working immediately.</p>
    <p style="font:700 1.6rem ui-monospace"><code>${esc(code)}</code></p>
    <p><a href="/admin/tenants/${p.id}">Back</a></p>`));
});

function timingSafe(a, b) {
  const sa = crypto.createHash('sha256').update(String(a ?? '')).digest();
  const sb = crypto.createHash('sha256').update(String(b ?? '')).digest();
  return crypto.timingSafeEqual(sa, sb);
}

// --- auth -----------------------------------------------------------------

route('GET', '/', async (req, res) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const data = await withTenant(tid, async ({ query }) => {
    const t = (await query('SELECT * FROM tenants WHERE id=$1', [tid])).rows[0];
    const stats = (await query(`
      SELECT
        (SELECT count(*)::int FROM leads) AS leads,
        (SELECT count(*)::int FROM mailboxes) AS mailboxes,
        (SELECT count(*)::int FROM campaigns) AS campaigns,
        (SELECT count(*)::int FROM deliveries WHERE sent_at >= date_trunc('day', now())) AS sent_today,
        (SELECT count(*)::int FROM deliveries WHERE status='queued') AS queued,
        (SELECT count(*)::int FROM suppressions) AS suppressed
    `)).rows[0];
    const health = (await query(`
      SELECT
        (SELECT count(*)::int FROM leads WHERE status='invalid') AS invalid,
        (SELECT count(*)::int FROM leads WHERE status='risky')   AS risky,
        (SELECT count(*)::int FROM suppressions WHERE reason='complaint') AS complaints,
        (SELECT count(*)::int FROM suppressions WHERE reason='bounce')    AS bounces,
        (SELECT count(*)::int FROM suppressions WHERE reason='unsubscribe') AS unsubs,
        (SELECT count(*)::int FROM test_sends) AS tests`)).rows[0];
    return { t, stats, health };
  });
  if (!data) return redirect(res, '/login');
  const { t, stats, health } = data;
  // We cannot query SES to confirm DNS, so DNS is treated as done once the
  // client has added a mailbox (which only makes sense after verifying it).
  const steps = [
    ['Add your DNS records', stats.mailboxes > 0, '/dns',
      'Verify your domain in Amazon SES and publish SPF, DKIM and DMARC.'],
    ['Create a mailbox', stats.mailboxes > 0, '/mailboxes',
      'One mailbox per person who replies. Each caps its own daily volume.'],
    ['Import your lead list', stats.leads > 0, '/leads',
      'A CSV with columns email, first_name, last_name, company.'],
    ['Write and queue a campaign', stats.campaigns > 0, '/campaigns',
      'Use {{first_name}}, {{last_name}} and {{company}} in the subject and body.'],
  ];
  const done = steps.filter((s) => s[1]).length;
  const pct = Math.round((done / steps.length) * 100);
  return send(res, page(t.name, `
    ${t.suspended ? `<div class="note bad"><strong>Sending is paused.</strong>
      ${esc(t.suspended_reason ?? 'Contact your account manager.')} Your queued emails will
      not be sent and new campaigns cannot be queued until this is lifted.</div>` : ''}
    <div class=stats>
      ${stat('Leads', stats.leads)}
      ${stat('Mailboxes', stats.mailboxes)}
      ${stat('Campaigns', stats.campaigns)}
      ${stat('Sent today', stats.sent_today, `cap ${t.daily_cap}/day`)}
      ${stat('Queued', stats.queued)}
      ${stat('Suppressed', stats.suppressed)}
    </div>

    ${card('Get set up', `
      <div class=btn-row style="justify-content:space-between;margin-bottom:14px">
        <strong>${done} of ${steps.length} complete</strong>
        <span class="muted small">${esc(t.sending_domain)} &middot; warm-up ${
          t.warmup_started_at ? 'started ' + new Date(t.warmup_started_at).toISOString().slice(0, 10) : 'not started'}</span>
      </div>
      <div class=bar style="margin-bottom:16px"><i style="width:${pct}%"></i></div>
      <ol class=steps>
        ${steps.map(([title, ok, href, desc]) => `<li>
          <div><div class=t>${ok ? `${esc(title)} <span class="badge ok">done</span>` : `<a href="${href}">${esc(title)}</a>`}</div>
          <div class=d>${esc(desc)}</div></div></li>`).join('')}
      </ol>`)}

    ${card('Deliverability health', `
      <div class=stats style="margin-bottom:0">
        ${stat('Bad leads blocked', health.invalid, 'no working mail server')}
        ${stat('Hard bounces', health.bounces)}
        ${stat('Complaints', health.complaints, 'keep under 0.3% of sends')}
        ${stat('Unsubscribed', health.unsubs)}
        ${stat('Test sends', health.tests)}
      </div>
      <div class="note warn" style="margin-top:18px">
        Gmail, Yahoo and Outlook require complaints under 0.3% of sends. Past 0.1% you
        are at risk of having your sending blocked. A rising complaint count means
        tighten your targeting or stop mailing that list.
      </div>`)}`,
    { active: '/', text: 'Your sending dashboard', brand: [t.name[0].toUpperCase(), t.name] }));
});

// Clears both cookies so one sign-out leaves nothing behind on either side.
route('GET', '/logout', (req, res) => {
  res.writeHead(302, {
    'Set-Cookie': 't=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0',
    Location: '/login',
  });
  res.end();
});

route('GET', '/login', (req, res) => send(res, authPage('Sign in', ['O', 'Outreach'], `
    <h1>Sign in</h1>
    <p class="muted small">Enter the access code your account manager gave you.</p>
    <form method=post action=/login>
      <div class=field><label for=code>Access code</label>
        <input id=code name=code autofocus autocomplete=off placeholder="e.g. a1b2c3d4e5f6"></div>
      <button class="btn btn-primary" style="width:100%">Sign in</button>
    </form>`,
    `<a href="/admin">Agency staff? Sign in here</a>`)));

route('POST', '/login', async (req, res) => {
  // URLSearchParams stores entries internally; destructuring { code } yields
  // undefined, so always go through .get().
  const code = new URLSearchParams(await body(req)).get('code');
  const t = await asPlatform(async ({ query }) =>
    (await query('SELECT tenant_id FROM tenant_codes WHERE code_hash=$1', [sha256(code)])).rows[0]);
  if (!t) return send(res, authPage('Sign in', ['O', 'Outreach'], `
    <h1>Sign in</h1>
    <div class="note bad">That access code is not valid. Check it with your account manager.</div>
    <form method=post action=/login>
      <div class=field><label for=code>Access code</label>
        <input id=code name=code autofocus autocomplete=off></div>
      <button class="btn btn-primary" style="width:100%">Sign in</button>
    </form>`,
    `<a href="/admin">Agency staff? Sign in here</a>`), 401);
  res.writeHead(302, {
    'Set-Cookie': `t=${encodeURIComponent(sign({ tid: t.tenant_id }))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`,
    Location: '/',
  });
  res.end();
});

// --- DNS ------------------------------------------------------------------
// Yahoo/Gmail/Outlook reject bulk mail outright (550-5.7.26) unless SPF, DKIM
// and DMARC all pass with alignment. This page is the whole onboarding flow.

route('GET', '/dns', async (req, res) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const t = await withTenant(tid, async ({ query }) =>
    (await query('SELECT sending_domain FROM tenants WHERE id=$1', [tid])).rows[0]);
  if (!t) return redirect(res, '/login');
  const d = t.sending_domain;
  return send(res, page('DNS setup', `
    <div class="note warn">Senders that do not pass all of these are rejected outright by
      Gmail, Yahoo and Outlook with <code>550-5.7.26</code>. The mail is refused, not
      deferred, and never retried.</div>

    ${card('Records to publish', dnsBlock(d),
      `<a href="https://support.google.com/a/answer/2466580" class="btn btn-secondary btn-sm"
         target=_blank rel=noopener>Check in Postmaster Tools</a>`)}

    ${card('Never publish a second SPF record', `
      <p>A domain may only have one SPF record. If you already have
        <code>v=spf1 ...</code> published, <strong>append</strong> the value above to it
        rather than adding another. Two SPF records makes the domain fail, and your mail
        stops arriving entirely.</p>`)}

    ${card('Once it is done', `
      <ol class=steps>
        <li><div><div class=t>Verify the domain with your sending provider</div>
          <div class=d>They issue the verification token and DKIM key you publish above.</div></div></li>
        <li><div><div class=t>Wait for DNS to propagate</div>
          <div class=d>Usually minutes, occasionally up to 48 hours.</div></div></li>
        <li><div><div class=t>Send a test send to a seed inbox</div>
          <div class=d>It should arrive in the inbox, not Spam.</div></div></li>
      </ol>`)}`,
    { active: '/dns' }));
});

// --- campaigns ------------------------------------------------------------

route('GET', '/campaigns', async (req, res) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const justQueued = new URL(req.url, 'http://x').searchParams.get('queued');
  const rows = await withTenant(tid, async ({ query }) => (await query(`
    SELECT c.*, count(d.id) FILTER (WHERE d.status='sent') AS sent,
           count(d.id) FILTER (WHERE d.status='queued') AS queued
      FROM campaigns c LEFT JOIN deliveries d ON d.campaign_id=c.id
     GROUP BY c.id ORDER BY c.created_at DESC`)).rows);
  const { sending_domain: domain, suspended } = await withTenant(tid, async ({ query }) =>
    (await query('SELECT sending_domain, suspended FROM tenants WHERE id=$1', [tid])).rows[0]);
  return send(res, page('Campaigns', `
    ${suspended ? '<div class="note bad">Your account is suspended, so campaigns cannot be queued.</div>' : ''}
    ${justQueued ? `<div class="note good">Queued <strong>${esc(justQueued)}</strong> emails,
      spread across today rather than sent as one burst.</div>` : ''}

    ${card('Your campaigns', rows.length ? `
      <table>
        <tr><th>Name</th><th>From</th><th>Subject</th><th>Status</th>
          <th class=num>Sent</th><th class=num>Queued</th><th></th></tr>
        ${rows.map((c) => `<tr>
          <td><strong>${esc(c.name)}</strong></td>
          <td class=muted>${esc(c.from_email)}</td>
          <td>${esc(c.subject)}</td>
          <td>${badge(c.status)}</td>
          <td class=num>${c.sent}</td><td class=num>${c.queued}</td>
          <td><div class=actions>
            ${c.status === 'draft' && !suspended ? `
              <form method=post action="/campaigns/${c.id}/queue">
                <button class="btn btn-primary btn-sm">Queue</button></form>
              <form method=post action="/campaigns/${c.id}/test" class=btn-row>
                <input name=to placeholder="seed@mailbox.com"
                       style="width:11rem;padding:5px 8px;font-size:.82rem">
                <button class="btn btn-secondary btn-sm">Test send</button></form>` : ''}
          </div></td>
        </tr>`).join('')}
      </table>
      <p class="small muted" style="margin-top:14px">
        Test sends go to seed inboxes you control. They bypass your daily cap and do not
        affect campaign stats. Open each one, mark it read, and move it out of Spam if
        it was filtered &mdash; that is the strongest signal you can give your mailbox
        provider.</p>`
      : empty('✉', 'No campaigns yet', 'Write your first campaign below. It stays a draft until you queue it.'))}

    ${card('New campaign', `
      <form method=post action=/campaigns class=form-narrow>
        <div class=field><label for=name>Campaign name</label>
          <input id=name name=name required placeholder="Q3 outreach"></div>
        <div class=field><label for=from_email>From address</label>
          <input id=from_email name=from_email type=email required placeholder="jane@${esc(domain)}">
          <div class=hint>Must be on ${esc(domain)}.</div></div>
        <div class=field><label for=subject>Subject</label>
          <input id=subject name=subject required placeholder="Quick question for {{first_name}}">
          <div class=hint>Merge tags: <code>{{first_name}}</code> <code>{{last_name}}</code> <code>{{company}}</code></div></div>
        <div class=field><label for=body>Body</label>
          <textarea id=body name=body rows=8 required placeholder="Hi {{first_name}},&#10;&#10;I noticed {{company}} is hiring..."></textarea></div>
        <button class="btn btn-primary">Create draft</button>
      </form>`)}`,
    { active: '/campaigns' }));
});

route('POST', '/campaigns', async (req, res) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const f = new URLSearchParams(await body(req));
  await withTenant(tid, async ({ query }) => {
    const t = (await query('SELECT sending_domain FROM tenants WHERE id=$1', [tid])).rows[0];
    const from = f.get('from_email');
    if (!from.endsWith('@' + t.sending_domain))
      throw new Error(`From must be on ${t.sending_domain}`);
    await query(
      `INSERT INTO campaigns (tenant_id,name,subject,body,from_email) VALUES ($1,$2,$3,$4,$5)`,
      [tid, f.get('name'), f.get('subject'), f.get('body'), from],
    );
  });
  return redirect(res, '/campaigns');
});

route('POST', '/campaigns/:id/test', async (req, res, params) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const f = new URLSearchParams(await body(req));
  const to = String(f.get('to') ?? '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
  if (!to.length) return send(res, page('Test send', '<p>Enter at least one address.</p>'), 400);

  const campaign = await withTenant(tid, async ({ query }) =>
    (await query(`
      SELECT c.*, m.display_name, m.domain
        FROM campaigns c
        JOIN mailboxes m ON m.local_part = split_part(c.from_email,'@',1)
                         AND m.domain = split_part(c.from_email,'@',2)
       WHERE c.id = $1`, [params.id])).rows[0]);
  if (!campaign) return send(res, page('Test send', '<p>That campaign has no matching mailbox.</p>'), 400);

  let sent = 0;
  const failed = [];
  for (const addr of to) {
    try { await sendTest({ tenantId: tid, campaign, to: addr }); sent++; }
    catch (e) { failed.push(`${addr} (${e.message})`); }
  }
  return send(res, page('Test sends', `
    <div class="note ${sent ? 'good' : 'bad'}">Sent to <strong>${sent}</strong> seed
      ${sent === 1 ? 'address' : 'addresses'}.${failed.length
        ? ` Failed: ${esc(failed.join(', '))}` : ''}</div>

    ${card('Check each one now', `
      <ol class=steps>
        <li><div><div class=t>Open each seed inbox, search for the subject</div>
          <div class=d>Use a fresh tab so you see it as a recipient would.</div></div></li>
        <li><div><div class=t>Mark it as read</div>
          <div class=d>Gmail and Outlook re-score bulk mail on unread messages and will
            bury your real campaign mail more deeply.</div></div></li>
        <li><div><div class=t>Check Spam and Junk too</div>
          <div class=d>Anything landing outside the inbox is a deliverability problem to
            fix before you send for real.</div></div></li>
        <li><div><div class=t>Hit &ldquo;Not spam&rdquo; if it was filtered</div>
          <div class=d>This is the single strongest positive signal you can give your
            mailbox provider.</div></div></li>
      </ol>
      <p class="small muted" style="margin-top:12px">These sends do not count toward your
        daily cap or campaign stats. Merge tags rendered as sample values (John Doe / Acme)
        so the message looks like the real thing.</p>`,
      `<a href="/campaigns" class="btn btn-secondary btn-sm">Back to campaigns</a>`)}`,
    { active: '/campaigns' }));
});

route('POST', '/campaigns/:id/queue', async (req, res, params) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const blocked = await withTenant(tid, async ({ query }) =>
    (await query('SELECT suspended, suspended_reason FROM tenants WHERE id=$1', [tid])).rows[0]);
  if (blocked?.suspended)
    return send(res, page('Sending is paused', card('', empty('!', 'Sending is paused',
      `Your account is suspended: ${blocked.suspended_reason ?? 'contact your account manager'}.`))), 403);
  const queued = await withTenant(tid, async ({ query }) => {
    const mails = (await query('SELECT id FROM mailboxes WHERE tenant_id=$1 AND paused=false', [tid])).rows;
    if (mails.length === 0) throw new Error('Add a mailbox first');
    // Fan leads across mailboxes round-robin; ordering by created_at keeps any
    // per-mailbox daily cap roughly fair instead of starving later mailboxes.
    const leads = (await query('SELECT id FROM leads ORDER BY created_at', [])).rows;
    // Spread across a day, not a fixed step per lead. A fixed step would push
    // lead 10,000 of a large list almost two weeks into the future.
    const step = leads.length ? Math.floor(DAY_SECONDS / leads.length) : 0;
    let n = 0;
    for (const [i, lead] of leads.entries()) {
      const ins = await query(
        `INSERT INTO deliveries (tenant_id,campaign_id,lead_id,mailbox_id,scheduled_at)
         VALUES ($1,$2,$3,$4, now() + make_interval(secs => $5))
         ON CONFLICT (campaign_id, lead_id) DO NOTHING RETURNING id`,
        [tid, params.id, lead.id, mails[i % mails.length].id, i * step],
      );
      n += ins.rowCount;
    }
    await query(`UPDATE campaigns SET status='sending' WHERE id=$1`, [params.id]);
    return n;
  });
  return redirect(res, `/campaigns?queued=${queued}`);
});

// --- leads ----------------------------------------------------------------

route('GET', '/leads', async (req, res) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const rows = await withTenant(tid, async ({ query }) =>
    (await query(`SELECT email, first_name, last_name, company, status FROM leads
                   ORDER BY created_at DESC LIMIT 200`)).rows);
  const tally = await withTenant(tid, async ({ query }) =>
    (await query(`SELECT status, count(*)::int n FROM leads GROUP BY status`)).rows);
  const n = Object.fromEntries(tally.map((r) => [r.status, r.n]));
  return send(res, page('Leads', `
    <div class=stats>
      ${stat('Total', rows.length)}
      ${stat('Deliverable', n.valid ?? 0, 'domain has mail server')}
      ${stat('Role addresses', n.risky ?? 0, 'info@, sales@')}
      ${stat('Rejected', n.invalid ?? 0, 'never sent')}
    </div>

    ${card('Lead list', rows.length ? `
      <table><tr><th>Email</th><th>First</th><th>Last</th><th>Company</th><th>Status</th></tr>
      ${rows.map((l) => `<tr>
        <td><strong>${esc(l.email)}</strong></td>
        <td>${esc(l.first_name)}</td><td>${esc(l.last_name)}</td><td>${esc(l.company)}</td>
        <td>${badge(l.status)}</td></tr>`).join('')}
      </table>` : empty('👥', 'No leads yet',
        'Import a CSV to get started. Columns: email, first_name, last_name, company.'),
      `<span class="muted small">showing latest 200</span>`)}

    ${card('Import CSV', `
      <div class="note">Every address is checked on import. Ones with no working mail
        server are marked <span class="badge bad">invalid</span> and are never sent &mdash;
        hard bounces are the fastest way to damage your sender reputation.</div>
      <form id=imp>
        <div class=field><label for=f>CSV file</label>
          <input id=f type=file accept=".csv,text/csv" required></div>
        <button class="btn btn-primary">Import leads</button>
      </form>
      <script>document.getElementById('imp').onsubmit=async e=>{e.preventDefault();
        const r=await fetch('/leads',{method:'POST',headers:{'Content-Type':'text/plain'},
          body:await document.getElementById('f').files[0].text()});
        location.href=r.url;}</script>`)}`,
    { active: '/leads' }));
});

route('POST', '/leads', async (req, res) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const csv = parseCsv(await body(req));
  const [head, ...rows] = csv;
  if (!head) return send(res, page('Leads', '<p>That file was empty.</p>'), 400);
  const col = Object.fromEntries(head.map((h, i) => [h.trim().toLowerCase(), i]));
  if (col.email === undefined)
    return send(res, page('Leads', '<p>That CSV needs an <code>email</code> column.</p>'), 400);

  const emails = rows.map((r) => (r[col.email] ?? '').trim()).filter(Boolean);
  // Checked before insert so a list full of dead domains never becomes rows.
  const checked = new Map(await verifyEmails(emails));

  const counts = await withTenant(tid, async ({ query }) => {
    const c = { imported: 0, valid: 0, invalid: 0, risky: 0, duplicate: 0 };
    for (const r of rows) {
      const email = (r[col.email] ?? '').trim();
      if (!email) continue;
      const status = checked.get(email.toLowerCase()) ?? 'unknown';
      const ins = await query(
        `INSERT INTO leads (tenant_id,email,first_name,last_name,company,status,checked_at)
         VALUES ($1,$2,$3,$4,$5,$6,now())
         ON CONFLICT (tenant_id,email) DO NOTHING RETURNING id`,
        [tid, email, r[col.first_name] ?? '', r[col.last_name] ?? '', r[col.company] ?? '', status],
      );
      if (ins.rowCount === 0) { c.duplicate++; continue; }
      c.imported++;
      c[status === 'unknown' ? 'valid' : status]++;
    }
    return c;
  });

  return send(res, page('Import complete', `
    <div class="note good">Imported <strong>${counts.imported}</strong> new leads
      ${counts.duplicate ? `(${counts.duplicate} were already on the list)` : ''}.</div>
    <div class=stats>
      ${stat('Deliverable', counts.valid, 'domain has mail server')}
      ${stat('Role addresses', counts.risky, 'still sendable')}
      ${stat('Rejected', counts.invalid, 'no working mail server')}
    </div>
    <div class=actions><a href="/leads" class="btn btn-primary">Back to leads</a></div>`,
    { active: '/leads' }));
});

// --- mailboxes ------------------------------------------------------------

route('GET', '/mailboxes', async (req, res) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const { rows, domain } = await withTenant(tid, async ({ query }) => ({
    rows: (await query('SELECT * FROM mailboxes ORDER BY created_at')).rows,
    domain: (await query('SELECT sending_domain FROM tenants WHERE id=$1', [tid])).rows[0].sending_domain,
  }));
  return send(res, page('Mailboxes', `
    <div class=stats>
      ${stat('Mailboxes', rows.length)}
      ${stat('Combined daily cap', rows.reduce((n, m) => n + m.daily_cap, 0))}
      ${stat('Paused', rows.filter((m) => m.paused).length)}
    </div>

    ${rows.length ? card('Your mailboxes', `
      <table><tr><th>Address</th><th>Display name</th><th class=num>Daily cap</th><th>Status</th><th></th></tr>
      ${rows.map((m) => `<tr>
        <td><strong>${esc(m.local_part)}@${esc(m.domain)}</strong></td>
        <td>${esc(m.display_name)}</td>
        <td class=num>${m.daily_cap}</td>
        <td>${m.paused ? '<span class="badge warn">paused</span>' : '<span class="badge ok">active</span>'}</td>
        <td><div class=actions>
          <form method=post action="/mailboxes/${m.id}" class=btn-row>
            <input name=daily_cap type=number value="${m.daily_cap}" min=1 max=100
                   style="width:5rem;padding:5px 8px;font-size:.82rem">
            <input type=hidden name=action value=cap>
            <button class="btn btn-secondary btn-sm">Set</button>
          </form>
          <form method=post action="/mailboxes/${m.id}">
            <input type=hidden name=action value="${m.paused ? 'resume' : 'pause'}">
            <button class="btn ${m.paused ? 'btn-primary' : 'btn-secondary'} btn-sm">${m.paused ? 'Resume' : 'Pause'}</button>
          </form>
        </div></td>
      </tr>`).join('')}
      </table>
      <p class="small muted" style="margin-top:14px">Cold outreach runs at roughly
        20&ndash;50 emails per mailbox per day. Scale by adding mailboxes, never by
        raising one mailbox&rsquo;s cap.</p>`) : ''}

    ${card('Add a mailbox', `
      <form method=post action=/mailboxes class=form-narrow>
        <div class=field><label for=local_part>Local part</label>
          <input id=local_part name=local_part required placeholder="jane">
          <div class=hint>Becomes jane@${esc(domain)}.</div></div>
        <div class=field><label for=display_name>Display name</label>
          <input id=display_name name=display_name required placeholder="Jane Smith"></div>
        <div class=field><label for=daily_cap>Daily cap</label>
          <input id=daily_cap name=daily_cap type=number value=30 min=1 max=100></div>
        <button class="btn btn-primary">Add mailbox</button>
      </form>`)}`,
    { active: '/mailboxes' }));
});

route('POST', '/mailboxes/:id', async (req, res, p) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const f = new URLSearchParams(await body(req));
  if (f.get('action') === 'cap') {
    const cap = Number(f.get('daily_cap'));
    if (!Number.isInteger(cap) || cap < 1 || cap > 100)
      return send(res, page('Invalid cap', card('', empty('!', 'Invalid daily cap',
        'Choose a whole number between 1 and 100.'))), 400);
    await withTenant(tid, async ({ query }) =>
      query('UPDATE mailboxes SET daily_cap=$2 WHERE id=$1', [p.id, cap]));
  } else {
    await withTenant(tid, async ({ query }) =>
      query('UPDATE mailboxes SET paused=$2 WHERE id=$1',
        [p.id, f.get('action') === 'pause']));
  }
  return redirect(res, '/mailboxes');
});

route('POST', '/mailboxes', async (req, res) => {
  const tid = tenantFrom(req);
  if (!tid) return redirect(res, '/login');
  const f = new URLSearchParams(await body(req));
  await withTenant(tid, async ({ query }) => {
    const t = (await query('SELECT sending_domain FROM tenants WHERE id=$1', [tid])).rows[0];
    await query(
      `INSERT INTO mailboxes (tenant_id,local_part,domain,display_name,daily_cap)
       VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
      [tid, f.get('local_part'), t.sending_domain, f.get('display_name'), Number(f.get('daily_cap')) || 30],
    );
  });
  return redirect(res, '/mailboxes');
});

// --- unsubscribe (RFC 8058) ----------------------------------------------
// One-click requires a bare POST endpoint that returns 200 with no UI. Gmail and
// Yahoo scrape this within 48h; not having it is a hard deliverability failure.

route('GET', '/u/:token', async (req, res, p) => {
  const t = verify(p.token);
  if (!t) return send(res, page('Unsubscribe', '<p>Link expired or invalid.</p>'), 400);
  await suppress(t.t, t.e, 'unsubscribe');
  return send(res, page('Unsubscribed',
    `<p>${esc(t.e)} will receive no further mail.</p>
     <p style=color:#666;font-size:13px>${esc(new Date().toUTCString())}</p>`));
});

route('POST', '/u/:token', async (req, res, p) => {
  const t = verify(p.token);
  if (!t) return send(res, '', 400);
  await suppress(t.t, t.e, 'unsubscribe');
  res.writeHead(200).end();
});

async function suppress(tid, email, reason) {
  await withTenant(tid, async ({ query }) => {
    await query(
      `INSERT INTO suppressions (tenant_id,email,reason) VALUES ($1,$2,$3)
       ON CONFLICT (tenant_id,email) DO UPDATE SET reason=EXCLUDED.reason`,
      [tid, email, reason],
    );
  });
}

// --- bounce / complaint webhook -------------------------------------------
// Secret in the path rather than full SNS signature verification: if this leaks,
// anyone can suppress arbitrary addresses. Rotate the secret on SES if exposed.

route('POST', '/webhooks/bounces/:secret', async (req, res, p) => {
  if (!BOUNCE_SECRET || p.secret !== BOUNCE_SECRET) return send(res, '', 403);
  const events = JSON.parse(await body(req));
  for (const e of events ?? []) {
    // Soft bounces are transient; only permanent ones mean the address is dead.
    const list = e.notificationType === 'Bounce'
      ? (e.bounce?.bounceType === 'Permanent' ? e.bounce.bouncedRecipients : [])
      : e.notificationType === 'Complaint'
        ? (e.complaint?.complainedRecipients ?? [])
        : [];
    if (!list.length) continue;
    const reason = e.notificationType === 'Complaint' ? 'complaint' : 'bounce';
    // The delivery id rides in a header we set at send time, paired with its
    // tenant: a webhook cannot look this up unscoped, because RLS rightly
    // refuses a read with no tenant context. Re-reading the row inside
    // withTenant proves the pair is consistent rather than trusting the header.
    const [tid, did] = String(e.mail?.commonHeaders?.['x-entity-ref-id'] ?? '').split('/');
    if (!isUuid(tid) || !isUuid(did)) continue;
    const found = await withTenant(tid, async ({ query }) =>
      (await query('SELECT id FROM deliveries WHERE id=$1', [did])).rows[0]);
    if (!found) continue;
    for (const r of list) await suppress(tid, r.emailAddress, reason);
  }
  res.writeHead(200).end();
});

// --- helpers --------------------------------------------------------------

function parseCsv(text) {
  const out = []; let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') q = false;
      else cell += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n') { row.push(cell); out.push(row); row = []; cell = ''; }
    else if (c !== '\r') cell += c;
  }
  if (cell || row.length) { row.push(cell); out.push(row); }
  return out;
}

const send = (res, html, status = 200) => {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
};
const redirect = (res, to) => { res.writeHead(302, { Location: to }); res.end(); };

// Shared UI pieces so every page looks like it came from the same product.
const TONES = { draft: 'grey', queued: 'info', sending: 'warn', done: 'ok', paused: 'grey',
                valid: 'ok', invalid: 'bad', risky: 'warn', unknown: 'grey',
                sent: 'ok', failed: 'bad', skipped: 'grey' };
const badge = (v) => `<span class="badge ${TONES[v] ?? 'grey'}">${esc(v)}</span>`;
const stat = (k, v, note = '') =>
  `<div class=stat><div class=k>${esc(k)}</div><div class=v>${esc(v)}</div>${note ? `<div class=n>${esc(note)}</div>` : ''}</div>`;
const empty = (icon, title, text, cta = '') =>
  `<div class=empty><div class=icon>${icon}</div><h3>${esc(title)}</h3><p>${esc(text)}</p>${cta}</div>`;
const card = (title, body, head = '') =>
  `<section class=card>${title ? `<div class=card-head><h2>${esc(title)}</h2>${head}</div>` : ''}<div class=card-body>${body}</div></section>`;

// Suspension controls. Split out because the suspended/resumed states are
// genuinely different screens, and nesting templates inline made a mess.
function suspendPanel(t) {
  const url = `/admin/tenants/${t.id}/suspension`;
  if (t.suspended) {
    return card('Suspend client', `
      <div class="note bad">Suspended. All sending is stopped and new campaigns are blocked.</div>
      <p class="small muted">Reason on file: ${esc(t.suspended_reason ?? 'not recorded')}</p>
      <form method=post action="${url}">
        <input type=hidden name=action value=resume>
        <button class="btn btn-primary">Lift suspension</button>
      </form>`);
  }
  return card('Suspend client', `
    <div class="note warn">Suspension stops all sending immediately and blocks new
      campaigns. Use it when a client&rsquo;s list is generating spam complaints against
      your sending IP.</div>
    <form method=post action="${url}" class=form-narrow>
      <input type=hidden name=action value=suspend>
      <div class=field><label for=reason>Reason</label>
        <input id=reason name=reason required placeholder="Complaint rate over 0.3%"></div>
      <button class="btn btn-danger">Suspend client</button>
    </form>`);
}

// Renders the provider-specific DNS records. Both the client page and the admin
// client detail use this, so the two can never disagree about what to publish.
function dnsBlock(domain) {
  const r = dnsRecords(domain);
  const row = (label, rec) => !rec ? '' : `<tr>
      <td><span class="badge info">${esc(rec.type)}</span></td>
      <td><code>${esc(label)}</code></td>
      <td>${rec.value ? `<code>${esc(rec.value)}</code>` : `<span class=muted>${esc(rec.note)}</span>`}</td></tr>`;
  return `
    <div class="note">Sending provider: <strong>${esc(r.provider)}</strong>. ${esc(r.howto)}</div>
    <table>
      <tr><th>Type</th><th>Name</th><th>Value</th></tr>
      ${row('Domain verification', r.verify)}
      ${row('DKIM key', r.dkim)}
      ${row('DMARC policy', r.dmarc)}
    </table>
    <p class="small" style="margin-top:14px"><strong>SPF</strong> &mdash; add to the
      <em>one existing</em> SPF record on <code>${esc(domain)}</code>:</p>
    <p><code style="display:inline-block;background:#f3f4f6;padding:8px 12px;border-radius:6px">${esc(r.spf)}</code></p>
    ${r.rdns ? `<div class="note warn">${esc(r.rdns)}</div>` : ''}`;
}

// Serves public/app.css. Node has no static middleware and this app has exactly
// one asset, so a hardcoded map beats pulling in a dependency for it. Read once
// at boot: a missing file should stop the server, not 500 on first page load.
const ASSETS = {
  '/app.css': ['text/css; charset=utf-8',
    readFileSync(resolve(import.meta.dirname, '..', 'public/app.css'))],
};

export const server = http.createServer(async (req, res) => {
  const { pathname } = new URL(req.url, 'http://x');

  const asset = ASSETS[pathname];
  if (asset) {
    return res.writeHead(200, {
      'Content-Type': asset[0],
      'Cache-Control': 'public, max-scale=300',
    }).end(asset[1]);
  }

  for (const r of routes) {
    const params = {};
    const rx = new RegExp('^' + r.path.replace(/:(\w+)/g, (_, k) => { params[k] = ''; return '([^/]+)'; }) + '$');
    const m = pathname.match(rx);
    if (!m) continue;
    if (r.method !== req.method) continue;
    m.slice(1).forEach((v, i) => { params[Object.keys(params)[i]] = decodeURIComponent(v); });
    try {
      return await r.fn(req, res, params);
    } catch (e) {
      console.error('[http]', pathname, e);
      return send(res, page('Something went wrong',
        card('', `<p>${esc(e.message)}</p>`)), 500);
    }
  }
  send(res, page('Page not found', card('', empty('404', 'Nothing here',
    'That page does not exist, or you may not have access to it.'))), 404);
});

// Only listen when run directly, so tests can import the server and exercise
// real routes. Importing used to start listening, which made every page
// unreachable from a test.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  server.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
    runForever();
  });
}
