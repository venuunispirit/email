import nodemailer from 'nodemailer';
import { withTenant, asAdmin } from './db.js';
import { sign } from './token.js';

import { smtpSettings } from './providers.js';

const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:3000';

// Lets tests exercise the queue/cap/suppression path without a live SMTP server.
export let transport;
export const setTransport = (t) => { transport = t; };
transport = nodemailer.createTransport(smtpSettings());

// The floor of 5 belongs to the ramp, not to the result: a tenant who sets a
  // cap below 5 must still be held to it.
// Cold mailboxes start at 5/day and double daily until the tenant's cap. Sending
// 500 cold emails on day one is indistinguishable from a spam run, and Gmail
// judges a new domain that way permanently.
export function warmupCap(tenant, now = Date.now()) {
  // Before warm-up starts, still clamped: an unwarmed tenant with a cap of 3
  // must not silently get 5, which is what this early return used to do.
  if (!tenant.warmup_started_at) return Math.min(tenant.daily_cap, 5);
  const days = Math.floor((now - new Date(tenant.warmup_started_at).getTime()) / 86_400_000);
  return Math.min(tenant.daily_cap, Math.max(5, 5 * 2 ** Math.min(days, 10)));
}

export function render(template, lead) {
  return String(template).replace(/\{\{(\w+)\}\}/g, (_, k) => lead[k] ?? '');
}

const CANDIDATES = `
  SELECT d.id, d.campaign_id,
         c.subject, c.body,
         l.email, l.first_name, l.last_name, l.company,
         m.id AS mailbox_id, m.local_part, m.domain, m.display_name, m.daily_cap AS mailbox_cap
    FROM deliveries d
    JOIN campaigns c ON c.id = d.campaign_id
    JOIN leads     l ON l.id = d.lead_id
    JOIN mailboxes m ON m.id = d.mailbox_id
   WHERE d.status = 'queued'
     AND d.scheduled_at <= now()
     AND c.status IN ('sending','queued')
     AND m.paused = false
     -- Never mail an address verified as undeliverable; a hard bounce is the
     -- fastest way to damage the sender reputation this whole app protects.
     AND l.status <> 'invalid'
     AND NOT EXISTS (
       SELECT 1 FROM suppressions s WHERE s.tenant_id = d.tenant_id AND s.email = l.email
     )
   ORDER BY d.scheduled_at
   LIMIT 200`;

// Claim up to what the tenant has left today and this month, then divide that
// across mailboxes. Runs inside withTenant so RLS guarantees these rows belong
// to the tenant being processed, even if this function later grows a bug.
async function claimBatch(tenant, cap) {
  return withTenant(tenant.id, async ({ query }) => {
    if (tenant.suspended) return [];
    const { rows } = await query(CANDIDATES);
    if (!rows.length) return [];

    await query(`UPDATE tenants SET warmup_started_at = COALESCE(warmup_started_at, now()) WHERE id=$1`, [tenant.id]);

    const used = (await query(`
      SELECT count(*) FILTER (WHERE sent_at >= date_trunc('day', now()))::int      AS today,
             count(*) FILTER (WHERE sent_at >= date_trunc('month', now()))::int    AS month
        FROM deliveries WHERE status = 'sent'`, [])).rows[0];

    // tenants.daily_cap is a tenant-wide ceiling, not a per-mailbox one. Applying
    // it per mailbox let a tenant with 3 mailboxes send 3x their stated cap.
    const monthlyLeft = tenant.monthly_cap == null ? Infinity : tenant.monthly_cap - used.month;
    let budget = Math.min(cap - used.today, monthlyLeft);
    if (budget <= 0) return [];

    const counts = new Map();
    const claimed = [];
    for (const row of rows) {
      if (budget <= 0) break;
      const mid = row.mailbox_id;
      if (!counts.has(mid)) {
        const r = await query(
          `SELECT count(*)::int AS n FROM deliveries
            WHERE mailbox_id = $1 AND sent_at >= date_trunc('day', now())`, [mid]);
        counts.set(mid, r.rows[0].n);
      }
      // Respect both the remaining tenant budget and the mailbox's own ceiling.
      const allowed = Math.min(budget, Math.max(0, row.mailbox_cap - counts.get(mid)));
      if (allowed <= 0) continue;
      // Atomic hand-off so two workers cannot send the same lead.
      const c = await query(
        `UPDATE deliveries SET status='sending' WHERE id=$1 AND status='queued' RETURNING id`, [row.id]);
      if (c.rowCount !== 1) continue;
      counts.set(mid, counts.get(mid) + 1);
      claimed.push({ ...row, tenant_id: tenant.id });
      budget--;
    }
    return claimed;
  });
}

async function record(row, ok, error) {
  return withTenant(row.tenant_id, async ({ query }) => {
    if (ok) {
      await query(`UPDATE deliveries SET status='sent', sent_at=now() WHERE id=$1`, [row.id]);
      await query(
        `INSERT INTO events (tenant_id, kind, email, campaign_id) VALUES ($1,'sent',$2,$3)`,
        [row.tenant_id, row.email, row.campaign_id]);
    } else {
      await query(`UPDATE deliveries SET status='failed', error=$2 WHERE id=$1`, [row.id, error]);
    }
  });
}

export async function runOnce() {
  // Enumerate tenants as admin, then do all real work inside withTenant. RLS
  // stays on for the entire send path.
  const tenants = await asAdmin(async ({ query }) =>
    (await query(`SELECT id, daily_cap, monthly_cap, suspended, warmup_started_at
                    FROM tenants WHERE suspended = false`)).rows);

  let sent = 0;
  for (const tenant of tenants) {
    const cap = warmupCap(tenant);
    const claimed = await claimBatch(tenant, cap);
    for (const row of claimed) {
      const unsub = `${PUBLIC_URL}/u/${sign({ t: row.tenant_id, e: row.email }, 60 * 60 * 24 * 365)}`;
      try {
        // Sent outside any transaction: holding a DB transaction open across an
        // SMTP round trip would pin connections and block the pool.
        await transport.sendMail({
          from: { name: row.display_name, address: `${row.local_part}@${row.domain}` },
          to: row.email,
          subject: render(row.subject, row),
          text: render(row.body, row).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(),
          // Must go through `headers`, not top-level options: nodemailer does
          // not map listUnsubscribe* onto real headers, so Gmail and Yahoo
          // would never see them and bulk mail gets refused.
          headers: {
            'List-Unsubscribe': `<${unsub}>, <mailto:unsubscribe@${row.domain}?subject=unsubscribe>`,
            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
            // tenant/delivery, so the bounce webhook can attribute the message
            // without an unscoped lookup that RLS would (correctly) refuse.
            'X-Entity-Ref-ID': `${row.tenant_id}/${row.id}`,
          },
        });
        await record(row, true);
        sent++;
      } catch (e) {
        // ponytail: a crash mid-batch leaves rows stuck in 'sending' forever.
        // Add a reaper that resets stale 'sending' rows when that shows up.
        await record(row, false, e.message);
      }
    }
  }
  return sent;
}

// Test sends deliberately bypass the queue, the caps and the events table: a
// seed mailbox you control must not consume today's quota or skew campaign
// stats. It does not know whether the mail reached the inbox -- that check is
// manual (see the seed-address guidance on /campaigns).
export async function sendTest({ tenantId, campaign, to }) {
  // A seed mailbox has no lead behind it, so merge tags would render as empty
  // and the message would not look like a real campaign. Sample values keep the
  // test representative of what recipients will actually receive.
  const sample = { first_name: 'John', last_name: 'Doe', company: 'Acme', email: to };
  const unsub = `${PUBLIC_URL}/u/${sign({ t: tenantId, e: to }, 60 * 60 * 24 * 365)}`;
  await transport.sendMail({
    from: { name: campaign.display_name, address: campaign.from_email },
    to,
    subject: render(campaign.subject, sample),
    text: render(campaign.body, sample).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(),
    headers: {
      'List-Unsubscribe': `<${unsub}>, <mailto:unsubscribe@${campaign.domain}?subject=unsubscribe>`,
      'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
    },
  });
  return withTenant(tenantId, async ({ query }) => {
    await query(
      `INSERT INTO test_sends (tenant_id, campaign_id, email) VALUES ($1,$2,$3)`,
      [tenantId, campaign.id, to],
    );
  });
}

export async function runForever() {
  for (;;) {
    try {
      await runOnce();
    } catch (e) {
      console.error('[send]', e.message);
    }
    await new Promise((r) => setTimeout(r, Number(process.env.SEND_INTERVAL_MS || 5000)));
  }
}