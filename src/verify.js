import dns from 'node:dns/promises';
import net from 'node:net';

// A dead domain (gmial.com) is the biggest single source of hard bounces, and
// catching it costs one DNS lookup. Role addresses (info@, sales@) are usually
// a gatekeeper with no interest in cold outreach.
const SYNTAX = /^[^\s@,;<>()[\]\\\s]+@[^\s@,;<>()[\]\\\s]+\.[a-z]{2,}$/i;
const ROLE = /^(admin|info|support|sales|contact|help|office|postmaster|hostmaster|webmaster|abuse|marketing)@/i;

export const domainOf = (email) => email.trim().toLowerCase().split('@').pop();

export function classify(email) {
  const e = String(email).trim().toLowerCase();
  if (!SYNTAX.test(e)) return 'invalid';
  if (ROLE.test(e)) return 'risky';
  return 'unknown';
}

export async function hasMx(domain) {
  if (!domain || net.isIP(domain)) return false;
  try {
    // resolveMx is stdlib: no API key, no third-party service, no per-check cost.
    return (await dns.resolveMx(domain)).length > 0;
  } catch {
    return false;
  }
}

// Bounded concurrency: a 50k-row CSV would otherwise open thousands of sockets
// at once and get the app's own hostname rate-limited mid-import.
async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (let i = next++; i < items.length; i = next++) out[i] = await fn(items[i]);
  }));
  return out;
}

// One DNS answer per domain, not per row: a 10k-lead list is usually a few
// hundred domains, and they do not change between rows of one import.
export async function verifyEmails(emails, { concurrency = 12 } = {}) {
  const rows = emails.map((email) => [String(email).trim().toLowerCase(), classify(email)]);
  const domains = [...new Set(rows.filter(([, s]) => s !== 'invalid').map(([e]) => domainOf(e)))];

  const out = await pool(domains, concurrency, hasMx);
  const mx = new Map(domains.map((d, i) => [d, out[i]]));

  return rows.map(([email, status]) => {
    if (status === 'invalid') return [email, 'invalid'];
    // Only a confirmed lack of MX disqualifies an address. A transient DNS
    // failure leaves it unknown rather than silently deleting a real lead.
    if (!mx.get(domainOf(email))) return [email, 'invalid'];
    return [email, status === 'risky' ? 'risky' : 'valid'];
  });
}