// Which service actually sends the mail. Everything provider-specific -- SMTP
// settings, DNS records, SPF -- comes from here, so nothing about Amazon is
// hardcoded in the UI. Set MAIL_PROVIDER in .env.
//
// Records assume SPF/DKIM/DMARC on the client's own domain, which is what keeps
// each client's sender reputation separate.

const PROVIDERS = {
  ses: {
    label: 'Amazon SES',
    smtp: { host: 'email-smtp.REGION.amazonaws.com', port: 587 },
    howto: 'Verify the domain in Amazon SES, then publish the records below.',
    verify: { name: '_amazonses.{d}', note: 'Domain verification token from SES' },
    dkim:  { name: 'ses1._domainkey.{d}', note: 'DKIM public key from SES' },
    spf:   'v=spf1 include:amazonses.com ~all',
  },
  postmark: {
    label: 'Postmark',
    smtp: { host: 'smtp.postmarkapp.com', port: 2525 },
    howto: 'Add the domain in Postmark, then publish the records below.',
    verify: null,
    dkim:  { name: 'postmark._domainkey.{d}', note: 'DKIM record from Postmark' },
    spf:   'v=spf1 include:spf.postmarkapp.com ~all',
  },
  mailgun: {
    label: 'Mailgun',
    smtp: { host: 'smtp.mailgun.org', port: 587 },
    howto: 'Add the domain in Mailgun, then publish the records below.',
    verify: { name: 'MAILGUN_TXT.{d}', note: 'Domain verification TXT from Mailgun' },
    dkim:  { name: 'k1._domainkey.{d}', note: 'DKIM records from Mailgun' },
    spf:   'v=spf1 include:mailgun.org ~all',
  },
  smtp: {
    label: 'Your own mail server',
    smtp: null, // falls back to SMTP_HOST / SMTP_PORT
    howto: 'These are the records your own mail server needs. It must have a matching ' +
      'PTR/rDNS record on its sending IP, or Gmail and Outlook will treat it as spam.',
    verify: null,
    dkim:  { name: 'mail._domainkey.{d}', note: 'DKIM key your server signs with' },
    spf:   'v=spf1 a mx ip4:SERVER_IP ~all',
  },
};

const key = () => (process.env.MAIL_PROVIDER || 'ses').toLowerCase();

export const provider = () => {
  const p = PROVIDERS[key()];
  if (!p) throw new Error(`Unknown MAIL_PROVIDER "${key()}". Use: ${Object.keys(PROVIDERS).join(', ')}`);
  return p;
};

// SMTP settings for nodemailer. Explicit SMTP_HOST always wins, so any provider
// (or a relay) works without a code change.
export function smtpSettings() {
  return {
    host: process.env.SMTP_HOST || provider().smtp?.host,
    port: Number(process.env.SMTP_PORT || provider().smtp?.port || 587),
    secure: Number(process.env.SMTP_PORT || 0) === 465,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  };
}

// The records a client must publish for their own domain.
export function dnsRecords(domain) {
  const p = provider();
  const fill = (r) => (r ? { type: 'TXT', name: r.name.replace('{d}', domain), note: r.note } : null);
  return {
    provider: p.label,
    howto: p.howto,
    verify: fill(p.verify),
    dkim: fill(p.dkim),
    dmarc: {
      type: 'TXT',
      name: `_dmarc.${domain}`,
      value: `v=DMARC1; p=none; rua=mailto:dmarc@${domain}`,
    },
    spf: p.spf,
    // Not a DNS record, but the single most common cause of rejection on a
    // self-hosted sender, so it is worth stating outright.
    rdns: p.smtp ? null :
      'Also set a reverse DNS (PTR) record for your sending IP, matching your mail host.',
  };
}