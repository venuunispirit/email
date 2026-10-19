// Creates a tenant. Run by the agency, never by the app:
//
//   node bin/provision.js "Acme" acme.com
//   node bin/provision.js "Acme" acme.com 200 secret-code
//
// The admin panel at /admin does the same thing in the browser; both call
// createTenant so the two paths cannot drift apart.
import { createTenant } from '../src/db.js';

const [name, domain, cap, code] = process.argv.slice(2);
try {
  const t = await createTenant({ name, domain, dailyCap: cap, accessCode: code });
  console.log(`tenant ${t.id}
domain        ${t.sending_domain}
access code   ${t.accessCode}   (shown once, stored hashed)

Next: have the client add the DNS records listed at /dns in the app.`);
} catch (e) {
  console.error(e.message);
  process.exit(1);
}