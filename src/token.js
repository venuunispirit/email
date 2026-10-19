import crypto from 'node:crypto';

const SECRET = process.env.APP_SECRET;
if (!SECRET) throw new Error('APP_SECRET is required (openssl rand -hex 32)');

const b64 = (s) => Buffer.from(s).toString('base64url');

export function sign(payload, ttlSeconds = 60 * 60 * 24 * 30) {
  const body = b64(JSON.stringify({ ...payload, exp: Date.now() / 1000 + ttlSeconds }));
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

export function verify(token) {
  const [body, mac] = String(token).split('.');
  if (!body || !mac) return null;
  // Constant-time, and digest both sides first: timingSafeEqual throws on a
  // length mismatch, which a malformed token could otherwise trigger.
  const sha = (s) => crypto.createHash('sha256').update(s).digest();
  if (!crypto.timingSafeEqual(sha(mac), sha(crypto.createHmac('sha256', SECRET).update(body).digest('base64url'))))
    return null;
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
  if (payload.exp < Date.now() / 1000) return null;
  return payload;
}