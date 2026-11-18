import { createHmac, timingSafeEqual } from 'node:crypto';

/*
 * Session cookie format, shared by the sign-in Lambda (which issues it) and the edge check
 * (which verifies it, reimplemented in edge.ts for the CloudFront Functions runtime):
 *
 *   <expiry, unix seconds>.<subject, base64url>.<HMAC-SHA256 hex>
 *
 * The HMAC covers "<domain>|<expiry>|<subject>", so a cookie only works on the domain it was
 * issued for, even if two domains shared a signing key.
 */

export function signSession(key: string, domain: string, subject: string, expiresAt: number) {
  const encodedSubject = Buffer.from(subject).toString('base64url');
  const signature = sessionSignature(key, domain, String(expiresAt), encodedSubject);
  return `${expiresAt}.${encodedSubject}.${signature}`;
}

/** Returns the session's subject if the cookie is valid for this domain and not expired */
export function verifySession(keys: string[], domain: string, cookie: string, now: number) {
  const parts = cookie.split('.');
  if (parts.length !== 3) return undefined;
  const [expiresAt, encodedSubject, signature] = parts;

  const isExpired = !(Number(expiresAt) > now);
  if (isExpired) return undefined;

  const signedByKnownKey = keys.some((key) =>
    equalStrings(sessionSignature(key, domain, expiresAt, encodedSubject), signature),
  );
  if (!signedByKnownKey) return undefined;

  return Buffer.from(encodedSubject, 'base64url').toString();
}

function sessionSignature(key: string, domain: string, expiresAt: string, subject: string) {
  return createHmac('sha256', key).update(`${domain}|${expiresAt}|${subject}`).digest('hex');
}

/** Constant-time comparison, so response timing doesn't reveal how much of a signature matched */
export function equalStrings(a: string, b: string) {
  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);
  return bufferA.length === bufferB.length && timingSafeEqual(bufferA, bufferB);
}
