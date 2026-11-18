import assert from 'node:assert/strict';
import test from 'node:test';
import { signSession, verifySession } from '../src/session.ts';
import { DOMAIN, KEY, PREVIOUS_KEY } from './helpers.ts';

const NOW = 1_800_000_000;

test('a session verifies on its own domain until it expires', () => {
  const cookie = signSession(KEY, DOMAIN, 'user-1', NOW + 60);
  assert.equal(verifySession([KEY], DOMAIN, cookie, NOW), 'user-1');
  assert.equal(verifySession([KEY], DOMAIN, cookie, NOW + 60), undefined);
});

test('a session is rejected on another domain or with another key', () => {
  const cookie = signSession(KEY, DOMAIN, 'user-1', NOW + 60);
  assert.equal(verifySession([KEY], 'other.example.com', cookie, NOW), undefined);
  assert.equal(verifySession([PREVIOUS_KEY], DOMAIN, cookie, NOW), undefined);
});

test('a session signed with the previous key stays valid during a rotation', () => {
  const cookie = signSession(PREVIOUS_KEY, DOMAIN, 'user-1', NOW + 60);
  assert.equal(verifySession([KEY, PREVIOUS_KEY], DOMAIN, cookie, NOW), 'user-1');
});

test('a tampered expiry or subject invalidates the session', () => {
  const [expiresAt, subject, signature] = signSession(KEY, DOMAIN, 'user-1', NOW + 60).split('.');
  assert.equal(
    verifySession([KEY], DOMAIN, `${Number(expiresAt) + 1}.${subject}.${signature}`, NOW),
    undefined,
  );
  const otherSubject = Buffer.from('user-2').toString('base64url');
  assert.equal(
    verifySession([KEY], DOMAIN, `${expiresAt}.${otherSubject}.${signature}`, NOW),
    undefined,
  );
});
