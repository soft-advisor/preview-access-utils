import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_COOKIE_NAME, DEFAULT_SIGNING_KEY_NAME } from '../src/options.ts';
import { signSession } from '../src/session.ts';
import { DOMAIN, KEY, PREVIOUS_KEY, runEdge } from './helpers.ts';

const store = { [DEFAULT_SIGNING_KEY_NAME]: KEY };
const inOneHour = () => Math.floor(Date.now() / 1000) + 3600;
const sessionCookie = (value: string) => ({ [DEFAULT_COOKIE_NAME]: { value } });

test('a request with a valid session reaches the app', async () => {
  const cookies = sessionCookie(signSession(KEY, DOMAIN, 'user-1', inOneHour()));
  const result = await runEdge({ uri: '/page', cookies }, store);
  assert.equal(result.uri, '/page');
});

test('a page load without a session goes to sign-in, keeping the path and query', async () => {
  const result = await runEdge(
    {
      uri: '/page',
      querystring: {
        a: { value: '1' },
        flag: { value: '' },
        b: { value: '2', multiValue: [{ value: '2' }, { value: '3' }] },
      },
    },
    store,
  );
  assert.equal(result.statusCode, 302);
  assert.equal(
    result.headers.location.value,
    `/__access/login?return=${encodeURIComponent('/page?a=1&flag&b=2&b=3')}`,
  );
});

test('other requests without a session get 401', async () => {
  const result = await runEdge({ method: 'POST', uri: '/api/thing' }, store);
  assert.equal(result.statusCode, 401);
});

test('expired, foreign-domain and tampered sessions are rejected', async () => {
  const expired = signSession(KEY, DOMAIN, 'user-1', Math.floor(Date.now() / 1000) - 1);
  const otherDomain = signSession(KEY, 'other.example.com', 'user-1', inOneHour());
  const tampered = `${signSession(KEY, DOMAIN, 'user-1', inOneHour()).slice(0, -1)}0`;
  for (const value of [expired, otherDomain, tampered, 'garbage', '']) {
    const result = await runEdge({ cookies: sessionCookie(value) }, store);
    assert.equal(result.statusCode, 302, value);
  }
});

test('sessions signed with the previous key pass during a rotation', async () => {
  const cookies = sessionCookie(signSession(PREVIOUS_KEY, DOMAIN, 'user-1', inOneHour()));
  const rotating = { ...store, [`${DEFAULT_SIGNING_KEY_NAME}:previous`]: PREVIOUS_KEY };
  assert.equal((await runEdge({ cookies }, rotating)).uri, '/');
  assert.equal((await runEdge({ cookies }, store)).statusCode, 302);
});

test("the sign-in path is never checked, so sign-in can't loop", async () => {
  const result = await runEdge({ uri: '/__access/callback' }, store);
  assert.equal(result.uri, '/__access/callback');
});

test('a missing signing key fails closed', async () => {
  const cookies = sessionCookie(signSession(KEY, DOMAIN, 'user-1', inOneHour()));
  assert.equal((await runEdge({ cookies }, {})).statusCode, 302);
});
