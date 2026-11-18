import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import test, { beforeEach } from 'node:test';
import type { LambdaConfig } from '../src/lambda/config.ts';
import { type FunctionUrlEvent, handle, safeReturnPath } from '../src/lambda/handler.ts';
import { resetCaches } from '../src/lambda/oidc.ts';
import { verifySession } from '../src/session.ts';
import { DOMAIN, KEY } from './helpers.ts';

const ISSUER = 'https://idp.example.com/pool';
const NOW = Math.floor(Date.now() / 1000);
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

const config: LambdaConfig = {
  domain: DOMAIN,
  issuer: ISSUER,
  clientId: 'client-1',
  authorizationEndpoint: 'https://login.example.com/oauth2/authorize',
  requiredGroup: DOMAIN,
  groupsClaim: 'cognito:groups',
  scopes: ['openid', 'email'],
  sessionSeconds: 86400,
  pathPrefix: '/__access',
  cookieName: '__Host-preview-access',
  signingKeys: [KEY],
};

/** What the fake identity provider puts in the next ID token, and what it received */
let idTokenClaims: Record<string, unknown> = {};
let tokenRequest: URLSearchParams | undefined;

function idToken(claims: Record<string, unknown>) {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const unsigned = `${encode({ alg: 'RS256', kid: 'key-1' })}.${encode(claims)}`;
  return `${unsigned}.${sign('sha256', Buffer.from(unsigned), privateKey).toString('base64url')}`;
}

beforeEach(() => {
  resetCaches();
  tokenRequest = undefined;
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return json({
        authorization_endpoint: 'https://discovered.example.com/authorize',
        token_endpoint: 'https://idp.example.com/token',
        jwks_uri: 'https://idp.example.com/jwks',
      });
    }
    if (url === 'https://idp.example.com/jwks') {
      return json({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'key-1' }] });
    }
    if (url === 'https://idp.example.com/token') {
      tokenRequest = new URLSearchParams(String(init?.body));
      return json({ id_token: idToken(idTokenClaims) });
    }
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
});

/** Runs /login, then the provider's redirect back to /callback with the given claims */
async function signIn(claims: Record<string, unknown>, returnTo = '/page?x=1') {
  const login = await handle(
    config,
    { rawPath: '/__access/login', queryStringParameters: { return: returnTo } },
    NOW,
  );
  const authorize = new URL(login.headers!.location);
  idTokenClaims = {
    iss: ISSUER,
    aud: 'client-1',
    sub: 'user-1',
    email: 'alice@example.com',
    token_use: 'id',
    iat: NOW,
    exp: NOW + 300,
    nonce: authorize.searchParams.get('nonce'),
    'cognito:groups': [DOMAIN],
    ...claims,
  };
  const loginCookie = login.cookies![0].split(';')[0];
  const callback: FunctionUrlEvent = {
    rawPath: '/__access/callback',
    queryStringParameters: { code: 'code-1', state: authorize.searchParams.get('state')! },
    cookies: [loginCookie],
  };
  return { login, authorize, callback: await handle(config, callback, NOW) };
}

function sessionFrom(cookies: string[] | undefined) {
  const session = cookies?.find((cookie) => cookie.startsWith('__Host-preview-access='));
  return session?.split(';')[0].split('=')[1];
}

test('login redirects to the provider with PKCE, state and nonce', async () => {
  const { login, authorize } = await signIn({});
  assert.equal(login.statusCode, 302);
  assert.equal(authorize.origin + authorize.pathname, 'https://login.example.com/oauth2/authorize');
  assert.equal(authorize.searchParams.get('client_id'), 'client-1');
  assert.equal(authorize.searchParams.get('redirect_uri'), `https://${DOMAIN}/__access/callback`);
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  assert.match(
    login.cookies![0],
    /^__Host-preview-access-login=.+; Max-Age=600; Path=\/; Secure; HttpOnly; SameSite=Lax$/,
  );
});

test('a member signs in: the session is valid on this domain and they return to their page', async () => {
  const { authorize, callback } = await signIn({});
  assert.equal(callback.statusCode, 302);
  assert.equal(callback.headers!.location, '/page?x=1');

  const session = sessionFrom(callback.cookies);
  assert.equal(verifySession([KEY], DOMAIN, session!, NOW), 'user-1');

  // The token request proved possession of the PKCE verifier
  const verifier = tokenRequest!.get('code_verifier')!;
  assert.equal(
    createHash('sha256').update(verifier).digest('base64url'),
    authorize.searchParams.get('code_challenge'),
  );
});

test('a signed-in user outside the domain group gets 403 and no session', async () => {
  const { callback } = await signIn({ 'cognito:groups': ['other.example.com'] });
  assert.equal(callback.statusCode, 403);
  assert.match(callback.body!, /alice@example.com doesn't have access to dev.example.com/);
  assert.equal(sessionFrom(callback.cookies), undefined);
});

test('tokens with the wrong issuer, audience, nonce or expiry are rejected', async () => {
  for (const claims of [
    { iss: 'https://evil.example.com' },
    { aud: 'other-client' },
    { nonce: 'other-nonce' },
    { exp: NOW - 120 },
    { token_use: 'access' },
  ]) {
    const { callback } = await signIn(claims);
    assert.equal(callback.statusCode, 400, JSON.stringify(claims));
    assert.equal(sessionFrom(callback.cookies), undefined);
  }
});

test('a callback without its login state starts over instead of signing in', async () => {
  const { callback } = await signIn({});
  const replay = await handle(
    config,
    { rawPath: '/__access/callback', queryStringParameters: { code: 'code-1', state: 'forged' } },
    NOW,
  );
  assert.equal(callback.statusCode, 302);
  assert.equal(replay.statusCode, 302);
  assert.equal(replay.headers!.location, '/__access/login?return=%2F');
});

test('return paths are limited to this site', () => {
  assert.equal(safeReturnPath('/page?x=1'), '/page?x=1');
  for (const value of [
    'https://evil.example.com',
    '//evil.example.com',
    '/\\evil.example.com',
    undefined,
  ]) {
    assert.equal(safeReturnPath(value), '/');
  }
});

test('the authorization endpoint comes from discovery when not configured', async () => {
  const login = await handle(
    { ...config, authorizationEndpoint: undefined },
    { rawPath: '/__access/login' },
    NOW,
  );
  assert.match(login.headers!.location, /^https:\/\/discovered\.example\.com\/authorize\?/);
});

test('logout clears the session', async () => {
  const response = await handle(config, { rawPath: '/__access/logout' }, NOW);
  assert.equal(response.statusCode, 200);
  assert.match(response.cookies![0], /^__Host-preview-access=; Max-Age=0;/);
});
