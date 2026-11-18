import { createPublicKey, type JsonWebKey, verify } from 'node:crypto';
import type { LambdaConfig } from './config.ts';

// Tolerated clock difference between this Lambda and the identity provider
const CLOCK_SKEW_SECONDS = 60;
// Only asymmetric algorithms: a token signed with anything else is rejected outright
const ALGORITHMS = {
  RS256: { hash: 'sha256', dsaEncoding: undefined },
  ES256: { hash: 'sha256', dsaEncoding: 'ieee-p1363' },
} as const;

type Endpoints = { authorizationEndpoint: string; tokenEndpoint: string; jwksUri: string };
type Jwk = JsonWebKey & { kid?: string };
export type IdTokenClaims = Record<string, unknown> & { sub: string };

// Cached between invocations of a warm Lambda
let endpointsCache: Promise<Endpoints> | undefined;
let keysCache: { keys: Map<string, Jwk>; fetchedAt: number } | undefined;
// Refetch keys at most this often when a token names an unknown key (e.g. after rotation)
const KEY_REFRESH_SECONDS = 300;

/** The provider's endpoints: explicit config first, then its OpenID discovery document */
export function endpoints(config: LambdaConfig): Promise<Endpoints> {
  endpointsCache ??= discover(config).catch((error) => {
    endpointsCache = undefined;
    throw error;
  });
  return endpointsCache;
}

async function discover(config: LambdaConfig): Promise<Endpoints> {
  const response = await fetch(`${config.issuer}/.well-known/openid-configuration`);
  if (!response.ok) throw new Error(`OpenID discovery failed: ${response.status}`);
  const document = (await response.json()) as Record<string, string>;
  return {
    authorizationEndpoint: config.authorizationEndpoint ?? document.authorization_endpoint,
    tokenEndpoint: config.tokenEndpoint ?? document.token_endpoint,
    jwksUri: document.jwks_uri,
  };
}

/** Exchanges the authorization code (with its PKCE verifier) for the user's ID token */
export async function exchangeCode(
  config: LambdaConfig,
  code: string,
  codeVerifier: string,
  redirectUri: string,
) {
  const { tokenEndpoint } = await endpoints(config);
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: config.clientId,
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
    }),
  });
  if (!response.ok) throw new Error(`Token exchange failed: ${response.status}`);
  const tokens = (await response.json()) as { id_token?: string };
  if (!tokens.id_token) throw new Error('Token response has no id_token');
  return tokens.id_token;
}

/**
 * Verifies an ID token's signature against the issuer's published keys, then its issuer,
 * audience, expiry and nonce. Throws if anything doesn't match.
 */
export async function verifyIdToken(
  config: LambdaConfig,
  token: string,
  nonce: string,
  now: number,
): Promise<IdTokenClaims> {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
  if (!encodedSignature) throw new Error('Malformed token');

  const header = decodeJson(encodedHeader);
  const algorithm = ALGORITHMS[header.alg as keyof typeof ALGORITHMS];
  if (!algorithm) throw new Error(`Unsupported token algorithm: ${String(header.alg)}`);

  const jwk = await signingKey(config, String(header.kid));
  const signatureIsValid = verify(
    algorithm.hash,
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: algorithm.dsaEncoding },
    Buffer.from(encodedSignature, 'base64url'),
  );
  if (!signatureIsValid) throw new Error('Invalid token signature');

  const claims = decodeJson(encodedPayload) as IdTokenClaims;
  checkClaims(config, claims, nonce, now);
  return claims;
}

function checkClaims(config: LambdaConfig, claims: IdTokenClaims, nonce: string, now: number) {
  if (claims.iss !== config.issuer) throw new Error('Token issuer mismatch');

  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(config.clientId)) throw new Error('Token audience mismatch');

  const isExpired = !(Number(claims.exp) + CLOCK_SKEW_SECONDS > now);
  if (isExpired) throw new Error('Token expired');

  const isIssuedInFuture = Number(claims.iat) - CLOCK_SKEW_SECONDS > now;
  if (isIssuedInFuture) throw new Error('Token issued in the future');

  if (claims.nonce !== nonce) throw new Error('Token nonce mismatch');

  // Cognito marks ID tokens; other providers don't set token_use
  const isNotIdToken = claims.token_use !== undefined && claims.token_use !== 'id';
  if (isNotIdToken) throw new Error('Not an ID token');

  if (typeof claims.sub !== 'string' || !claims.sub) throw new Error('Token has no subject');
}

/** Finds the key that signed a token, refetching the issuer's keys if it's new */
async function signingKey(config: LambdaConfig, kid: string) {
  const cached = keysCache?.keys.get(kid);
  if (cached) return cached;

  const canRefresh = !keysCache || Date.now() / 1000 - keysCache.fetchedAt > KEY_REFRESH_SECONDS;
  if (!canRefresh) throw new Error(`Unknown signing key: ${kid}`);

  const { jwksUri } = await endpoints(config);
  const response = await fetch(jwksUri);
  if (!response.ok) throw new Error(`Fetching signing keys failed: ${response.status}`);
  const { keys } = (await response.json()) as { keys: Jwk[] };
  keysCache = {
    keys: new Map(keys.map((key) => [String(key.kid), key])),
    fetchedAt: Date.now() / 1000,
  };

  const key = keysCache.keys.get(kid);
  if (!key) throw new Error(`Unknown signing key: ${kid}`);
  return key;
}

function decodeJson(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, 'base64url').toString());
}

/** Clears cached endpoints and keys; for tests */
export function resetCaches() {
  endpointsCache = undefined;
  keysCache = undefined;
}
