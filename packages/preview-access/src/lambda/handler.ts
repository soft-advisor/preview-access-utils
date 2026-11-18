import { createHash, createHmac, randomBytes } from 'node:crypto';
import { equalStrings, signSession } from '../session.ts';
import { type LambdaConfig, readConfig } from './config.ts';
import { endpoints, exchangeCode, verifyIdToken } from './oidc.ts';

/*
 * The sign-in Lambda, served on <pathPrefix>/* of the protected domain (behind CloudFront, as
 * a Lambda function URL):
 *
 *   /login     starts an OpenID Connect sign-in (authorization code + PKCE)
 *   /callback  receives the result, checks the user's group, sets the session cookie
 *   /logout    clears the session cookie
 */

// How long a started sign-in may take before its state expires
const LOGIN_STATE_SECONDS = 10 * 60;

/** The parts of a Lambda function URL event (payload format 2.0) this handler reads */
export type FunctionUrlEvent = {
  rawPath: string;
  queryStringParameters?: Record<string, string | undefined>;
  cookies?: string[];
};

type Response = {
  statusCode: number;
  headers?: Record<string, string>;
  cookies?: string[];
  body?: string;
};

type LoginState = { state: string; verifier: string; nonce: string; returnTo: string; exp: number };

let configCache: LambdaConfig | undefined;

export async function handler(event: FunctionUrlEvent): Promise<Response> {
  configCache ??= readConfig(process.env);
  return handle(configCache, event, Math.floor(Date.now() / 1000));
}

export async function handle(
  config: LambdaConfig,
  event: FunctionUrlEvent,
  now: number,
): Promise<Response> {
  const path = event.rawPath.slice(config.pathPrefix.length);
  const query = event.queryStringParameters ?? {};
  const cookies = parseCookies(event.cookies);

  try {
    if (path === '/login') return await startLogin(config, query.return, now);
    if (path === '/callback') return await finishLogin(config, query, cookies, now);
    if (path === '/logout') return logout(config);
    return page(404, 'Not found', 'There is nothing here.');
  } catch (error) {
    // Never log tokens or codes, only what went wrong
    console.error('Sign-in failed:', error instanceof Error ? error.message : error);
    return page(400, 'Sign-in failed', 'Something went wrong while signing in.', config);
  }
}

/** Redirects to the provider's sign-in page, remembering the state in a short-lived cookie */
async function startLogin(config: LambdaConfig, returnTo: string | undefined, now: number) {
  const login: LoginState = {
    state: randomBytes(16).toString('base64url'),
    verifier: randomBytes(32).toString('base64url'),
    nonce: randomBytes(16).toString('base64url'),
    returnTo: safeReturnPath(returnTo),
    exp: now + LOGIN_STATE_SECONDS,
  };

  const { authorizationEndpoint } = await endpoints(config);
  const url = new URL(authorizationEndpoint);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: callbackUrl(config),
    scope: config.scopes.join(' '),
    state: login.state,
    nonce: login.nonce,
    code_challenge: createHash('sha256').update(login.verifier).digest('base64url'),
    code_challenge_method: 'S256',
  }).toString();

  return {
    statusCode: 302,
    headers: { location: url.toString(), 'cache-control': 'no-store' },
    cookies: [cookie(loginCookieName(config), signLoginState(config, login), LOGIN_STATE_SECONDS)],
  };
}

/** Verifies the sign-in result and, if the user may access this domain, starts a session */
async function finishLogin(
  config: LambdaConfig,
  query: Record<string, string | undefined>,
  cookies: Map<string, string>,
  now: number,
) {
  const login = readLoginState(config, cookies.get(loginCookieName(config)), now);
  if (!login || !query.state || !equalStrings(query.state, login.state)) {
    // Unknown or expired sign-in, e.g. a bookmarked callback URL: start again
    return redirect(`${config.pathPrefix}/login?return=${encodeURIComponent('/')}`, [
      clearCookie(loginCookieName(config)),
    ]);
  }
  if (!query.code) throw new Error(`No code in callback: ${query.error ?? 'unknown error'}`);

  const idToken = await exchangeCode(config, query.code, login.verifier, callbackUrl(config));
  const claims = await verifyIdToken(config, idToken, login.nonce, now);

  const groups = claims[config.groupsClaim];
  const isMember =
    !config.requiredGroup || (Array.isArray(groups) && groups.includes(config.requiredGroup));
  if (!isMember) {
    const who = typeof claims.email === 'string' ? claims.email : 'This account';
    return page(
      403,
      'No access',
      `${escapeHtml(who)} doesn't have access to ${escapeHtml(config.domain)}. Ask an administrator to grant it.`,
      config,
      [clearCookie(loginCookieName(config))],
    );
  }

  const session = signSession(
    config.signingKeys[0],
    config.domain,
    claims.sub,
    now + config.sessionSeconds,
  );
  return redirect(login.returnTo, [
    cookie(config.cookieName, session, config.sessionSeconds),
    clearCookie(loginCookieName(config)),
  ]);
}

function logout(config: LambdaConfig) {
  return page(200, 'Signed out', `You're signed out of ${escapeHtml(config.domain)}.`, config, [
    clearCookie(config.cookieName),
  ]);
}

function signLoginState(config: LambdaConfig, login: LoginState) {
  const payload = Buffer.from(JSON.stringify(login)).toString('base64url');
  return `${payload}.${loginStateSignature(config.signingKeys[0], payload)}`;
}

function readLoginState(config: LambdaConfig, value: string | undefined, now: number) {
  const [payload, signature] = (value ?? '').split('.');
  if (!payload || !signature) return undefined;
  if (!equalStrings(loginStateSignature(config.signingKeys[0], payload), signature)) {
    return undefined;
  }
  const login = JSON.parse(Buffer.from(payload, 'base64url').toString()) as LoginState;
  return login.exp > now ? login : undefined;
}

function loginStateSignature(key: string, payload: string) {
  return createHmac('sha256', key).update(`login|${payload}`).digest('hex');
}

/** Only same-site paths, so a crafted link can't send users elsewhere after signing in */
export function safeReturnPath(value: string | undefined) {
  const isLocalPath =
    typeof value === 'string' &&
    value.startsWith('/') &&
    !value.startsWith('//') &&
    !value.startsWith('/\\');
  return isLocalPath ? value : '/';
}

function callbackUrl(config: LambdaConfig) {
  return `https://${config.domain}${config.pathPrefix}/callback`;
}

function loginCookieName(config: LambdaConfig) {
  return `${config.cookieName}-login`;
}

function cookie(name: string, value: string, maxAgeSeconds: number) {
  return `${name}=${value}; Max-Age=${maxAgeSeconds}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

function clearCookie(name: string) {
  return cookie(name, '', 0);
}

function parseCookies(cookies: string[] | undefined) {
  const parsed = new Map<string, string>();
  for (const entry of cookies ?? []) {
    const separator = entry.indexOf('=');
    if (separator > 0) parsed.set(entry.slice(0, separator).trim(), entry.slice(separator + 1));
  }
  return parsed;
}

function redirect(location: string, cookies: string[]): Response {
  return { statusCode: 302, headers: { location, 'cache-control': 'no-store' }, cookies };
}

function page(
  statusCode: number,
  title: string,
  message: string,
  config?: LambdaConfig,
  cookies: string[] = [],
): Response {
  const signIn = config ? `<p><a href="${config.pathPrefix}/login">Sign in again</a></p>` : '';
  return {
    statusCode,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    cookies,
    body: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title></head><body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>${title}</h1><p>${message}</p>${signIn}</body></html>`,
  };
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`);
}
