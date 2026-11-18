import {
  DEFAULT_COOKIE_NAME,
  DEFAULT_GROUPS_CLAIM,
  DEFAULT_PATH_PREFIX,
  DEFAULT_SCOPES,
  DEFAULT_SESSION_SECONDS,
} from '../options.ts';

/** The sign-in Lambda's settings, read from its environment variables */
export type LambdaConfig = {
  domain: string;
  issuer: string;
  clientId: string;
  /** Explicit endpoints; when unset they come from the issuer's OpenID discovery document */
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  /** Group the user must be in; unset means any signed-in user is allowed */
  requiredGroup?: string;
  groupsClaim: string;
  scopes: string[];
  sessionSeconds: number;
  pathPrefix: string;
  cookieName: string;
  /** Signing keys, current first. The previous key keeps old sessions valid during a rotation. */
  signingKeys: string[];
};

/** Environment variable names, set by the Pulumi component or by hand */
export const ENV = {
  domain: 'PREVIEW_ACCESS_DOMAIN',
  issuer: 'PREVIEW_ACCESS_ISSUER',
  clientId: 'PREVIEW_ACCESS_CLIENT_ID',
  authorizationEndpoint: 'PREVIEW_ACCESS_AUTHORIZATION_ENDPOINT',
  tokenEndpoint: 'PREVIEW_ACCESS_TOKEN_ENDPOINT',
  requiredGroup: 'PREVIEW_ACCESS_REQUIRED_GROUP',
  groupsClaim: 'PREVIEW_ACCESS_GROUPS_CLAIM',
  scopes: 'PREVIEW_ACCESS_SCOPES',
  sessionSeconds: 'PREVIEW_ACCESS_SESSION_SECONDS',
  pathPrefix: 'PREVIEW_ACCESS_PATH_PREFIX',
  cookieName: 'PREVIEW_ACCESS_COOKIE_NAME',
  signingKey: 'PREVIEW_ACCESS_SIGNING_KEY',
  previousSigningKey: 'PREVIEW_ACCESS_PREVIOUS_SIGNING_KEY',
} as const;

export function readConfig(env: Record<string, string | undefined>): LambdaConfig {
  const required = (name: string) => {
    const value = env[name];
    if (!value) throw new Error(`${name} must be set`);
    return value;
  };
  const optional = (name: string) => env[name] || undefined;

  const signingKeys = [required(ENV.signingKey), optional(ENV.previousSigningKey)].filter(
    (key): key is string => Boolean(key),
  );

  return {
    domain: required(ENV.domain),
    issuer: required(ENV.issuer).replace(/\/$/, ''),
    clientId: required(ENV.clientId),
    authorizationEndpoint: optional(ENV.authorizationEndpoint),
    tokenEndpoint: optional(ENV.tokenEndpoint),
    requiredGroup: optional(ENV.requiredGroup),
    groupsClaim: optional(ENV.groupsClaim) ?? DEFAULT_GROUPS_CLAIM,
    scopes: optional(ENV.scopes)?.split(' ') ?? DEFAULT_SCOPES,
    sessionSeconds: Number(optional(ENV.sessionSeconds) ?? DEFAULT_SESSION_SECONDS),
    pathPrefix: optional(ENV.pathPrefix) ?? DEFAULT_PATH_PREFIX,
    cookieName: optional(ENV.cookieName) ?? DEFAULT_COOKIE_NAME,
    signingKeys,
  };
}
