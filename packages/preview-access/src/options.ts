/** Settings shared by the edge check and the sign-in Lambda, with their defaults applied */
export type EdgeOptions = {
  /** The protected domain, e.g. dev.example.com. Session cookies are bound to it. */
  domain: string;
  /** Path prefix routed to the sign-in Lambda instead of the app */
  pathPrefix: string;
  /** Name of the session cookie */
  cookieName: string;
  /** Key in the CloudFront KeyValueStore holding the cookie signing key */
  signingKeyName: string;
};

export const DEFAULT_PATH_PREFIX = '/__access';
// The __Host- prefix makes browsers reject the cookie unless it's Secure, host-only and Path=/
export const DEFAULT_COOKIE_NAME = '__Host-preview-access';
export const DEFAULT_SIGNING_KEY_NAME = 'preview-access:signing-key';
// The previous key stays valid during a rotation, so existing sessions survive it
export const PREVIOUS_KEY_SUFFIX = ':previous';
export const DEFAULT_SESSION_SECONDS = 24 * 60 * 60;
// Cognito puts a user's groups in this ID token claim
export const DEFAULT_GROUPS_CLAIM = 'cognito:groups';
export const DEFAULT_SCOPES = ['openid', 'email'];

export function edgeOptions(options: Partial<EdgeOptions> & { domain: string }): EdgeOptions {
  return {
    domain: options.domain,
    pathPrefix: options.pathPrefix ?? DEFAULT_PATH_PREFIX,
    cookieName: options.cookieName ?? DEFAULT_COOKIE_NAME,
    signingKeyName: options.signingKeyName ?? DEFAULT_SIGNING_KEY_NAME,
  };
}
