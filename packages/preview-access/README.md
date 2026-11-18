# @soft-advisor/preview-access

Put a CloudFront-served site, such as a preview or staging environment, behind an OpenID Connect sign-in (e.g. Amazon Cognito), without changing the app.

- **Checked at the edge.** A CloudFront Function checks a signed session cookie on every request, including static assets and API routes, before anything reaches the app.
- **The app is untouched.** Sign-in happens on the identity provider's own domain, and the app only ever sees requests from signed-in users. Its own cookies and `Authorization` headers pass through unchanged.
- **One identity provider for many sites.** Each protected domain has its own app client and, optionally, a group users must belong to. Sites can be in different AWS accounts from the provider; nothing secret crosses accounts.
- **Costs next to nothing.** CloudFront Functions, a KeyValueStore read per request, and a small Lambda that only runs while signing in.

## How it works

1. A request without a valid session cookie is redirected to `/__access/login` (page loads) or gets `401` (other methods).
2. `/__access/*` is routed to the sign-in Lambda. It starts an authorization code flow with PKCE at your provider.
3. After sign-in, the provider redirects to `/__access/callback`. The Lambda exchanges the code, verifies the ID token against the provider's published keys (issuer, audience, expiry, nonce), and checks that the user is in the required group.
4. It sets a 24-hour session cookie (`__Host-preview-access`: `HttpOnly`, `Secure`, `SameSite=Lax`, host-only), HMAC-signed with a key held in a CloudFront KeyValueStore, and sends the user back to the page they asked for.

Users outside the group get a 403 page. `/__access/logout` clears the session. Removing someone from a group stops new sign-ins; an existing session lasts until its cookie expires.

## Identity provider setup

Per protected domain, the provider needs a **public app client** (no client secret) with:

- the authorization code flow, with PKCE
- scopes `openid` (and `email` for nicer error pages)
- callback URL `https://<domain>/__access/callback`

For Amazon Cognito, users in a group named after the domain get in by default (the `cognito:groups` claim). With other providers, set `groupsClaim` and `requiredGroup`, or `requiredGroup: null` to allow any signed-in user.

## Usage

### SST (`sst.aws.Nextjs` and other CloudFront site components)

```ts
// Inside run(), importing the package there too, as SST recommends
const { createPreviewAccess } = await import('@soft-advisor/preview-access/pulumi');
const { previewAccessSiteArgs } = await import('@soft-advisor/preview-access/sst');

const access = await createPreviewAccess('Access', {
  domain: 'dev.example.com',
  issuer: 'https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_abc123',
  clientId: '1example23456789',
  // Optional: use your custom Cognito domain instead of the discovered one
  authorizationEndpoint: 'https://login.example.com/oauth2/authorize',
  tokenEndpoint: 'https://login.example.com/oauth2/token',
});

const web = new sst.aws.Nextjs('Web', {
  ...previewAccessSiteArgs(access),
  domain: 'dev.example.com',
});
access.allowDistribution(web.nodes.cdn.nodes.distribution.arn);
```

The check runs first in SST's own viewer-request function, and SST stores its routing data in the same KeyValueStore. If your site already sets `edge.viewerRequest.injection` or `transform.cdn`, combine them, keeping the access injection first.

### Pulumi, with your own CloudFront distribution

```ts
import { createPreviewAccess } from '@soft-advisor/preview-access/pulumi';

const access = await createPreviewAccess('Access', { domain, issuer, clientId });

const viewerRequest = new aws.cloudfront.Function('ViewerRequest', {
  runtime: 'cloudfront-js-2.0',
  code: access.viewerRequestFunction,
  keyValueStoreAssociations: [access.kvStore.arn],
  publish: true,
});

const distributionArgs: aws.cloudfront.DistributionArgs = {
  origins: [appOrigin],
  defaultCacheBehavior: {
    // ...your app's behavior, plus:
    functionAssociations: [{ eventType: 'viewer-request', functionArn: viewerRequest.arn }],
  },
  // ...
};
// Adds the sign-in origin and its cache behavior (or use access.origin and access.cacheBehavior)
access.addSignInRoute(distributionArgs);
const distribution = new aws.cloudfront.Distribution('Site', distributionArgs);
access.allowDistribution(distribution.arn);
```

Associate the viewer-request function with every cache behavior except `access.cacheBehavior`.

### Other tools (CDK, Terraform, the console)

- `@soft-advisor/preview-access` exports `viewerRequestFunction(options)` and `viewerRequestInjection(options)`, which return the CloudFront Function code as a string.
- `@soft-advisor/preview-access/lambda` exports `lambdaCode`, the sign-in Lambda as a single ES module (save it as `index.mjs`, handler `index.handler`, Node.js 22+), and `ENV`, its environment variable names.

Store a random signing key (e.g. 32 random bytes, hex) in the KeyValueStore under `preview-access:signing-key`, and give the same value to the Lambda as `PREVIEW_ACCESS_SIGNING_KEY`. Serve the Lambda through a function URL with `AWS_IAM` auth and CloudFront origin access control.

## `createPreviewAccess` options

| Option                                   | Default                              |                                               |
| ---------------------------------------- | ------------------------------------ | --------------------------------------------- |
| `domain`                                 | required                             | The protected domain; cookies are bound to it |
| `issuer`                                 | required                             | OpenID Connect issuer URL                     |
| `clientId`                               | required                             | The domain's public app client                |
| `authorizationEndpoint`, `tokenEndpoint` | from the issuer's discovery document |                                               |
| `requiredGroup`                          | the domain                           | `null` allows any signed-in user              |
| `groupsClaim`                            | `cognito:groups`                     | ID token claim listing the user's groups      |
| `scopes`                                 | `["openid", "email"]`                |                                               |
| `sessionSeconds`                         | `86400` (24 hours)                   |                                               |
| `pathPrefix`                             | `/__access`                          | Must not be used by the app                   |
| `cookieName`                             | `__Host-preview-access`              |                                               |

`@pulumi/pulumi` and `@pulumi/aws` (6.57 or later) are optional peer dependencies: the component uses your project's copies, or SST's under SST. They're loaded with dynamic imports when `createPreviewAccess` runs, never when the package is imported, so bundlers (e.g. SST's) can't hoist them to where they aren't installed yet.

## Rotating the signing key

The edge check also accepts the key stored under `preview-access:signing-key:previous`, and the Lambda the one in `PREVIEW_ACCESS_PREVIOUS_SIGNING_KEY`. To rotate without signing everyone out, copy the current key there, then replace the current key (e.g. by recreating the component's `signing-key` resource). Remove the previous key after one session lifetime. Replacing the key without that step signs everyone out, which is also a way to revoke all sessions at once.

## Security notes

- Meant for nonproduction environments, as an extra layer in front of the app's own security, not a replacement for it.
- Sessions can't be revoked individually before they expire; shorten `sessionSeconds` if that matters.
- The KeyValueStore and the Lambda's environment hold the signing key, so anyone who can read them in the AWS account can forge sessions for that domain.
