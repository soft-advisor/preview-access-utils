import { randomBytes } from 'node:crypto';
// Types only: the Pulumi packages are loaded with dynamic imports when the component is created,
// so importing this module never loads them. Bundlers such as SST's hoist static imports of
// external packages to the top of the bundle, where they'd run before SST installs its own.
import type * as Aws from '@pulumi/aws';
import type * as Pulumi from '@pulumi/pulumi';
import { viewerRequestFunction, viewerRequestInjection } from './edge.ts';
import { lambdaCode } from './generated/lambda-code.ts';
import { ENV } from './lambda/config.ts';
import {
  DEFAULT_COOKIE_NAME,
  DEFAULT_GROUPS_CLAIM,
  DEFAULT_PATH_PREFIX,
  DEFAULT_SCOPES,
  DEFAULT_SESSION_SECONDS,
  DEFAULT_SIGNING_KEY_NAME,
} from './options.ts';

// AWS managed CloudFront policies
const CACHING_DISABLED_POLICY_ID = '4135ea2d-6df8-44a3-9df3-4b5a84be39ad';
const ALL_VIEWER_EXCEPT_HOST_HEADER_POLICY_ID = 'b689b0a8-53d0-40ab-baf2-68738e2966ac';
const COMPONENT_TYPE = 'soft-advisor:preview-access:PreviewAccess';
const LAMBDA_RUNTIME = 'nodejs22.x';
const LAMBDA_TIMEOUT_SECONDS = 10;
const LOG_RETENTION_DAYS = 14;
const SIGNING_KEY_BYTES = 32;

type Origin = Aws.types.input.cloudfront.DistributionOrigin;
type CacheBehavior = Aws.types.input.cloudfront.DistributionOrderedCacheBehavior;

export type PreviewAccessArgs = {
  /** The protected domain, e.g. dev.example.com */
  domain: Pulumi.Input<string>;
  /** OpenID Connect issuer, e.g. https://cognito-idp.<region>.amazonaws.com/<user pool ID> */
  issuer: Pulumi.Input<string>;
  /** The domain's app client ID at the provider: public, with the authorization code flow and PKCE */
  clientId: Pulumi.Input<string>;
  /** Defaults to the issuer's discovery document; set it to use e.g. a custom sign-in domain */
  authorizationEndpoint?: Pulumi.Input<string>;
  /** Defaults to the issuer's discovery document */
  tokenEndpoint?: Pulumi.Input<string>;
  /**
   * Group a user must be in to open the domain, read from the ID token's `groupsClaim`.
   * Defaults to the domain itself; `null` allows any signed-in user.
   */
  requiredGroup?: Pulumi.Input<string> | null;
  /** ID token claim listing the user's groups. Default: `cognito:groups` */
  groupsClaim?: string;
  /** Scopes to request. Default: `openid email` */
  scopes?: string[];
  /** Session cookie lifetime. Default: 24 hours */
  sessionSeconds?: number;
  /** Path prefix routed to the sign-in Lambda. Default: `/__access` */
  pathPrefix?: string;
  /** Session cookie name. Default: `__Host-preview-access` */
  cookieName?: string;
};

/** The resources protecting one site, and what's needed to wire them into its distribution */
export type PreviewAccess = {
  /** Parent of every resource below */
  component: Pulumi.ComponentResource;
  /** KeyValueStore the edge check reads the signing key from */
  kvStore: Aws.cloudfront.KeyValueStore;
  function: Aws.lambda.Function;
  functionUrl: Aws.lambda.FunctionUrl;
  originAccessControl: Aws.cloudfront.OriginAccessControl;
  /** Code to inject into an existing viewer-request function, e.g. SST's `edge.viewerRequest.injection` */
  viewerRequestInjection: Pulumi.Output<string>;
  /** A complete viewer-request function, for distributions without their own */
  viewerRequestFunction: Pulumi.Output<string>;
  /** CloudFront origin for the sign-in Lambda */
  origin: Pulumi.Output<Origin>;
  /** Cache behavior routing `<pathPrefix>/*` to the sign-in Lambda, uncached and unchecked */
  cacheBehavior: Pulumi.Output<CacheBehavior>;
  pathPrefix: string;
  /** Adds the sign-in origin and cache behavior to CloudFront distribution args, in place */
  addSignInRoute(args: DistributionRouteArgs): void;
  /** Lets the given CloudFront distribution invoke the sign-in Lambda */
  allowDistribution(distributionArn: Pulumi.Input<string>): void;
};

/** The parts of CloudFront distribution args that `addSignInRoute` changes */
export type DistributionRouteArgs = {
  origins: Pulumi.Input<Pulumi.Input<object>[]>;
  orderedCacheBehaviors?: Pulumi.Input<Pulumi.Input<object>[]>;
};

/**
 * Protects a CloudFront-served site with an OpenID Connect sign-in. Creates the sign-in Lambda
 * (as a function URL behind CloudFront), a KeyValueStore holding the cookie signing key, and
 * the edge check's code. Wire it into a distribution with `addSignInRoute` (or `origin` and
 * `cacheBehavior`) and `viewerRequestInjection` or `viewerRequestFunction`, then call
 * `allowDistribution` with the distribution's ARN.
 */
export async function createPreviewAccess(
  name: string,
  args: PreviewAccessArgs,
  opts?: Pulumi.ComponentResourceOptions,
): Promise<PreviewAccess> {
  const pulumi = await import('@pulumi/pulumi');
  const aws = await import('@pulumi/aws');

  const pathPrefix = args.pathPrefix ?? DEFAULT_PATH_PREFIX;
  const cookieName = args.cookieName ?? DEFAULT_COOKIE_NAME;
  const originId = `${name}-sign-in`;
  // A subclass only to reach registerOutputs, which is protected
  class PreviewAccessComponent extends pulumi.ComponentResource {
    complete(outputs: Pulumi.Inputs) {
      this.registerOutputs(outputs);
    }
  }
  const component = new PreviewAccessComponent(COMPONENT_TYPE, name, {}, opts);
  const parent = { parent: component };

  const kvStore = new aws.cloudfront.KeyValueStore(
    `${name}-kv-store`,
    { comment: 'Cookie signing key for @soft-advisor/preview-access' },
    parent,
  );

  // A random key, generated once: later runs generate a new value, which ignoreChanges discards.
  // To rotate, see the README.
  const signingKey = new aws.cloudfront.KeyvaluestoreKey(
    `${name}-signing-key`,
    {
      keyValueStoreArn: kvStore.arn,
      key: DEFAULT_SIGNING_KEY_NAME,
      value: pulumi.secret(randomBytes(SIGNING_KEY_BYTES).toString('hex')),
    },
    { ...parent, ignoreChanges: ['value'], additionalSecretOutputs: ['value'] },
  );

  const role = new aws.iam.Role(
    `${name}-role`,
    { assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({ Service: 'lambda.amazonaws.com' }) },
    parent,
  );
  new aws.iam.RolePolicyAttachment(
    `${name}-role-logs`,
    { role: role.name, policyArn: aws.iam.ManagedPolicy.AWSLambdaBasicExecutionRole },
    parent,
  );

  const logGroup = new aws.cloudwatch.LogGroup(
    `${name}-logs`,
    { retentionInDays: LOG_RETENTION_DAYS },
    parent,
  );

  const requiredGroup = args.requiredGroup === null ? '' : (args.requiredGroup ?? args.domain);
  const signInFunction = new aws.lambda.Function(
    `${name}-sign-in`,
    {
      runtime: LAMBDA_RUNTIME,
      handler: 'index.handler',
      role: role.arn,
      timeout: LAMBDA_TIMEOUT_SECONDS,
      code: new pulumi.asset.AssetArchive({
        'index.mjs': new pulumi.asset.StringAsset(lambdaCode),
      }),
      loggingConfig: { logFormat: 'Text', logGroup: logGroup.name },
      environment: {
        variables: {
          [ENV.domain]: args.domain,
          [ENV.issuer]: args.issuer,
          [ENV.clientId]: args.clientId,
          [ENV.authorizationEndpoint]: args.authorizationEndpoint ?? '',
          [ENV.tokenEndpoint]: args.tokenEndpoint ?? '',
          [ENV.requiredGroup]: requiredGroup,
          [ENV.groupsClaim]: args.groupsClaim ?? DEFAULT_GROUPS_CLAIM,
          [ENV.scopes]: (args.scopes ?? DEFAULT_SCOPES).join(' '),
          [ENV.sessionSeconds]: String(args.sessionSeconds ?? DEFAULT_SESSION_SECONDS),
          [ENV.pathPrefix]: pathPrefix,
          [ENV.cookieName]: cookieName,
          [ENV.signingKey]: signingKey.value,
        },
      },
    },
    parent,
  );

  // Only CloudFront, signing requests through the origin access control, can call it
  const functionUrl = new aws.lambda.FunctionUrl(
    `${name}-sign-in-url`,
    { functionName: signInFunction.name, authorizationType: 'AWS_IAM' },
    parent,
  );

  const originAccessControl = new aws.cloudfront.OriginAccessControl(
    `${name}-sign-in-oac`,
    {
      description: 'Sign-in Lambda of @soft-advisor/preview-access',
      originAccessControlOriginType: 'lambda',
      signingBehavior: 'always',
      signingProtocol: 'sigv4',
    },
    parent,
  );

  const edgeOptions = pulumi
    .output(args.domain)
    .apply((domain) => ({ domain, pathPrefix, cookieName }));

  const origin = pulumi.all([functionUrl.functionUrl, originAccessControl.id]).apply(
    ([url, originAccessControlId]): Origin => ({
      originId,
      domainName: new URL(url).hostname,
      originAccessControlId,
      customOriginConfig: {
        httpPort: 80,
        httpsPort: 443,
        originProtocolPolicy: 'https-only',
        originSslProtocols: ['TLSv1.2'],
      },
    }),
  );

  const cacheBehavior = pulumi.output<CacheBehavior>({
    pathPattern: `${pathPrefix}/*`,
    targetOriginId: originId,
    viewerProtocolPolicy: 'redirect-to-https',
    allowedMethods: ['GET', 'HEAD'],
    cachedMethods: ['GET', 'HEAD'],
    compress: true,
    cachePolicyId: CACHING_DISABLED_POLICY_ID,
    originRequestPolicyId: ALL_VIEWER_EXCEPT_HOST_HEADER_POLICY_ID,
  });

  function addSignInRoute(distributionArgs: DistributionRouteArgs) {
    distributionArgs.origins = pulumi
      .all([distributionArgs.origins, origin])
      .apply(([origins, signInOrigin]) => [...origins, signInOrigin]);
    // First, so the app's own path patterns can't shadow the sign-in path
    distributionArgs.orderedCacheBehaviors = pulumi
      .all([distributionArgs.orderedCacheBehaviors ?? [], cacheBehavior])
      .apply(([behaviors, signInBehavior]) => [signInBehavior, ...behaviors]);
  }

  function allowDistribution(distributionArn: Pulumi.Input<string>) {
    new aws.lambda.Permission(
      `${name}-allow-cloudfront-url`,
      {
        action: 'lambda:InvokeFunctionUrl',
        function: signInFunction.name,
        principal: 'cloudfront.amazonaws.com',
        sourceArn: distributionArn,
        functionUrlAuthType: 'AWS_IAM',
      },
      parent,
    );
    // Function URLs also require lambda:InvokeFunction for the caller
    new aws.lambda.Permission(
      `${name}-allow-cloudfront-invoke`,
      {
        action: 'lambda:InvokeFunction',
        function: signInFunction.name,
        principal: 'cloudfront.amazonaws.com',
        sourceArn: distributionArn,
      },
      parent,
    );
  }

  component.complete({ kvStoreArn: kvStore.arn, functionArn: signInFunction.arn });

  return {
    component,
    kvStore,
    function: signInFunction,
    functionUrl,
    originAccessControl,
    viewerRequestInjection: edgeOptions.apply(viewerRequestInjection),
    viewerRequestFunction: edgeOptions.apply(viewerRequestFunction),
    origin,
    cacheBehavior,
    pathPrefix,
    addSignInRoute,
    allowDistribution,
  };
}
