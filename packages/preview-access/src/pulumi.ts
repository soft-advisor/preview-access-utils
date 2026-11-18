import { randomBytes } from 'node:crypto';
import * as aws from '@pulumi/aws';
import * as pulumi from '@pulumi/pulumi';
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
const LAMBDA_RUNTIME = 'nodejs22.x';
const LAMBDA_TIMEOUT_SECONDS = 10;
const LOG_RETENTION_DAYS = 14;
const SIGNING_KEY_BYTES = 32;

export type PreviewAccessArgs = {
  /** The protected domain, e.g. dev.example.com */
  domain: pulumi.Input<string>;
  /** OpenID Connect issuer, e.g. https://cognito-idp.<region>.amazonaws.com/<user pool ID> */
  issuer: pulumi.Input<string>;
  /** The domain's app client ID at the provider: public, with the authorization code flow and PKCE */
  clientId: pulumi.Input<string>;
  /** Defaults to the issuer's discovery document; set it to use e.g. a custom sign-in domain */
  authorizationEndpoint?: pulumi.Input<string>;
  /** Defaults to the issuer's discovery document */
  tokenEndpoint?: pulumi.Input<string>;
  /**
   * Group a user must be in to open the domain, read from the ID token's `groupsClaim`.
   * Defaults to the domain itself; `null` allows any signed-in user.
   */
  requiredGroup?: pulumi.Input<string> | null;
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

/**
 * Protects a CloudFront-served site with an OpenID Connect sign-in. Creates the sign-in Lambda
 * (as a function URL behind CloudFront), a KeyValueStore holding the cookie signing key, and
 * the edge check's code. Wire it into a distribution with `origin`, `cacheBehavior` and either
 * `viewerRequestInjection` (an existing viewer-request function) or `viewerRequestFunction`,
 * then call `allowDistribution` with the distribution's ARN.
 */
export class PreviewAccess extends pulumi.ComponentResource {
  /** KeyValueStore the edge check reads the signing key from */
  readonly kvStore: aws.cloudfront.KeyValueStore;
  readonly function: aws.lambda.Function;
  readonly functionUrl: aws.lambda.FunctionUrl;
  readonly originAccessControl: aws.cloudfront.OriginAccessControl;
  /** Code to inject into an existing viewer-request function, e.g. SST's `edge.viewerRequest.injection` */
  readonly viewerRequestInjection: pulumi.Output<string>;
  /** A complete viewer-request function, for distributions without their own */
  readonly viewerRequestFunction: pulumi.Output<string>;
  /** CloudFront origin for the sign-in Lambda */
  readonly origin: pulumi.Output<aws.types.input.cloudfront.DistributionOrigin>;
  /** Cache behavior routing `<pathPrefix>/*` to the sign-in Lambda, uncached and unchecked */
  readonly cacheBehavior: pulumi.Output<aws.types.input.cloudfront.DistributionOrderedCacheBehavior>;
  readonly originId: string;
  readonly pathPrefix: string;

  private readonly componentName: string;

  constructor(name: string, args: PreviewAccessArgs, opts?: pulumi.ComponentResourceOptions) {
    super('soft-advisor:preview-access:PreviewAccess', name, {}, opts);
    this.componentName = name;
    this.pathPrefix = args.pathPrefix ?? DEFAULT_PATH_PREFIX;
    this.originId = `${name}-sign-in`;
    const cookieName = args.cookieName ?? DEFAULT_COOKIE_NAME;
    const parent = { parent: this };

    this.kvStore = new aws.cloudfront.KeyValueStore(
      `${name}-kv-store`,
      { comment: 'Cookie signing key for @soft-advisor/preview-access' },
      parent,
    );

    // A random key, generated once: later runs generate a new value, which ignoreChanges discards.
    // To rotate, see the README.
    const signingKey = new aws.cloudfront.KeyvaluestoreKey(
      `${name}-signing-key`,
      {
        keyValueStoreArn: this.kvStore.arn,
        key: DEFAULT_SIGNING_KEY_NAME,
        value: pulumi.secret(randomBytes(SIGNING_KEY_BYTES).toString('hex')),
      },
      { ...parent, ignoreChanges: ['value'], additionalSecretOutputs: ['value'] },
    );

    const role = new aws.iam.Role(
      `${name}-role`,
      {
        assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({ Service: 'lambda.amazonaws.com' }),
      },
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
    this.function = new aws.lambda.Function(
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
            [ENV.pathPrefix]: this.pathPrefix,
            [ENV.cookieName]: cookieName,
            [ENV.signingKey]: signingKey.value,
          },
        },
      },
      parent,
    );

    // Only CloudFront, signing requests through the origin access control, can call it
    this.functionUrl = new aws.lambda.FunctionUrl(
      `${name}-sign-in-url`,
      { functionName: this.function.name, authorizationType: 'AWS_IAM' },
      parent,
    );

    this.originAccessControl = new aws.cloudfront.OriginAccessControl(
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
      .apply((domain) => ({ domain, pathPrefix: this.pathPrefix, cookieName }));
    this.viewerRequestInjection = edgeOptions.apply(viewerRequestInjection);
    this.viewerRequestFunction = edgeOptions.apply(viewerRequestFunction);

    this.origin = pulumi
      .all([this.functionUrl.functionUrl, this.originAccessControl.id])
      .apply(([url, originAccessControlId]) => ({
        originId: this.originId,
        domainName: new URL(url).hostname,
        originAccessControlId,
        customOriginConfig: {
          httpPort: 80,
          httpsPort: 443,
          originProtocolPolicy: 'https-only',
          originSslProtocols: ['TLSv1.2'],
        },
      }));

    this.cacheBehavior = pulumi.output({
      pathPattern: `${this.pathPrefix}/*`,
      targetOriginId: this.originId,
      viewerProtocolPolicy: 'redirect-to-https',
      allowedMethods: ['GET', 'HEAD'],
      cachedMethods: ['GET', 'HEAD'],
      compress: true,
      cachePolicyId: CACHING_DISABLED_POLICY_ID,
      originRequestPolicyId: ALL_VIEWER_EXCEPT_HOST_HEADER_POLICY_ID,
    });

    this.registerOutputs({
      kvStoreArn: this.kvStore.arn,
      functionArn: this.function.arn,
    });
  }

  /** Lets the given CloudFront distribution invoke the sign-in Lambda */
  allowDistribution(distributionArn: pulumi.Input<string>) {
    const parent = { parent: this };
    new aws.lambda.Permission(
      `${this.componentName}-allow-cloudfront-url`,
      {
        action: 'lambda:InvokeFunctionUrl',
        function: this.function.name,
        principal: 'cloudfront.amazonaws.com',
        sourceArn: distributionArn,
        functionUrlAuthType: 'AWS_IAM',
      },
      parent,
    );
    // Function URLs also require lambda:InvokeFunction for the caller
    new aws.lambda.Permission(
      `${this.componentName}-allow-cloudfront-invoke`,
      {
        action: 'lambda:InvokeFunction',
        function: this.function.name,
        principal: 'cloudfront.amazonaws.com',
        sourceArn: distributionArn,
      },
      parent,
    );
  }
}
