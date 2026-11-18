import * as pulumi from '@pulumi/pulumi';
import type { PreviewAccess } from './pulumi.ts';

/** The subset of SST's CDN component args (`transform.cdn`) this adapter changes */
type CdnArgs = {
  origins: pulumi.Input<pulumi.Input<object>[]>;
  orderedCacheBehaviors?: pulumi.Input<pulumi.Input<object>[]>;
};

/**
 * Settings for an SST site component that renders through CloudFront, such as
 * `sst.aws.Nextjs`: the edge check runs first in SST's own viewer-request function, and
 * `<pathPrefix>/*` routes to the sign-in Lambda.
 *
 *   const access = new PreviewAccess("Access", { domain, issuer, clientId });
 *   const web = new sst.aws.Nextjs("Web", { ...previewAccessSiteArgs(access), ... });
 *   access.allowDistribution(web.nodes.cdn.nodes.distribution.arn);
 *
 * If the site already sets `edge.viewerRequest.injection` or `transform.cdn`, combine them:
 * the access injection must come first.
 */
export function previewAccessSiteArgs(access: PreviewAccess) {
  return {
    edge: {
      viewerRequest: {
        injection: access.viewerRequestInjection,
        // SST keeps its routing data in this store too, under its own namespace
        kvStore: access.kvStore.arn,
      },
    },
    transform: {
      cdn: (args: CdnArgs) => addSignInRoute(access, args),
    },
  };
}

/** Adds the sign-in Lambda's origin and cache behavior to CloudFront distribution args */
export function addSignInRoute(access: PreviewAccess, args: CdnArgs) {
  args.origins = pulumi
    .all([args.origins, access.origin])
    .apply(([origins, origin]) => [...origins, origin]);
  args.orderedCacheBehaviors = pulumi
    .all([args.orderedCacheBehaviors ?? [], access.cacheBehavior])
    .apply(([behaviors, behavior]) => [behavior, ...behaviors]);
}
