import type { DistributionRouteArgs, PreviewAccess } from './pulumi.ts';

/**
 * Settings for an SST site component that renders through CloudFront, such as
 * `sst.aws.Nextjs`: the edge check runs first in SST's own viewer-request function, and
 * `<pathPrefix>/*` routes to the sign-in Lambda. Call it inside `run()`:
 *
 *   const access = await createPreviewAccess("Access", { domain, issuer, clientId });
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
      cdn: (args: DistributionRouteArgs) => access.addSignInRoute(args),
    },
  };
}
