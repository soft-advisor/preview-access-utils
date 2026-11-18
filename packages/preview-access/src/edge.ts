import { type EdgeOptions, edgeOptions, PREVIOUS_KEY_SUFFIX } from './options.ts';

/*
 * The edge check runs in CloudFront Functions (runtime cloudfront-js-2.0) on every request to
 * the protected site. It lets a request through only with a valid session cookie, signed with
 * the key in the function's KeyValueStore. Without one, page loads go to the sign-in Lambda and
 * other requests get 401.
 *
 * The generated code avoids newer syntax (optional chaining, nullish coalescing) that the
 * CloudFront Functions runtime doesn't support.
 */

/**
 * Code to inject at the top of an existing viewer-request handler, e.g. SST's
 * `edge.viewerRequest.injection`. It expects `event` and the `cf` module (`import cf from
 * "cloudfront"`) in scope, and returns a response when the request isn't allowed.
 */
export function viewerRequestInjection(options: Partial<EdgeOptions> & { domain: string }) {
  const { domain, pathPrefix, cookieName, signingKeyName } = edgeOptions(options);
  const settings = JSON.stringify({
    domain,
    pathPrefix,
    cookieName,
    keyNames: [signingKeyName, signingKeyName + PREVIOUS_KEY_SUFFIX],
  });

  return `
// @soft-advisor/preview-access: require a signed session cookie
const __previewAccessResponse = await (async (settings) => {
  const request = event.request;
  if (request.uri.indexOf(settings.pathPrefix + "/") === 0) return undefined;

  const cookie = request.cookies[settings.cookieName];
  const parts = cookie && cookie.value ? cookie.value.split(".") : [];
  if (parts.length === 3 && Number(parts[0]) > Date.now() / 1000) {
    const crypto = require("crypto");
    const signed = settings.domain + "|" + parts[0] + "|" + parts[1];
    for (const keyName of settings.keyNames) {
      let key;
      try {
        key = await cf.kvs().get(keyName);
      } catch (e) {
        continue;
      }
      const expected = crypto.createHmac("sha256", key).update(signed).digest("hex");
      let difference = expected.length === parts[2].length ? 0 : 1;
      for (let i = 0; i < expected.length && i < parts[2].length; i++) {
        difference |= expected.charCodeAt(i) ^ parts[2].charCodeAt(i);
      }
      if (difference === 0) return undefined;
    }
  }

  const isPageLoad = request.method === "GET" || request.method === "HEAD";
  if (!isPageLoad) {
    return { statusCode: 401, statusDescription: "Unauthorized" };
  }

  const query = Object.keys(request.querystring)
    .map((name) => {
      const parameter = request.querystring[name];
      const values = parameter.multiValue ? parameter.multiValue : [parameter];
      return values
        .map((value) => (value.value === "" ? name : name + "=" + value.value))
        .join("&");
    })
    .join("&");
  const returnTo = request.uri + (query ? "?" + query : "");
  return {
    statusCode: 302,
    statusDescription: "Found",
    headers: {
      location: { value: settings.pathPrefix + "/login?return=" + encodeURIComponent(returnTo) },
      "cache-control": { value: "no-store" },
    },
  };
})(${settings});
if (__previewAccessResponse) return __previewAccessResponse;
`;
}

/**
 * A complete viewer-request function, for distributions without their own. Associate it with
 * every cache behavior except the sign-in path, together with the KeyValueStore.
 */
export function viewerRequestFunction(options: Partial<EdgeOptions> & { domain: string }) {
  return `import cf from "cloudfront";

async function handler(event) {
${viewerRequestInjection(options)}
  return event.request;
}
`;
}
