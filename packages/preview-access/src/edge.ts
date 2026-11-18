import { type EdgeOptions, edgeOptions, PREVIOUS_KEY_SUFFIX } from './options.ts';

/*
 * The edge check runs in CloudFront Functions (runtime cloudfront-js-2.0) on every request to
 * the protected site. It lets a request through only with a valid session cookie, signed with
 * the key in the function's KeyValueStore. Without one, page loads go to the sign-in Lambda and
 * other requests get 401.
 *
 * That runtime is ES 5.1 plus a few later features, so the generated code sticks to plain
 * statements: no async closures (async arrow functions or IIFEs), no for...of, no optional
 * chaining or nullish coalescing. test/edge-runtime.test.ts enforces this. Names are prefixed
 * with __previewAccess so they can't clash with the host function's code.
 */

/**
 * Code to inject at the top of an existing async viewer-request handler, e.g. SST's
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
{
  const __previewAccess = ${settings};
  const __previewAccessRequest = event.request;
  const __previewAccessIsSignInPath =
    __previewAccessRequest.uri.indexOf(__previewAccess.pathPrefix + "/") === 0;

  let __previewAccessIsValid = false;
  const __previewAccessCookie = __previewAccessRequest.cookies[__previewAccess.cookieName];
  const __previewAccessParts =
    __previewAccessCookie && __previewAccessCookie.value ? __previewAccessCookie.value.split(".") : [];
  const __previewAccessIsUnexpired =
    __previewAccessParts.length === 3 && Number(__previewAccessParts[0]) > Date.now() / 1000;

  if (!__previewAccessIsSignInPath && __previewAccessIsUnexpired) {
    const __previewAccessCrypto = require("crypto");
    const __previewAccessSigned =
      __previewAccess.domain + "|" + __previewAccessParts[0] + "|" + __previewAccessParts[1];
    const __previewAccessSignature = __previewAccessParts[2];
    for (let i = 0; i < __previewAccess.keyNames.length && !__previewAccessIsValid; i++) {
      let __previewAccessKey = "";
      try {
        __previewAccessKey = await cf.kvs().get(__previewAccess.keyNames[i]);
      } catch (e) {
        __previewAccessKey = "";
      }
      if (__previewAccessKey) {
        const __previewAccessExpected = __previewAccessCrypto
          .createHmac("sha256", __previewAccessKey)
          .update(__previewAccessSigned)
          .digest("hex");
        // Constant-time comparison
        let __previewAccessDifference =
          __previewAccessExpected.length === __previewAccessSignature.length ? 0 : 1;
        for (let j = 0; j < __previewAccessExpected.length && j < __previewAccessSignature.length; j++) {
          __previewAccessDifference |=
            __previewAccessExpected.charCodeAt(j) ^ __previewAccessSignature.charCodeAt(j);
        }
        __previewAccessIsValid = __previewAccessDifference === 0;
      }
    }
  }

  if (!__previewAccessIsSignInPath && !__previewAccessIsValid) {
    const __previewAccessIsPageLoad =
      __previewAccessRequest.method === "GET" || __previewAccessRequest.method === "HEAD";
    if (!__previewAccessIsPageLoad) {
      return { statusCode: 401, statusDescription: "Unauthorized" };
    }

    const __previewAccessQuery = [];
    for (let name in __previewAccessRequest.querystring) {
      const parameter = __previewAccessRequest.querystring[name];
      const values = parameter.multiValue ? parameter.multiValue : [parameter];
      for (let k = 0; k < values.length; k++) {
        __previewAccessQuery.push(values[k].value === "" ? name : name + "=" + values[k].value);
      }
    }
    const __previewAccessReturnTo =
      __previewAccessRequest.uri +
      (__previewAccessQuery.length > 0 ? "?" + __previewAccessQuery.join("&") : "");
    return {
      statusCode: 302,
      statusDescription: "Found",
      headers: {
        location: {
          value:
            __previewAccess.pathPrefix + "/login?return=" + encodeURIComponent(__previewAccessReturnTo),
        },
        "cache-control": { value: "no-store" },
      },
    };
  }
}
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
