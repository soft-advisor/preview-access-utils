import * as crypto from 'node:crypto';
import { viewerRequestInjection } from '../src/edge.ts';

export const DOMAIN = 'dev.example.com';
export const KEY = 'a'.repeat(64);
export const PREVIOUS_KEY = 'b'.repeat(64);

type EdgeRequest = {
  method: string;
  uri: string;
  querystring: Record<string, { value: string; multiValue?: { value: string }[] }>;
  cookies: Record<string, { value: string }>;
};

/**
 * Runs the generated edge check the way CloudFront Functions does: inside a viewer-request
 * handler, with `cf.kvs()` backed by `store` and `require("crypto")` available.
 */
export async function runEdge(request: Partial<EdgeRequest>, store: Record<string, string>) {
  const cf = {
    kvs: () => ({
      get: async (key: string) => {
        if (!(key in store)) throw new Error('KeyNotFound');
        return store[key];
      },
    }),
  };
  const requireModule = (name: string) => {
    if (name !== 'crypto') throw new Error(`Module not available: ${name}`);
    return crypto;
  };
  const handler = new Function(
    'cf',
    'require',
    `return async function handler(event) { ${viewerRequestInjection({ domain: DOMAIN })} return event.request; }`,
  )(cf, requireModule);

  const fullRequest: EdgeRequest = {
    method: 'GET',
    uri: '/',
    querystring: {},
    cookies: {},
    ...request,
  };
  return handler({ request: fullRequest });
}
