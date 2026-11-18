import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import * as pulumi from '@pulumi/pulumi';

pulumi.runtime.setMocks({
  newResource: (args) => {
    const state: Record<string, unknown> = { ...args.inputs, arn: `arn:aws:mock:::${args.name}` };
    if (args.type === 'aws:lambda/functionUrl:FunctionUrl') {
      state.functionUrl = 'https://abc123.lambda-url.eu-west-2.on.aws/';
    }
    return { id: `${args.name}-id`, state };
  },
  call: (args) => args.inputs,
});

const { createPreviewAccess } = await import('../src/pulumi.ts');
const { previewAccessSiteArgs } = await import('../src/sst.ts');

const output = <T>(value: pulumi.Output<T>) =>
  new Promise<T>((resolve) => value.apply((resolved) => resolve(resolved)));

const args = {
  domain: 'dev.example.com',
  issuer: 'https://idp.example.com/pool',
  clientId: 'client-1',
};

test('the component routes /__access/* to the sign-in Lambda through origin access control', async () => {
  const access = await createPreviewAccess('Access', args);
  const origin = await output(access.origin);
  assert.equal(origin.domainName, 'abc123.lambda-url.eu-west-2.on.aws');
  assert.equal(origin.originAccessControlId, 'Access-sign-in-oac-id');
  const behavior = await output(access.cacheBehavior);
  assert.equal(behavior.pathPattern, '/__access/*');
  assert.equal(behavior.targetOriginId, origin.originId);

  const injection = await output(access.viewerRequestInjection);
  assert.match(injection, /"domain":"dev.example.com"/);
});

test('the SST adapter adds the sign-in origin and puts its behavior first', async () => {
  const access = await createPreviewAccess('Site', args);
  const cdnArgs: {
    origins: pulumi.Input<object[]>;
    orderedCacheBehaviors?: pulumi.Input<object[]>;
  } = {
    origins: [{ originId: 'default' }],
    orderedCacheBehaviors: [{ pathPattern: '/existing/*' }],
  };
  previewAccessSiteArgs(access).transform.cdn(cdnArgs);
  const origins = (await output(pulumi.output(cdnArgs.origins))) as { originId: string }[];
  assert.deepEqual(
    origins.map((origin) => origin.originId),
    ['default', 'Site-sign-in'],
  );
  const behaviors = (await output(pulumi.output(cdnArgs.orderedCacheBehaviors!))) as {
    pathPattern: string;
  }[];
  assert.deepEqual(
    behaviors.map((behavior) => behavior.pathPattern),
    ['/__access/*', '/existing/*'],
  );
});

test('importing the package never loads Pulumi, so bundlers can hoist it safely', () => {
  // A fresh process where loading any @pulumi/* module throws
  const script = `
    import { registerHooks } from 'node:module';
    registerHooks({
      resolve(specifier, context, nextResolve) {
        if (specifier.startsWith('@pulumi/')) throw new Error('loaded ' + specifier);
        return nextResolve(specifier, context);
      },
    });
    await import('./src/index.ts');
    await import('./src/pulumi.ts');
    await import('./src/sst.ts');
    await import('./src/lambda.ts');
  `;
  execFileSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: new URL('..', import.meta.url),
  });
});
