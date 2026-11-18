import assert from 'node:assert/strict';
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

const { PreviewAccess } = await import('../src/pulumi.ts');
const { addSignInRoute } = await import('../src/sst.ts');

const output = <T>(value: pulumi.Output<T>) =>
  new Promise<T>((resolve) => value.apply((resolved) => resolve(resolved)));

test('the component routes /__access/* to the sign-in Lambda through origin access control', async () => {
  const access = new PreviewAccess('Access', {
    domain: 'dev.example.com',
    issuer: 'https://idp.example.com/pool',
    clientId: 'client-1',
  });
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
  const access = new PreviewAccess('Site', {
    domain: 'dev.example.com',
    issuer: 'https://idp.example.com/pool',
    clientId: 'client-1',
  });
  const args: { origins: pulumi.Input<object[]>; orderedCacheBehaviors?: pulumi.Input<object[]> } =
    {
      origins: [{ originId: 'default' }],
      orderedCacheBehaviors: [{ pathPattern: '/existing/*' }],
    };
  addSignInRoute(access, args);
  const origins = (await output(pulumi.output(args.origins))) as { originId: string }[];
  assert.deepEqual(
    origins.map((origin) => origin.originId),
    ['default', 'Site-sign-in'],
  );
  const behaviors = (await output(pulumi.output(args.orderedCacheBehaviors!))) as {
    pathPattern: string;
  }[];
  assert.deepEqual(
    behaviors.map((behavior) => behavior.pathPattern),
    ['/__access/*', '/existing/*'],
  );
});
