// The sign-in Lambda for deploying without the Pulumi component: a single ES module file
// (`index.mjs`, handler `index.handler`, Node.js 22+) configured through the environment
// variables in ENV.
export { lambdaCode } from './generated/lambda-code.ts';
export { ENV } from './lambda/config.ts';
