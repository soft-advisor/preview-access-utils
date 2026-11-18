# preview-access-utils

Reusable building blocks for protecting nonproduction sites behind a sign-in, published to npm.

| Package                                                   |                                                                                                                                                                         |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@soft-advisor/preview-access`](packages/preview-access) | Put a CloudFront-served site behind an OpenID Connect sign-in (e.g. Amazon Cognito) without changing the app: edge check, sign-in Lambda, Pulumi component, SST adapter |

## Development

Node 24 and pnpm (`corepack enable`).

```sh
pnpm install
pnpm lint        # Biome lint + format check
pnpm typecheck
pnpm test
pnpm build
```

## Releasing

Each package publishes itself when its `package.json` version isn't on npm yet: bump the version in a PR, and merging it to `main` publishes ([`publish.yml`](.github/workflows/publish.yml)). Packages are published from GitHub Actions with npm provenance, so each version links to the commit and workflow that built it.

**Publishing credentials.** `@soft-advisor/preview-access` publishes with npm trusted publishing: GitHub Actions signs in with OIDC, and no npm token exists. For a new package, npm trusted publishing (GitHub OIDC, no token) can only be set up for a package that already exists. So:

1. The first version of a new package is published with a short-lived npm token in the `NPM_TOKEN` repository secret.
2. Then, on npmjs.com, the package's Settings → Trusted publisher is set to GitHub Actions, repository `soft-advisor/preview-access-utils`, workflow `publish.yml`.
3. The `NPM_TOKEN` secret is deleted and the token revoked. Later versions publish through OIDC.
