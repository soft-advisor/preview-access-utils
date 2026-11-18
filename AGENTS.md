# AGENTS.md

Guidance for anyone changing this repo, human or agent. See [README.md](README.md).

- **These are public, reusable packages.** No organization-specific URLs, names or IDs in package code; take them as options with sensible defaults.
- **Security-sensitive code.** `preview-access` decides who can open protected sites. Every check (signatures, issuer, audience, expiry, nonce, state, return paths) needs a test, including the rejected cases.
- **Edge code runs in CloudFront Functions** (`cloudfront-js-2.0`), not Node: no optional chaining, nullish coalescing or Node APIs other than `require("crypto")`, and keep it small (10 KB per function, shared with the host's code).
- **The session cookie format is shared** by `session.ts` (Lambda) and `edge.ts` (CloudFront). Change both together; `test/edge.test.ts` checks they agree.
- **Readable code.** One statement per line, named checks with specific errors, descriptive names, named constants, and comments that explain why.
- **Releases:** bump the package version in the PR that should publish it. Breaking changes need a major version.
- **No AI attribution in commits or PRs:** no `Co-Authored-By` trailers for AI tools, no "Generated with …" lines and no session links.

## Checks

```sh
pnpm lint && pnpm typecheck && pnpm test && pnpm build
```
