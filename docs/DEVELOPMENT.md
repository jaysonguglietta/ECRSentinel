# Development and verification

ECR Sentinel is intentionally small: a Node.js ES module server, static browser UI, AWS CLI adapter, Trivy job service, and build-host SBOM helper. There is no frontend build step, framework, database, or remote service controlled by this repository.

## Local setup

```bash
git clone https://github.com/jaysonguglietta/ECRSentinel.git
cd ECRSentinel
npm ci
npm test
npm start
```

Use Node.js 20 or newer. The app also needs AWS CLI v2 and Trivy 0.71.1 or newer at runtime. Docker is needed only where the SBOM helper inspects a locally available final image. The browser must open the full private launch URL printed by `npm start`; `PORT=4180 npm start` selects another local port.

## Source layout

| Path | Main concern |
| --- | --- |
| `server.js` | Loopback server and request gate. |
| `src/api.js` | Internal JSON routes and body bounds. |
| `src/aws-cli.js` | Profile, MFA, AWS identity/inventory, credentials. |
| `src/trivy.js` | Scan queue, Trivy execution, normalization, retention. |
| `public/index.html` | Semantic app structure and dialogs. |
| `public/styles.css` | Visual system and responsive layout. |
| `public/app.js` | UI state, actions, polling, filtering, CSV export. |
| `public/auth-guide.js` | Sign-in guidance by AWS profile type. |
| `scripts/generate-sbom-bundle.mjs` | Authorized build-host helper. |
| `test/` | Node test runner coverage for backend, helper, and sign-in copy. |
| `docs/`, `README.md`, `SECURITY_AUDIT.md` | Operator, developer, and security documentation. |

Read [the architecture and API reference](ARCHITECTURE.md) before changing the AWS or scan boundary.

## Checks

Run the repository's test suite and JavaScript syntax checks:

```bash
npm test
node --check server.js
node --check src/api.js
node --check src/aws-cli.js
node --check src/trivy.js
node --check public/app.js
node --check public/auth-guide.js
node --check scripts/generate-sbom-bundle.mjs
npm audit --omit=dev
```

There is no separate lint, type-check, or build script in `package.json`. `npm audit` uses a current advisory database and can change over time. Do not treat a clean audit as proof that dependencies or Trivy are safe. Pin dependency updates in `package-lock.json` and review their transitive changes.

For UI changes, manually check desktop and mobile widths, keyboard focus, form errors, modal focus return, empty inventory, active scan, failed scan, and long finding names. For AWS changes, test with a disposable account/profile and verify that OTPs, launch tokens, access keys, and session tokens never appear in logs, browser storage other than the launch token, error responses, CSV exports, or child-process arguments.

The automated suite uses simulated AWS/Trivy behavior and a local SBOM fixture. A live role MFA challenge, a private ECR pull scan, and a genuine post-push build-host bundle require authorized environments; tests alone do not validate those integrations.

## Change guidelines

- Keep AWS requests tied to a selected named profile, verified caller account, Region, repository, and immutable digest. Do not accept arbitrary registry URLs from an API request.
- Preserve `execFile`/`spawn` argument arrays and avoid shell interpolation. Bound input, process time, output size, queue depth, and file size before adding new workflows.
- Update both the UI and server validation when adding an input; server validation is authoritative.
- Keep database download separate from credential-bearing Trivy image analysis. SBOM scanning must not receive AWS credentials.
- Treat imported SBOM fields as claims until signed provenance is implemented. Do not silently convert an unverified claim into trusted evidence.
- Keep error messages actionable but free of raw AWS CLI stderr, credential values, and private paths.
- Add a test for a meaningful new security boundary or failure mode. Avoid tests that merely duplicate implementation details.
- Update `README.md` and the focused guide for user-visible behavior, permissions, command requirements, or changed limits.

## Public repository hygiene

Before committing or publishing, inspect the staged file list and diff. Commit only source, tests, documentation, and the lockfile. Keep `node_modules/`, local caches, exported reports, SBOM bundles, screenshots containing account data, `.aws/` files, environment files, launch URLs, and credentials out of the repository. A generated SBOM can reveal private package names and versions even without image layers. See [SECURITY.md](../SECURITY.md) and the [audit](../SECURITY_AUDIT.md).
