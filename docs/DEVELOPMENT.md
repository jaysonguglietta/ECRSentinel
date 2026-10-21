# Development and verification

ECR Sentinel is intentionally small: a Node.js ES module server, static browser UI, AWS CLI adapter, Trivy job service, private local Inspector destination store, and build-host SBOM helper. Its Inspector path uses AWS-managed Inspector/S3/KMS resources but deploys none of them. There is no frontend build step, framework, or database.

## Local setup

```bash
git clone https://github.com/jaysonguglietta/ECRSentinel.git
cd ECRSentinel
npm ci
npm test
npm start
```

Use Node.js 20 or newer. The app also needs AWS CLI v2 and Trivy 0.71.1 or newer at runtime. Docker is needed only where the SBOM helper inspects a locally available final image. The browser must open the full private launch URL printed by `npm start`; `PORT=4180 npm start` selects another local port.

### Local prerequisites and first run

1. Confirm the executables resolve from the same shell that starts the app:

   ```bash
   node --version
   npm --version
   aws --version
   trivy --version
   aws configure list-profiles
   ```

2. Use the VPN and an approved named AWS profile. The app reads the AWS CLI configuration belonging to the operating-system user who launches Node. A profile may still need IAM Identity Center sign-in, `aws login`, or an MFA code. Supported simple `mfa_serial` role profiles can accept the OTP in the app; see [AWS access](AWS_ACCESS.md) for the exact cases.
3. Run `npm ci` to use the committed lockfile, then `npm test`. The test suite uses fakes and does not need live AWS permissions.
4. Run `npm start` and open the full URL printed to the terminal. The fragment is a private, per-process launch token. A plain `http://127.0.0.1:4173/` page can load static UI but cannot authorize API calls.
5. In the UI, select a profile and Region, connect, open a repository and image, and choose the scan path that matches the account's permissions. The [user guide](USER_GUIDE.md) and [Inspector SBOM guide](INSPECTOR_SBOM.md) cover the live workflows.

| Variable | Behavior | Development use |
| --- | --- | --- |
| `PORT` | Loopback listen port; default `4173`; integer 1–65535. | Avoid a port conflict, for example `PORT=4180 npm start`. |
| `ECR_SENTINEL_DATA_DIR` | Absolute directory for the local Inspector destination file. | Use a private temporary directory for manual testing without touching real settings. The app checks owner and mode. |
| AWS profile/config variables | Read by AWS CLI for non-MFA profile behavior. | Keep test shells and local profiles separate; never commit these values. |

There is no frontend compilation or hot reload. Browser assets are read from `public/` on each request, so a refresh usually shows an asset edit. Server-side JavaScript edits require a Node restart, which also rotates the launch token and clears in-memory scan state. A second server process should use another port and a separate data directory; the Inspector settings store does not coordinate writes across processes.

## Source layout

| Path | Main concern |
| --- | --- |
| `server.js` | Loopback server and request gate. |
| `src/api.js` | Internal JSON routes and body bounds. |
| `src/aws-cli.js` | Profile, MFA, AWS identity/inventory, Inspector export/S3 retrieval, credentials. |
| `src/inspector-settings.js` | Private, profile/account/Region-scoped Inspector destination settings. |
| `src/trivy.js` | Scan queue, Inspector SBOM binding, Trivy execution, normalization, retention. |
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
node --check src/inspector-settings.js
node --check src/trivy.js
node --check public/app.js
node --check public/auth-guide.js
node --check scripts/generate-sbom-bundle.mjs
npm audit --omit=dev
```

There is no separate lint, type-check, or build script in `package.json`. `npm audit` uses a current advisory database and can change over time. Do not treat a clean audit as proof that dependencies or Trivy are safe. Pin dependency updates in `package-lock.json` and review their transitive changes.

For UI changes, manually check desktop and mobile widths, keyboard focus, form errors, modal focus return, empty inventory, active scan, failed scan, and long finding names. For AWS changes, test with a disposable account/profile and verify that OTPs, launch tokens, access keys, and session tokens never appear in logs, browser storage other than the launch token, error responses, CSV exports, or child-process arguments.

The automated suite uses simulated AWS/Trivy behavior and local SBOM fixtures. A live role MFA challenge, Inspector export/S3/KMS route, private ECR pull scan, and genuine post-push build-host bundle require authorized environments; tests alone do not validate those integrations.

### Test organization and seams

The repository uses the built-in Node test runner and `node:assert/strict`. Run the whole suite with `npm test` or one area while iterating:

```bash
node --test test/backend.test.js
node --test test/sbom-bundle.test.js
node --test test/auth-guide.test.js
```

| Test file | What it proves |
| --- | --- |
| `test/backend.test.js` | Profile validation and MFA boundaries; fixed AWS arguments; direct scan digest/account/platform binding; Inspector exact filters and bounded S3 read; imported bundle and Inspector credential separation; private destination persistence; Java DB behavior; queue/cancel/report retention; HTTP token and upload protection. |
| `test/sbom-bundle.test.js` | Helper argument validation, Docker digest/platform binding, immutable local image ID, non-overwriting private output, inconsistent provenance rejection, and size bounds. |
| `test/auth-guide.test.js` | Profile-specific sign-in copy and correctly quoted copyable CLI commands. |

The core services expose dependency injection for tests without a live account:

- `new AwsCliService({run, command, credentialProviderFactory, configStampProvider})` replaces process execution and MFA credential resolution. The fake `run` returns `{stdout,stderr}` and can record exact AWS arguments, timeout, environment, and call order.
- `new TrivyScanService(aws, {run, command, cacheRoot, settingsRoot, settingsStore})` replaces Trivy process execution, isolates cache/settings paths, and allows deterministic job reports and failures.
- `createAppServer({aws, scans, publicDirectory, token})` builds a loopback server using fake services and a fixed token. Tests can exercise the HTTP gate, content type, body bounds, and JSON response without the real browser.
- The build-host helper exports parsers and `generateSbomBundle(options,{run})`. Fake Docker/Trivy output checks that the helper never reaches remote ECR and never replaces an existing bundle.

Use fresh temporary directories for tests that write settings or SBOM files, and remove them in `finally`. Avoid snapshots of complete secret-bearing environments or raw AWS errors. Assert behavior at trust boundaries: for example that the database update has no `AWS_ACCESS_KEY_ID`, an Inspector request contains one exact image filter, or a mismatched report never reaches the UI. A new test should cover a failure mode that could regress, not restate a helper's implementation.

### Manual verification matrix

Automated fakes do not replace a controlled integration run. Use a disposable or explicitly approved AWS account, sanitized image names, and a dedicated Inspector prefix. Capture only status codes and redacted screenshots in a bug report.

| Scenario | Action | Expected result |
| --- | --- | --- |
| First launch | Start Node, open full launch URL, choose a configured profile and Region. | Profile list appears; STS identity and inventory load; no AWS secret or OTP appears in page source or URL after token capture. |
| Stale launch | Restart Node, refresh an old tab. | API access fails clearly; opening the new printed URL reconnects. |
| Supported role MFA | Choose a simple role profile with `mfa_serial` and submit a valid one-time code. | Account/role identity appears; a later request uses the in-memory role session; code is not replayed into browser storage. |
| Expired or unsupported sign-in | Wait for expiry or use a chained/`credential_process` profile. | Clear recovery guidance to reauthenticate through the supported path. |
| Inventory pagination | Open a repository with more than 100 images and load another page. | No duplicate rows; search/sort include loaded pages only; selection remains tied to a digest. |
| Direct scan | Use an account with the required ECR registry pull permission. | Trivy updates its DB, reads only the selected digest, verifies platform, and returns findings or explicit limited coverage. |
| Direct scan denied | Remove pull permission in the disposable account and retry. | A clean `ECR_PULL_DENIED` style error; no successful partial report. |
| Imported bundle | Generate a bundle on an authorized host, transfer it privately, select matching image and platform, import. | The Mac scans package entries without ECR layer download; report labels association as unverified. |
| Imported mismatch | Select a different account, digest, or platform for that bundle. | Server rejects it before starting Trivy. |
| Inspector setup | Save an approved bucket/prefix/KMS ARN, restart Node, reconnect same profile/account/Region. | Setting survives; it is absent for another profile/account/Region. |
| Inspector scan | Use an Inspector-monitored image with export/S3/KMS permissions. | Job progresses through export, S3 retrieval, and local SBOM scan; report labels Inspector source and metadata-verified association. |
| Inspector failure | Remove one required export or object-read permission. | Failure names the missing action or recovery step without printing raw AWS stderr. |
| Cancellation | Queue two jobs, cancel the second, then cancel an active one. | Queued job never begins; running child work is aborted; final state is `CANCELED`. An accepted AWS export may still finish. |
| Report use | Search/filter by severity or package, follow a valid advisory, export CSV. | Counts and rows agree; only HTTPS advisory links open; spreadsheet formula-like text stays inert in CSV. |
| Settings removal | Remove the saved destination with the confirmation flow. | Inspector scan returns setup guidance for that profile/account/Region; existing S3 objects remain governed by bucket lifecycle. |

For browser QA, check a narrow mobile viewport and a desktop viewport, full keyboard navigation, visible focus, modal focus trap and return, reduced space/long names, loading states, and every error/empty state reached by the core workflows. A static asset refresh does not preserve a server-side job after Node restarts.

## Change guidelines

- Keep AWS requests tied to a selected named profile, verified caller account, Region, repository, and immutable digest. Do not accept arbitrary registry URLs from an API request. Inspector exports must always use an exact resource ID filter, a unique S3 prefix, and the validated saved destination. The saved destination is operator-writable and is not an administrator allowlist; enforce approved bucket/key/prefix with IAM, S3, and KMS policy.
- Preserve `execFile`/`spawn` argument arrays and avoid shell interpolation. Bound input, process time, output size, queue depth, and file size before adding new workflows.
- Update both the UI and server validation when adding an input; server validation is authoritative.
- Keep database download separate from credential-bearing Trivy image analysis. Neither SBOM path may pass AWS credentials to Trivy. Inspector S3 reads must remain bounded and private, and no raw AWS CLI stderr or SBOM content should enter browser errors.
- Treat imported SBOM fields as claims until signed provenance is implemented. Inspector metadata can bind an export to an image digest but cannot attest package completeness or a missing OS/variant. Do not silently convert a claim into trusted evidence.
- Keep error messages actionable but free of raw AWS CLI stderr, credential values, and private paths.
- Add a test for a meaningful new security boundary or failure mode. Avoid tests that merely duplicate implementation details.
- Update `README.md` and the focused guide for user-visible behavior, permissions, command requirements, or changed limits.

### Safe change recipes

**Adding an AWS operation:** Add a narrowly named method in `src/aws-cli.js`. Validate every input before building an argument array; resolve the named profile and Region; use the existing `execute` wrapper for timeout, output bound, concurrency, and sanitized error mapping. For operations that could return data from another account or resource, bind the response to STS account and the selected repository/digest before any scanner work. Add a backend test that records the exact command arguments and a denial test that proves the resulting browser error contains no raw stderr or secrets.

**Changing a scan route:** Keep queue and cancellation handling in `TrivyScanService`. Define the route's target identity and deduplication key, the exact byte/resource limits, whether AWS credentials may reach the child process, the provenance strength of a successful report, and what remains in S3 or local cache after cancellation. Update the HTTP route in `src/api.js`, the UI state/confirmation in `public/app.js`, architecture and operator documentation, and tests for both success and identity mismatch. If a route can no longer verify target association, fail closed or show the limitation explicitly.

**Changing an input or setting:** Treat browser validation as user feedback and server validation as the authority. A new field that selects an AWS resource must have a length limit, a constrained syntax, an account/Region binding, and a clear behavior when omitted. Persist only nonsecret settings through `InspectorDestinationStore` and keep its versioned file format backward compatible or provide a deliberate migration. A saved destination can be edited by anyone with the launch token; enforce organization policy outside the app through AWS policies.

**Changing normalized findings or CSV:** Update `normalizeTrivyReport`, the associated report tests, and the UI together. Preserve a finite finding/character budget. Continue to insert data into the DOM as text, accept only safe HTTPS advisory links, and neutralize formula prefixes in CSV cells. A zero-finding report must retain its `coverage` note; avoid phrasing it as proof of no vulnerabilities.

**Changing child process behavior:** Keep `shell: false` and fixed command/argument separation. Review the child environment for credentials, proxy settings, registry redirects, cache locations, and inherited configuration. A direct image scan may pass long-lived IAM-user keys from a static profile; do not log child environments or silently expand where those credentials can go. The database update and both SBOM routes must remain credential-free.

### Troubleshooting during development

The browser presents sanitized errors with an error code and recovery text. Inspect that code first, then reproduce with the smallest authorized profile/target. The [troubleshooting guide](TROUBLESHOOTING.md) maps common operator failures. For code-level diagnosis, use a fake runner to record arguments and selected nonsecret response fields. Do not turn on raw AWS CLI history or print MFA codes, launch URLs, access keys, session tokens, complete SBOMs, full Trivy JSON, or private account inventory to shared logs.

| Symptom | Useful check | Likely owner |
| --- | --- | --- |
| No profiles in selector | `aws configure list-profiles` from the Node process's shell/user. | Local AWS CLI setup. |
| Profile connects in terminal but not app | Profile type, `cli_history` setting, Node process environment, new launch token after restart. | Auth adapter/configuration. |
| Trivy unavailable | `trivy --version` and `GET /api/scanner/status` while using a valid launch tab. | Local scanner install or version. |
| Direct scan denied | Compare selected account/digest with approved ECR pull policy; inspect only the sanitized error code. | AWS IAM/ECR policy. |
| Inspector destination saves but export fails | Confirm saved account/Region and approved bucket/KMS policy, Inspector monitoring coverage, and the action named by the error. | AWS setup or Inspector coverage. |
| Inspector job waits | Check export status in an authorized AWS console/CLI session; local poll deadline is 12 minutes. | Inspector export or S3 destination. |
| SBOM mismatch | Compare bundle's declared account, Region, repository, digest, and platform with the selected image. | Bundle producer or selection. |
| Unsafe cache/settings directory | Check owner, symlink status, and group/other mode bits; do not weaken the server check. | Local filesystem permissions. |

### Release and documentation gate

Before shipping a change, inspect `git diff --check` and the staged file list; run `npm test`, JavaScript syntax checks, and the dependency audit above. Run the manual route affected by the change in an authorized environment if that route's behavior depends on AWS, Docker, or Trivy integration. Confirm the first screen and the changed workflow at desktop/mobile widths with keyboard access. Review error, loading, disabled, empty, cancel, and retry states. Verify a fresh clone with `npm ci` still starts. Update the relevant guide and the architecture/API reference whenever a permission, behavior, field, limit, or security boundary changes.

For public GitHub releases, confirm no sample account IDs, private repository names, real S3 destinations, launch URLs, SBOMs, report CSVs, screenshots with sensitive data, or AWS configuration have entered the commit history. A green local test suite proves only its simulated cases. The [security policy](../SECURITY.md) and [security audit](../SECURITY_AUDIT.md) describe production risks and review work.

## Public repository hygiene

Before committing or publishing, inspect the staged file list and diff. Commit only source, tests, documentation, and the lockfile. Keep `node_modules/`, local caches, exported reports, SBOM bundles, screenshots containing account data, `.aws/` files, environment files, launch URLs, credentials, and `inspector-destinations.json` out of the repository. The destination file contains no AWS credentials but can reveal account and storage details; the default location is macOS Application Support outside the checkout. A generated SBOM can reveal private package names and versions even without image layers. See [SECURITY.md](../SECURITY.md) and the [audit](../SECURITY_AUDIT.md).
