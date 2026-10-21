# Security policy and operating guide

ECR Sentinel handles AWS identities, private ECR inventory, image contents during direct scans, and sensitive package inventories in SBOMs. It is designed for **one operator running locally on a Mac** with an approved VPN and named AWS profile. The Node server binds to `127.0.0.1`; its browser launch URL is a per-run bearer credential. The current application has no user accounts, organization administration, or multi-tenant access control. Do not put it behind a reverse proxy, bind it to a public interface, or share its launch URL. See the [architecture](docs/ARCHITECTURE.md) for the trust boundaries and the [adversarial audit](SECURITY_AUDIT.md) for evidence, open findings, and a test plan.

## Report a vulnerability

Use GitHub's private **Report a vulnerability** option for this repository, if available. Otherwise, contact the repository maintainer through a private channel before sending exploit details. Do not place live credentials, MFA codes, launch URLs, account identifiers, private repository names, SBOM contents, or exploit details in a public issue. A useful report includes the affected version or commit, entry point, reproduction steps using disposable data, expected and actual behavior, impact, and any relevant logs after secrets have been removed.

There is no published response SLA, supported release branch policy, or bug bounty. Coordinate a fix and disclosure with the maintainer. Report vulnerabilities in AWS, Trivy, Node.js, or another upstream component to that upstream project's security process as well.

## Supported security boundary

| Boundary | Current behavior | Operator responsibility |
|---|---|---|
| Mac and browser | HTTP is available on loopback only. A 256-bit random token is printed in the Terminal launch URL fragment, moved to tab session storage, and required in `X-ECR-Sentinel-Token` for every API request. Static assets do not contain the token. Host and Origin checks, a restrictive CSP, and no CORS protect the browser boundary. | Use a standard, private macOS account. Keep the launch URL and Terminal output private. Do not install untrusted browser extensions or local software under that account. |
| AWS identity | A selected named profile is checked against the AWS CLI configuration and resolved to an AWS account. Supported one-step `mfa_serial` role profiles can accept a six-digit code in the app. The SDK resolves temporary credentials in Node memory; unsupported roles use the organization's existing Terminal/provider sign-in. | Use a least-privilege role or Identity Center profile. Protect source credentials and the AWS CLI cache. Verify the displayed account and Region before acting. |
| Direct image scan | Trivy reads the selected immutable ECR digest, so image layers reach the Mac. Trivy receives the profile's resolved AWS credentials in its child environment for that scan. The profile might resolve to a long-lived IAM user key. | Permit this mode only when the Mac is authorized to pull layers. Prefer temporary credentials and a trusted current Trivy binary. |
| Imported build-host SBOM | The bundle is checked for format, selected account/Region/repository/digest/platform consistency, and size. Neither the bundle's author nor its package completeness is cryptographically verified. Trivy receives no AWS credentials for this mode. | Generate the bundle from the final image on an authorized host and transfer it privately. Treat a clean result as a match against **listed packages**, not proof about all image contents. |
| Inspector SBOM | The app requests an exact-image CycloneDX export, checks the returned filters and selected-image metadata, reads one bounded S3 object, and runs local Trivy matching. It does not pull ECR layers. Inspector must already monitor the image. | Obtain an administrator-approved private bucket, prefix, and same-Region customer-managed symmetric KMS key. The selected role needs an explicit `inspector2:CreateSbomExport` **Write** exception, status/read/decrypt permissions, and approved service policies. |

The Inspector API [requires an S3 destination and returns a report ID](https://docs.aws.amazon.com/inspector/v2/APIReference/API_CreateSbomExport.html), not SBOM bytes. AWS [classifies `CreateSbomExport` as Write](https://docs.aws.amazon.com/service-authorization/latest/reference/list_inspector2.html), so a strictly read-only role cannot initiate this route. Sentinel cannot create the bucket, KMS key, policies, or exception with that role. A manual build-host bundle remains possible only if an authorized system can produce one. ECR metadata alone cannot produce an SBOM or prove which packages are in an image.

## Before connecting to AWS

1. Install Node.js 20 or newer, AWS CLI v2, and Trivy 0.71.1 or newer from trusted distributions. Install this repository's locked npm dependencies with `npm ci`. The app checks Trivy's version before scanning but does not verify the binary's signature or hash.
2. Start with `npm start` from the repository and open the **complete** private URL printed for that run. Restarting the server generates a new token. A plain loopback URL can serve the page but cannot use the API.
3. Confirm the selected AWS account, Region, repository, digest, and platform in the UI. Tags are mutable display context; the scan target uses the digest.
4. Review [AWS access requirements](docs/AWS_ACCESS.md). Inventory uses `ecr:DescribeRepositories` and `ecr:DescribeImages`. Direct scanning additionally needs registry authorization and layer-pull actions. Manual SBOM import does not grant pull access on the Mac. Inspector export needs its separate service, S3, and KMS permissions.
5. Keep AWS CLI history disabled for the selected profile. Sentinel rejects `cli_history=enabled` because history can persist sensitive CLI responses.
6. Confirm VPN, DNS, proxy, and endpoint access. Direct mode needs ECR registry and S3 layer routes; Inspector mode needs Inspector and its export bucket; the first Trivy scan also needs access to its vulnerability database registries. See [network routes](docs/AWS_ACCESS.md#network-routes-to-check).

For a supported role profile, enter the one-time MFA code only in Sentinel's MFA form or the organization's normal AWS sign-in. The app does not put it in an AWS CLI command argument, browser storage, report, or CSV. The in-app role session is held in Node memory and expires before the STS credential's expiration. Other profile types may write their own AWS CLI or provider cache outside Sentinel. Never paste an OTP or AWS secret into a repository file, issue, screenshot, or support log.

## Inspector destination controls

Saving the bucket, prefix, and KMS ARN in Sentinel is an operator convenience. It is keyed to the **verified profile, account, and Region** and stored in a private local file, but any holder of the launch token can update or remove that setting. The value is **not** an administrator-owned allowlist or an AWS permission. The Inspector scan request itself rejects ad hoc destination fields and uses the saved value.

An AWS administrator should approve a dedicated private bucket and prefix in the same Region as the image, enable S3 Block Public Access, and use a customer-managed symmetric KMS key. Configure the Inspector **service** bucket and key policies for encrypted writes and the caller's narrowly scoped S3 list/read and KMS decrypt rights. Limit write access to the Inspector service for that prefix, with source-account and source-ARN conditions from [AWS's policy examples](https://docs.aws.amazon.com/inspector/latest/user/findings-managing-exporting-reports.html). Apply a lifecycle rule and logging/monitoring required by the organization. Review cross-account bucket/key policies, permission boundaries, and SCPs together.

Do not assume the caller's `inspector2:CreateSbomExport` identity policy can name a destination bucket as its resource. The [Inspector authorization table](https://docs.aws.amazon.com/service-authorization/latest/reference/list_inspector2.html) does not list a resource type or condition key for that action. The caller policy normally uses `Resource: "*"`; destination confinement therefore depends on organization-controlled S3/KMS policies and, for a stronger local control, an administrator-owned app allowlist that the launch-token API cannot edit. The current app has no such allowlist. See finding F-06 in the [audit](SECURITY_AUDIT.md).

An Inspector export can continue after a local cancel and **remains in S3 after Sentinel finishes**. The app does not delete the object. Set an explicit bucket lifecycle policy before routine use and review export objects after failed or canceled jobs. Inspector's package list may omit unresolved components; Sentinel's Trivy result covers the components actually listed. See the [Inspector setup guide](docs/INSPECTOR_SBOM.md) for the administrator handoff and policy example.

## Local data and credential handling

| Data | Where it exists | Normal retention and control |
|---|---|---|
| Launch token | Printed in the owner's Terminal; held in the browser tab's session storage and sent as an API header | Valid until the Node process stops. **Lock this tab** clears that tab's token and connection choice but does not rotate the server token, stop other tabs, or revoke an AWS session. Stop the server to invalidate its token and drop in-memory MFA sessions. |
| MFA code and temporary role credentials | OTP in the request and Node process during sign-in; temporary credentials in Node memory and isolated AWS CLI child environments, plus direct Trivy child when scanning layers | OTP is not intentionally persisted by Sentinel. The active role session reference is dropped at expiry or server stop; this is not a guarantee that process memory has been overwritten. Other providers' caches are outside this boundary. |
| Inspector destination | `~/Library/Application Support/ECR Sentinel/inspector-destinations.json` by default; an absolute `ECR_SENTINEL_DATA_DIR` overrides the directory | Persists across runs in an owner-only directory and mode-`0600` file. It contains bucket, prefix, KMS ARN, profile/account/Region metadata, not access keys. Remove an entry through the app when it is no longer approved. |
| Active and completed reports | Node memory; browser DOM while viewed | At most ten completed reports and 40 recent job records. Reports disappear on server restart. A user-initiated CSV is saved wherever the browser downloads it. |
| Imported or Inspector SBOM bytes | Memory while queued; a mode-`0600` file under the app's private temporary cache while Trivy reads it | Removed after a normal scan/cancel. A hard kill may leave a private file until a later cache initialization sweeps matching files older than one hour. |
| Trivy databases and analysis cache | `ecr-sentinel-trivy-cache` under the operating system's temporary directory | Reused across runs and can be large. There is no app cache-clear button, automatic size quota, or complete retention policy. Stop Sentinel before removing it under an approved retention procedure. |
| Inspector export object | Administrator-approved S3 bucket and prefix | Remains until the bucket's lifecycle rule or an administrator removes it. The local job has no remote delete action. |

The private directory checks reduce accidental disclosure to another Mac account; they do not isolate the application from malware running as the **same** macOS user. SBOMs and CSVs can reveal private component names, versions, architecture, and vulnerabilities. Handle them under the same access and retention policy as internal software inventory. The app does not upload reports to a Sentinel-hosted service.

## When a secret or report may have been exposed

1. Stop the Sentinel Node process. That invalidates the per-run launch token and removes its in-memory role credentials; locking a tab alone is insufficient.
2. If an AWS access key or session token might be exposed, follow the organization's AWS credential revocation/rotation process. Ending Sentinel does not invalidate an already-issued STS session at AWS or clear an independent AWS CLI/provider cache.
3. Check the approved Inspector bucket for unexpected export prefixes, destinations, and retained objects. Preserve relevant AWS audit records and object evidence under your incident-response process before deletion.
4. Remove or restrict exposed SBOM bundles, CSV files, screenshots, and local cache contents according to the organization's retention and evidence requirements.
5. Reopen Sentinel from a fresh launch URL only after the workstation, browser, profiles, and export destination have been checked.

## Release and security verification

Run `npm test`, `node --check server.js`, and `npm audit --omit=dev` when changing dependencies or security-sensitive code. A clean advisory lookup is a point-in-time result, not a guarantee. Review `package-lock.json`, installed AWS CLI and Trivy versions, and the staged file list before publication. Do not commit `node_modules/`, `.aws/`, credentials, `.env` files, a launch URL, local Inspector settings, exported reports, SBOM bundles, private screenshots, or Trivy caches.

The automated suite uses simulated AWS, Trivy, and MFA responses. The current documentation does not claim a live private ECR pull, Inspector export through real S3/KMS policies, or real six-digit MFA challenge has passed. Verify those paths with a disposable approved account before relying on the reports for release decisions. The [audit's security test plan](SECURITY_AUDIT.md#10-security-test-plan) lists targeted checks for the remaining risks.
