# Architecture and local API

ECR Sentinel is a local, single-user Node.js application with a browser UI. The Node server binds to `127.0.0.1` and serves static files plus an internal JSON API. AWS CLI handles inventory, Inspector SBOM exports, S3 retrieval, and direct image credentials. The AWS SDK credential provider handles supported in-app role MFA. Trivy performs vulnerability checks on the Mac. An optional build-host helper produces an SBOM from a locally available final Docker image.

## Component map

```mermaid
flowchart LR
  B[Browser UI] -->|launch token + JSON| N[Node loopback server]
  N -->|approved destination setting| C[Private local settings file]
  N -->|AWS SDK role MFA| S[STS]
  N -->|AWS CLI identity and metadata| A[STS and ECR API]
  N -->|exact image SBOM export + status| I[Amazon Inspector]
  I -->|encrypted CycloneDX JSON| S3[Approved S3 bucket]
  S3 -->|bounded SBOM read via AWS CLI| N
  N -->|direct image job, temporary credentials| T[Local Trivy]
  T -->|selected ECR digest and layers| E[ECR registry and layer storage]
  T -->|database update without AWS credentials| D[Trivy database registries]
  H[Authorized build host and Docker] -->|private JSON bundle| B
  N -->|SBOM job, no AWS credentials| T
```

| File | Responsibility |
| --- | --- |
| `server.js` | Loopback HTTP server, launch token, Host/Origin checks, static-file restrictions, security headers. |
| `src/api.js` | Internal route dispatch, JSON limits, uniform error responses. |
| `src/aws-cli.js` | Profile discovery, authentication method detection, SDK role MFA, AWS CLI calls, Inspector destination validation, export/status, bounded S3 retrieval, credential export. |
| `src/inspector-settings.js` | Private, account/Region/profile-scoped Inspector export destination persistence and safe local file writes. |
| `src/trivy.js` | Scanner preflight, queue, database preparation, direct and SBOM scan execution, Inspector export orchestration and SBOM identity checks, report normalization and retention. |
| `public/index.html`, `public/styles.css`, `public/app.js` | Accessible browser UI, connection flow, inventory, scan actions, findings, CSV export. |
| `public/auth-guide.js` | Profile-specific sign-in instructions. |
| `scripts/generate-sbom-bundle.mjs` | Build-host helper that binds a local Docker image to an ECR digest/platform and writes a private bundle. |

The app has no hosted backend, application user database, account signup, or multi-tenant model. It stores only Inspector destination configuration locally; reports remain in memory, and Inspector's SBOM object is stored in the administrator-approved AWS bucket. It is intended to run as a standard macOS user with an already configured AWS identity.

## Trust boundaries

1. **Browser to local server.** The server generates a 256-bit random token per run and prints it in the launch URL fragment. The browser moves it into tab session storage and sends it in `X-ECR-Sentinel-Token` on API requests. Static assets do not contain the token. API requests also pass Host and Origin checks; CORS is not enabled. Anyone holding the launch URL while the server runs can use the app as that local OS user.
2. **Local server to AWS.** Named profiles are taken from AWS CLI configuration. For a supported MFA role, the one-time code is handed to the AWS SDK provider and temporary credentials remain in server memory. Other profiles use AWS CLI's established credential chain/cache. Calls use fixed command arguments through `execFile`; the shell is not used.
3. **Browser to local destination settings.** A launch-token holder can create, read, change, or remove the bucket, prefix, and KMS ARN setting for a verified profile, account, and Region. The server stores those nonsecret values in a private owner-only file and supplies them to future Inspector scan requests. The setting is an operator convenience, **not** an administrator-enforced destination allowlist. AWS IAM, S3, and KMS policies must enforce the organization's approved destination.
4. **Local server to Inspector and S3.** The request uses an exact ECR image resource ID, account, and resource type filter, then stores Inspector's export in the configured S3 bucket under a random per-job prefix. The server checks export status/destination and reads one bounded object from that prefix. S3/KMS permissions are controlled by the AWS team. The export remains in S3 after the local job ends; the app does not delete it. A strictly read-only role cannot call `CreateSbomExport` because AWS categorizes it as Write.
5. **Local server to Trivy.** Trivy is a child process. Its database update runs without AWS credentials. A direct image scan receives credentials in its child environment to fetch only the selected ECR image by digest. Both SBOM scan paths pass no AWS credentials and read a temporary private file.
6. **Build host to Mac.** An imported SBOM is untrusted input even if its metadata matches the selected ECR digest. The importer validates shape, size, account, Region, repository, digest, platform, and optional Trivy RepoDigest property; it does not verify a signature or attest package completeness.
7. **Inspector SBOM to Mac.** The Inspector export is checked for CycloneDX 1.4 format, one account, ECR resource type, image digest, and architecture. Inspector's published SBOM metadata may lack repository, Region, OS, and variant; those limits remain explicit. The checked metadata is not an attestation of package completeness.
8. **Third-party content.** ECR metadata, image layers, SBOM JSON, Trivy output, and advisory URLs may be attacker controlled. The UI inserts text as text, accepts only HTTPS advisory links, and protects exported CSV cells against formula interpretation.

See the [security audit](../SECURITY_AUDIT.md) for residual risks and tests.

## Internal API

The API is for the included browser UI and is not versioned as an external integration contract. It requires the launch-token header on **every** `/api/` request. POST requests with bodies send `Content-Type: application/json`. Success responses use JSON; errors use:

```json
{
  "error": {
    "code": "EXAMPLE_CODE",
    "message": "A recoverable, user-facing explanation."
  }
}
```

| Method | Route | Input | Result |
| --- | --- | --- | --- |
| GET | `/api/profiles` | Optional `refresh=1` | `profiles`: configured AWS profile names. |
| GET | `/api/auth-method` | `profile` | `authMethod`: `role-mfa`, `sso`, `login`, `iam-user-mfa`, or `standard`. |
| POST | `/api/auth/mfa` | JSON `profile`, `region`, `code` | Account, role ARN, Region, and session expiry; never credentials or the code. |
| GET | `/api/identity` | `profile`, `region` | Current account and caller ARN. |
| GET | `/api/repositories` | `profile`, `region`, optional `nextToken` | Up to 100 repository summaries and next token. |
| GET | `/api/images` | `profile`, `region`, `repository`, optional `nextToken` | Up to 100 image summaries and next token. |
| GET | `/api/scanner/status` | None | Trivy availability, version, or a scanner error. |
| GET | `/api/inspector/destination` | `profile`, `region` query parameters | Saved destination for the resolved profile/account/Region, or `configured: false`. |
| PUT | `/api/inspector/destination` | JSON `profile`, `region`, `destination: { bucketName, keyPrefix, kmsKeyArn }` | Save a validated destination scoped to the resolved profile/account/Region. |
| DELETE | `/api/inspector/destination` | `profile`, `region` query parameters | Remove that saved destination. |
| GET | `/api/scans/latest` | `profile`, `region`, `repository`, `digest`, `platform` | Latest matching report and job, if still retained. |
| POST | `/api/scans` | JSON target fields above | HTTP 202 and queued or active direct-image job. |
| POST | `/api/scans/sbom` | JSON target fields and `bundle` | HTTP 202 and queued or active SBOM job. |
| POST | `/api/scans/inspector` | JSON target fields only | HTTP 202 and queued or active Inspector export → local Trivy SBOM job, using the saved destination. Returns HTTP 409 `INSPECTOR_DESTINATION_NOT_CONFIGURED` if none is saved. |
| GET | `/api/scans/:id` | UUID job ID | Current status, phase, timestamps, error, and completed report if retained. |
| DELETE | `/api/scans/:id` | UUID job ID | Cancellation request or final job state. |

A scan target is `profile`, `region`, `repository`, `digest`, and `platform`. The digest must be a `sha256:` value with 64 lowercase hex digits; the default platform is `linux/amd64`. The app verifies the profile exists locally, resolves the AWS account, and rechecks the selected image and account during job execution. The SBOM upload body is limited to 20 MiB; ordinary JSON bodies are limited to 16 KiB.

Example target payload, using placeholders rather than real account data:

```json
{
  "profile": "sentinel-review",
  "region": "us-east-1",
  "repository": "team/service",
  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "platform": "linux/amd64"
}
```

The browser handles token storage and requests. External scripts should not extract a live launch token from another session or treat this unversioned API as a remote service. The settings API resolves STS identity before reading or modifying the profile/account/Region entry; destination fields in a scan request are rejected.

## Job lifecycle and limits

Jobs move through `PENDING`, `IN_PROGRESS`, then `COMPLETE`, `FAILED`, or `CANCELED`. Phases include preflight, database update, scan, and report processing. Inspector jobs also request, wait for, and retrieve the export. One job runs at a time and up to three may wait. Duplicate active requests for the same target, mode, and destination reuse the existing job. Each Trivy scan process has a 15-minute limit; Inspector export wait is capped at 12 minutes and the overall job deadline is 30 minutes. Direct image analysis is capped at 4 GB, imported and Inspector SBOMs at 16 MiB, report output at 64 MiB, and normalized findings at 5,000. Canceling a job stops local work; AWS may still finish an export already requested.

The first scan on each server run updates Trivy's vulnerability database; another update is attempted after six hours. Java database download may occur when a scan needs it. Reports are normalized into a common schema with scan mode, account, digest, platform, database timestamp, coverage, severity counts, findings, and SBOM provenance. Manual bundles carry producer claims; Inspector reports identify metadata-verified Inspector exports.

The server keeps at most 40 recent job records and ten completed reports **in memory**. Reports disappear on server restart. The nonsecret Inspector destination settings survive restart in `~/Library/Application Support/ECR Sentinel/inspector-destinations.json` by default, in a mode-`0700` directory and mode-`0600` file. `ECR_SENTINEL_DATA_DIR` can specify an absolute alternative directory; protect that path with the same owner-only permissions. Locking a browser tab does not erase settings; the settings API can remove an entry. Imported SBOM bytes are held while queued, written to a mode-`0600` temporary file for Trivy, and removed after normal completion or cancellation. Trivy database and analysis cache persist in `ecr-sentinel-trivy-cache` under the user's operating-system temporary directory. Hard kills may leave a temporary SBOM file; startup cache initialization removes matching files older than one hour. Exported CSV is written only when the operator requests it.

## Architectural limits

The browser searches and sorts loaded inventory pages, not every item in a large account. The app supports one account and Region in the current workspace and one selected platform per scan. No background scheduler, organization-wide scan fleet, signed SBOM validation, permanent report store, triage state, role-based access control, or production deployment gate is implemented. This local architecture should not be exposed as a public network service without a separate security design.
