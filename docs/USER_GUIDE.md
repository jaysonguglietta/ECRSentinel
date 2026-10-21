# Operator guide

ECR Sentinel is a single-operator application that runs on a Mac and checks known package vulnerabilities in private Amazon ECR images with local Trivy. The app uses a named AWS CLI profile for identity and ECR inventory. Its three scan inputs have different access requirements. Read the [permission matrix](AWS_ACCESS.md#permission-matrix) before choosing one.

## First run

1. Install Node.js 20 or newer, AWS CLI v2, and a trusted stable Trivy 0.71.1 or newer. Confirm `node --version`, `aws --version`, and `trivy --version` in the same Mac account that will run Sentinel.
2. Configure a named AWS profile through your organization's normal process. Connect the VPN if AWS endpoints require it. The profile needs ECR inventory access even if you plan to scan an SBOM.
3. In a trusted checkout of this repository, run:

   ```bash
   npm ci
   npm start
   ```

4. Open the **complete private URL** printed by this server run, including `#token=...`. Do not share it or paste it into an issue. The server listens on `127.0.0.1:4173` by default; `PORT=4180 npm start` selects another port. A plain loopback URL shows the page but cannot authorize API calls.
5. In the app, select the named profile and Region. Connect, then check the **AWS account and Region** shown in the workspace before browsing or scanning.

This version still needs a Terminal window to start `npm start`. Supported role MFA is entered inside the app after it starts. Restarting the server creates a new launch token and clears its in-memory jobs, reports, and MFA role sessions. Reopen the new URL in any older tab.

## Connect a profile that requires MFA

For a simple role profile with `role_arn`, one `source_profile`, and `mfa_serial`, expand **Need to enter MFA or sign in?**, enter the current six-digit one-time code, and select **Verify code and connect**. The app sends the code through its token-protected loopback API to AWS STS. It neither saves the code in browser storage nor puts it in a shell command. The temporary role session stays in server memory until expiry or shutdown. It does not populate the AWS CLI's separate role cache.

If a cached AWS CLI role session is valid, **Connect to registry** may work without a new in-app MFA challenge. If it expires, enter a fresh code and retry. For IAM Identity Center, IAM-user MFA, console-backed `aws login`, chained roles, or custom credential providers, follow the guidance shown for the selected profile. **Use Terminal instead** presents the role-profile fallback command. [AWS access](AWS_ACCESS.md#profile-types-and-mfa) gives exact commands and supported shapes.

**Refresh profiles** reloads named profiles after you create or change one. **Switch AWS profile** returns to the connection screen. If the account unexpectedly changes while scanning, Sentinel stops the job; reconnect and verify the identity before starting another.

**Lock this tab** removes that tab's launch token, selected context, and MFA input. Another unlocked tab or process running as the same Mac user may remain able to use the server. Stop `npm start` to end the local server session. Saved Inspector destination settings remain until you remove them in the app.

## Find the exact image

1. Select a repository in the overview or sidebar. Use **Load more repositories** to fetch additional AWS pages.
2. Search repositories or image rows by their displayed names, tags, or digests. Sort image rows by push date or tag. Search and sort cover rows **loaded so far**; choose **Load more images** to include later pages.
3. Choose **Review & scan** for the image you intend to assess. Use the immutable `sha256:` digest as its identity; tags can move.
4. Choose the deployed platform, for example `linux/amd64` or `linux/arm64`. An image index can reference different child images for different platforms. Run a separate assessment for each platform you deploy.
5. Check that the image status is active and that the selected account, Region, repository, digest, and platform match your deployment record.

An archived image needs restoration by the responsible AWS team before Sentinel can scan its layers or request its Inspector SBOM. If an index digest differs from a platform child digest reported by Inspector or Docker, select the matching child artifact. Never edit an SBOM to make a mismatch pass.

## Choose a scan input

| Method in the image drawer | When to use it | Access on this Mac | Main limitation |
| --- | --- | --- | --- |
| **Scan image with Trivy** | The selected role may read ECR image layers. | ECR inventory plus registry authorization and image-pull actions; VPN route to registry and S3 layer storage. | Pulls layer bytes to the Mac and lets Trivy inspect the image. |
| **Import build-host SBOM** | An authorized build host can inspect the exact final image and deliver a bundle privately. | ECR inventory and digest verification; no ECR layer pull or Inspector action. | The bundle's image association is an unsigned claim and omitted packages cannot be found. |
| **Inspector SBOM → Trivy** | Inspector Enhanced Scanning already monitors the image, and the role may start an Inspector export. | ECR inventory, Inspector create/status, scoped S3 list/read, and KMS decrypt; no ECR layer pull. | Requires one-time AWS destination setup and a Write-classified Inspector API action; only exported components are checked. |

All methods use the Mac's Trivy vulnerability database. The first scan may take several minutes to download it, and the Java database may require several gigabytes of temporary cache. Current database registries include `mirror.gcr.io` and `ghcr.io`; ask your network team for the approved route if updates fail.

### Scan image layers directly

1. Choose **Scan image with Trivy** in the image drawer.
2. Read the image-layer transfer confirmation, then choose **Start Trivy scan**.
3. Watch the status phases or close the drawer and return later. Trivy requests the selected digest and processes the image locally; it may store temporary analysis data. There is no need to run a separate `docker pull`, but this path **is** image download access.
4. Review the detected package types, findings, database timestamp, and platform in the report.

A profile that lists repositories can still lack `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, or `ecr:GetDownloadUrlForLayer`. If a pull is prohibited, use an authorized SBOM path instead of treating inventory access as permission to read the image.

### Import a build-host SBOM

1. On an authorized host with the final image in local Docker **after the push**, run the repository's helper for the exact ECR digest and platform. It checks Docker's `RepoDigests`, scans the immutable local image ID, and creates a private Sentinel JSON bundle. Follow the [build-host procedure](BUILD_HOST_SBOM.md).
2. Transfer the bundle through an approved private route. Its package names and versions are sensitive inventory.
3. In the matching image drawer on the Mac, choose **Import build-host SBOM**, select the JSON file, review the confirmation, then choose **Check SBOM with Trivy**.
4. Review the report's **build-host SBOM** source and coverage note. Sentinel validates the bundle structure and its claimed account, Region, repository, digest, and platform, then Trivy matches vulnerabilities in the listed components. No ECR image layers are requested by this path.

The helper's Docker check is useful consistency evidence, but the bundle is not cryptographically signed. Sentinel cannot prove a different producer did not replace it. If your organization needs attested deployment evidence, add a signed provenance workflow and verify it before relying on the report.

### Request an Inspector SBOM and scan it

**Prerequisites:** Inspector Enhanced Scanning must already monitor the selected digest. An AWS administrator must provide an approved private S3 bucket, export prefix, and customer-managed symmetric KMS key in the image's Region, configure Inspector's bucket/key access, and grant this role `inspector2:CreateSbomExport`, `inspector2:GetSbomExport`, prefix-scoped S3 read/list, and KMS decrypt. `CreateSbomExport` is an AWS **Write** action. A strictly read-only role cannot start this path. Give the administrator the [handoff request](INSPECTOR_SBOM.md#request-for-the-aws-administrator).

1. In the image drawer, choose **Inspector SBOM → Trivy**. The first time for the verified profile, account, and Region, enter the approved bucket name, prefix, and KMS key ARN in the destination form. These are destination identifiers, not AWS access keys.
2. Save the destination. Later images in the same verified context use it automatically. **Change destination** updates the local setting; **Remove** asks for confirmation and forgets it from this Mac. Neither action creates/deletes AWS resources or changes IAM permissions.
3. Select a `linux/amd64` or `linux/arm64` platform **without a variant** and choose **Start Inspector SBOM scan**. The app requests a CycloneDX 1.4 export filtered to the exact ECR resource, waits for Inspector, retrieves the single JSON object from a unique S3 job prefix, verifies its digest/account/resource type/architecture, and runs local `trivy sbom`.
4. Review the **Inspector SBOM** source, component coverage, Trivy database date, and findings. The app displays Trivy CVE matches, not Inspector's own vulnerability findings.

The Mac receives the SBOM object bytes, **not image layers**. Inspector writes that object to S3 even though the app holds no image-pull permission. Canceling or timing out a local job does not guarantee that the remote export stops; S3 objects remain until your organization's lifecycle rule or an authorized administrator removes them. The app does not provision a bucket or key, does not enable Enhanced Scanning, and does not bypass a role's read-only policy. Read the [Inspector setup and coverage limits](INSPECTOR_SBOM.md) before using these results as evidence.

## Scan progress and cancellation

Only one local scan runs at a time; at most three more may wait. A second request for the same active target and scan input reuses the existing job. **Cancel scan** opens a confirmation and asks the local job to stop. For Inspector, a remote export may continue and leave an S3 object. A server restart removes all in-memory jobs and reports, so export any needed CSV first. The overall local job deadline is 30 minutes; the Inspector export wait has a 12-minute limit.

If a scan fails, keep the error code and selected workflow, then use [Troubleshooting](TROUBLESHOOTING.md). Retry after correcting the cause. A missing S3 destination cannot be repaired by entering an arbitrary bucket on the scan request; save the approved destination through the app's one-time setup.

## Interpret and export a report

A report is scoped to one account, Region, repository, digest, platform, scan input, and Trivy database state. It shows severity counts, detected package types, affected package/version, available fix, and advisory links when present. For an SBOM report, inspect its source, normalized SBOM SHA-256, and coverage note. The hash identifies the bytes Sentinel analyzed; it is **not a signature** or proof that the SBOM came from the selected image.

- **Search findings** matches advisory, package, or target text in the current report. **Filter by severity** narrows what is displayed. **Show 100 more findings** reveals more rows without changing the underlying report.
- **Refresh** checks the current server's latest local job or report for this target. It does not query a historical cloud report store.
- **Export report** downloads CSV from the complete current in-memory report, regardless of the active search or severity filter. Store the CSV according to your organization's handling rules.

**Zero findings means Trivy found no known matches in the packages it detected or was given at that database date.** It does not mean the image is safe. An SBOM can omit packages; a third-party SBOM may yield less precise matching; unresolved components may not be vulnerability-scannable. A report with no package targets has especially limited coverage. The app does not prove exploitability, scan secrets or malware, or create a deployment approval. Rescan after a new image digest or vulnerability database update.

## Local data and privacy

The server binds to `127.0.0.1` and requires the per-run launch token on API requests. It keeps up to ten normalized reports in memory, with no persistent report history. The selected profile and Region live in browser-tab session storage; a private Inspector destination record is saved across restarts in `~/Library/Application Support/ECR Sentinel/inspector-destinations.json` on macOS. The directory and file are owner-only. Trivy's database/analysis cache resides in `ecr-sentinel-trivy-cache` under the Mac user's operating-system temporary directory. Temporary SBOM files are removed after normal processing; a hard kill may leave them until the next cache cleanup. Inspector's S3 export objects follow AWS bucket retention, independently of the local server. See [README data and retention](../README.md#local-data-and-retention) and the [security audit](../SECURITY_AUDIT.md).
