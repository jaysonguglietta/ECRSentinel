# Troubleshooting

Start with the error code and the stage shown in Sentinel. Most failures are scoped to one profile, account, Region, network path, image digest, platform, or SBOM. Preserve those details when asking your internal AWS team for help, but redact the private launch URL, MFA code, credentials, and sensitive package inventory. Direct scans and manual SBOM imports do not need Inspector; the Inspector SBOM option requires that Enhanced Scanning already covers the image.

## Find the failing boundary

1. **Can you open the app?** If the page displays a launch-token warning, use the current server's complete private URL. If the server will not start, check Node and the port.
2. **Can you connect to the selected profile?** If not, resolve MFA/SSO/credential status and STS reachability. Verify the account and Region shown after connection.
3. **Can you list the repository and selected digest?** If not, check ECR inventory IAM actions, repository scope, organization denies, and ECR API routing. A successful STS identity does not prove ECR inventory access.
4. **Which scan input failed?** A direct image scan needs ECR registry/layer access; a manual bundle needs a trusted matching file; an Inspector export needs existing coverage, a Write-classified export permission, Inspector service S3/KMS access, caller S3/KMS read access, and a reachable database source. Apply only the checks for that input.
5. **Did a report finish but look empty?** Inspect package/coverage counts and the Trivy database date. Zero known matches is not evidence of image safety.

For detailed IAM policy examples see [AWS access](AWS_ACCESS.md#permission-matrix). The [operator guide](USER_GUIDE.md) explains what the app does at each step.

## Startup and browser session

| Symptom | Likely cause | Recovery |
| --- | --- | --- |
| `npm start` fails because the port is occupied | Another process already listens on port 4173. | Stop the old server or run `PORT=4180 npm start`, then open the newly printed URL. |
| The page says **Open the launch URL from Terminal** | The tab lacks the current server's launch token, or an old server was restarted. | Open the complete URL printed by the **current** `npm start` process, including `#token=...`. Do not share the token. |
| The page loads but API actions fail with an invalid token | A plain loopback URL was opened, the tab was locked, or the server restarted. | Reopen the current private launch URL. |
| **Lock this tab** does not stop another open tab | Locking clears that tab's browser token and MFA field; the server session still exists. | Stop the local server to end its in-memory role sessions and invalidate the per-run token. |
| Profiles do not appear | AWS CLI v2 is missing from the process path, no named profile exists, or configuration changed after loading. | Verify `aws --version` and `aws configure list-profiles` in the same Mac environment; then choose **Refresh profiles** or restart the app. |
| The application opens but there is no AWS profile to select | The profile list is empty or AWS CLI could not enumerate named profiles. | Confirm `aws configure list-profiles` contains the expected profile, the app runs as the same Mac user, and the CLI binary is on that process's `PATH`. Use **Refresh profiles** after creating a profile. Do not paste credential files into the app. |

The app is started with `npm start` in this version. In-app MFA entry removes the Terminal prompt for supported roles, but a double-click macOS launcher is not yet packaged. The printed launch URL changes on each restart; the base loopback address alone is not enough.

## AWS connection and MFA

| Symptom or error code | Recovery |
| --- | --- |
| `AWS_MFA_REQUIRED` or `AWS_SESSION_EXPIRED` | For a supported role, enter a fresh six-digit code under **Need to enter MFA or sign in?**. An in-app role session and the AWS CLI's cached session are separate. For SSO or custom providers, complete the displayed provider/CLI sign-in and select **Retry connection**. If a scan expired mid-run, start a new scan after reconnecting. |
| `AWS_MFA_FAILED` | Use the current code from the configured device. Confirm local clock and device time are correct, then confirm the source principal can assume the role and its trust policy accepts that identity. |
| `AWS_MFA_UNSUPPORTED` | The profile has a chained or custom source, unexpected MFA device, or unsupported config. Use **Use Terminal instead** and the organization's normal sign-in; do not enter credentials into a new field. |
| `AWS_MFA_BUSY` or `AWS_MFA_RATE_LIMIT` | Wait for the current attempt to finish or one minute after repeated failed attempts. Sentinel allows one in-app role MFA operation at a time and five attempts per profile per minute. |
| `AWS_MFA_SOURCE_UNAVAILABLE` | Sign in to the source profile with its approved method, then retry. |
| `AWS_PROFILE_CHANGED` or `AWS_ACCOUNT_CHANGED` | The profile configuration or resolved account changed during the operation. Reconnect, verify the account shown in the UI, and start a new scan. |
| `CLI_HISTORY_ENABLED` | Disable AWS CLI history for the selected profile before using Sentinel; the app refuses it to avoid persisting sensitive STS or inventory data. |
| `AWS_CREDENTIALS` or `UNKNOWN_PROFILE` | Check the named profile in `aws configure list-profiles`, update expired credentials through the normal provider, then refresh profiles. |
| `AWS_ACCESS_DENIED` | Check the selected account, Region, role, identity policy, repository policy, permissions boundary, and SCP. Inventory needs `ecr:DescribeRepositories` and `ecr:DescribeImages`. See [AWS access](AWS_ACCESS.md). |
| `AWS_CONNECTION` or `AWS_TIMEOUT` | Confirm VPN, DNS, proxy policy, STS/ECR endpoints, and Region. A successful sign-in does not prove the ECR endpoint is reachable. |
| Account or Region shown in the app is unexpected | Stop before scanning. Check the selected profile, role's target account, SSO account, and Region; reconnect using the correct context. A destination saved for another profile/account/Region will not follow you. |

The app intentionally returns short user-facing errors instead of raw AWS CLI stderr. For deeper diagnosis, use the organization's approved AWS tooling with the same selected profile and Region. Do not post `~/.aws/credentials`, raw STS output, OTPs, launch URLs, or full environment dumps in a public issue.

## Scanner and ECR image access

| Symptom or error code | Recovery |
| --- | --- |
| Scanner unavailable or `TRIVY_UNSAFE_VERSION` | Install or update Trivy to a trusted stable version 0.71.1 or newer, verify `trivy --version`, then select **Check again**. |
| `TRIVY_DB_UNAVAILABLE` | Permit the configured Trivy database registries, including `mirror.gcr.io` and `ghcr.io`, through the network route. Retry after connectivity returns. First use may download multiple gigabytes including the Java database. |
| `TRIVY_DB_METADATA_MISSING` | The database update did not leave valid metadata in the local cache. Check disk space and scanner/cache permissions; after stopping Sentinel, clear the private cache if corrupt and retry the download. |
| Repositories/images appear, but direct scan returns `ECR_PULL_DENIED` | The Mac can read metadata but cannot pull. The selected identity needs the registry token and image pull actions, plus ECR registry/S3 network access. If the restriction is intentional, use an Inspector export for an already monitored image or import an approved build-host SBOM. |
| `SCAN_NETWORK` | For direct mode, check VPN, DNS, the ECR registry endpoint, S3 image-layer route, and database connectivity. ECR API access alone is insufficient for a direct pull. For Inspector mode, the Mac instead needs the Inspector API and export-bucket S3 route. |
| `IMAGE_NOT_FOUND` or `REPOSITORY_NOT_FOUND` | Refresh inventory and verify the account, Region, and digest. Tags may have moved or images may have been deleted. |
| `IMAGE_ARCHIVED` | Restore the image in ECR using your organization's normal process before direct scanning. |
| `PLATFORM_MISMATCH` | Choose the platform Trivy reports for the image and rescan. An index can contain several platforms. |
| `PLATFORM_UNVERIFIED` | Trivy did not identify the image platform reliably. Verify the selected digest is a platform image rather than an index, then retry with the correct platform. Do not attribute an unverified result to the selected target. |
| `IMAGE_TOO_LARGE` or `TRIVY_REPORT_TOO_LARGE` | The image/report exceeds a bounded local limit. Use a smaller artifact or a separately engineered scanner with suitable resource limits; do not remove limits casually. |
| `SCAN_QUEUE_FULL` | One job runs at a time and three may wait. Let a job finish or cancel an unneeded one. |
| `TRIVY_TIMEOUT` or `SCAN_DEADLINE` | Check image/SBOM size, VPN throughput, database route, disk space, and the local scanner. Retry after correcting the bottleneck. |
| Zero findings or **No package targets detected** | Inspect the coverage note and database timestamp. Zero findings only covers known vulnerabilities in detected packages; no package targets means the result is especially limited. |

The scanner uses a local cache under the user's temporary directory. If the cache is corrupted, stop Sentinel before removing its `ecr-sentinel-trivy-cache` directory; a later scan will redownload the databases. Follow your organization's data-retention rules before deleting or exporting results. A first successful database download does not prove the ECR registry or Inspector S3 path is reachable; these are separate network routes.

## SBOM generation and import

| Symptom or error code | Recovery |
| --- | --- |
| Helper says local image is not associated with the ECR digest | The Docker `RepoDigests` for `--image` does not contain the exact supplied repository digest. Check the pushed artifact and platform; do not edit the JSON claim manually. |
| Helper cannot inspect the image | Start Docker and ensure `--image` names an image locally available on the authorized host. A remote-only `buildx --push` artifact may not be loaded locally. |
| Helper says platform differs | Use the local image's actual OS/architecture/variant and create a bundle for that deployed platform. |
| Helper refuses existing output | Choose a new output path. It intentionally never overwrites a prior bundle. |
| `SBOM_TARGET_MISMATCH` | Select the matching account, Region, repository, digest, and platform in Sentinel, or regenerate the bundle from the exact final image. |
| `SBOM_BUNDLE_INVALID` or `SBOM_FORMAT_UNSUPPORTED` | Use a version 1 Sentinel JSON bundle generated by the included helper. A raw standalone CycloneDX/SPDX file lacks the required image association wrapper. |
| `SBOM_TOO_LARGE`, `SBOM_TOO_COMPLEX`, or upload size error | The bundle exceeds the 16 MiB file/SBOM cap, 20 MiB request cap, 100,000 package-entry cap, or parser complexity bounds. Produce a bounded package inventory on an authorized host and review coverage. |
| `SBOM_UPLOAD_BUSY` | Wait for the other import to finish, then retry. |
| `SBOM_SCAN_FAILED` | Check the bundle format, Trivy version, database access, and local disk space. |
| A raw CycloneDX/SPDX file is rejected | The importer expects a version 1 Sentinel bundle with image identity metadata. Generate it using the repository's helper on an authorized host; do not fabricate the wrapper around an unverified SBOM. |

See [the build-host workflow](BUILD_HOST_SBOM.md) for exact generation order and the [security audit](../SECURITY_AUDIT.md) for unsigned provenance and coverage limitations.

## Inspector SBOM export

| Symptom | Recovery |
| --- | --- |
| `INSPECTOR_DESTINATION_NOT_CONFIGURED` or the scan shows setup instead of starting | Save an AWS administrator-approved bucket name, prefix, and KMS key ARN for the connected profile, account, and Region in Sentinel. A setting from another account or Region is not reused. |
| `INSPECTOR_SETTINGS_FULL` | The local settings file reached its bounded size. Remove obsolete destinations in the app or ask the maintainer to review the private settings store; do not expand limits without review. |
| Destination cannot be saved or read (`INSPECTOR_SETTINGS_UNSAFE` or `INSPECTOR_SETTINGS_INVALID`) | The private local settings path is unsafe, inaccessible, or malformed. Check ownership and permissions of Sentinel's Application Support directory; do not replace it with a symlink or a shared directory. If the file is corrupted, back it up privately and remove it while Sentinel is stopped, then re-enter the approved destination. |
| The profile is strictly read-only | An administrator must grant `inspector2:CreateSbomExport`, which AWS classifies as Write. Saving a destination cannot grant permission. If policy forbids that exception, use a matching SBOM supplied by an authorized system. |
| Inspector reports that the resource is unavailable or export fails | Confirm Enhanced Scanning covers the **exact digest** in the selected account and Region. Archived, removed, or unmonitored images cannot provide an Inspector SBOM. |
| `INSPECTOR_CREATE_DENIED` | Check the caller's `inspector2:CreateSbomExport` Write exception, SCPs and boundaries, then the Inspector service's S3/KMS policies. AWS currently requires IAM `Resource: "*"` for this action; the approved destination is confined by S3/KMS controls. |
| `INSPECTOR_STATUS_DENIED` | Check `inspector2:GetSbomExport` for the selected principal and organization denies. |
| Export succeeds but S3 retrieval is denied | Check prefix-scoped `s3:ListBucket`, `s3:GetObject`, `kms:Decrypt`, bucket policy, key policy, and S3 endpoint connectivity for the selected profile. |
| `INSPECTOR_S3_LIST_DENIED` | Confirm the `s3:ListBucket` condition covers the nested `BASE_PREFIX/ecr-sentinel/<unique-id>/` path and that the Mac can reach the approved S3 bucket through VPN/DNS. |
| `INSPECTOR_S3_READ_DENIED` | Confirm `s3:GetObject` for the exported object, `kms:Decrypt` plus key policy, and S3 endpoint access. The ability to list a prefix does not imply object read/decrypt. |
| Destination rejected | Use an approved private bucket and customer-managed symmetric KMS key in the image's Region. Ask the AWS team to configure Inspector service write/encrypt rights using AWS's policy examples. |
| Exported SBOM does not match the selected digest or platform | Refresh inventory and select the exact platform child digest. A multi-platform index and child image may have different digests. Do not manually alter the SBOM metadata. |
| `INSPECTOR_SBOM_PLATFORM_UNVERIFIED` | Choose a Linux OS/architecture platform without a variant. Inspector's SBOM supplies architecture but not enough metadata to verify a variant. For another platform, use an authorized alternative rather than relabeling the SBOM. |
| `INSPECTOR_EXPORT_MISMATCH`, `INSPECTOR_SBOM_UNBOUND`, or `INSPECTOR_SBOM_TARGET_MISMATCH` | Stop and review the export's exact account/resource filters and the selected platform child digest. Sentinel rejected an object whose request metadata or SBOM identity did not match. Do not edit the JSON to force a report. |
| `INSPECTOR_EXPORT_AMBIGUOUS`, `INSPECTOR_EXPORT_CHANGED`, or `INSPECTOR_EXPORT_INVALID` | Sentinel expected one unchanged object under a unique job prefix. Ask the AWS team to inspect the export bucket and object writers; retry with a clean export after resolving the cause. |
| Export wait times out or local job is canceled | Inspector can continue its remote export after the local job stops. Check the bucket's lifecycle policy and retry with the correct image and permissions. |
| Trivy shows zero findings or no package targets | Review the SBOM component count and coverage warning. A third-party SBOM may not have the properties Trivy uses for its most precise matching. |

See [Inspector setup](INSPECTOR_SBOM.md) for a caller policy, S3/KMS prerequisites, and coverage limits.

## After a failed or canceled job

Local cancellation and timeout stop the Mac job. An Inspector export already accepted by AWS can continue, and its S3 object may remain after the app reports cancellation. Ask the bucket owner to use the configured lifecycle rule or approved cleanup process; Sentinel does not delete cloud objects. A server restart also drops in-memory reports, so export any CSV you need before stopping the server. The app keeps at most ten recent normalized reports in memory and does not provide historical triage storage.

If an error is intermittent, note the UTC time, profile **name**, account/Region, digest, platform, scan method, phase, and error code. Share these through an approved internal channel. Do not include the launch fragment, MFA code, raw STS output, AWS credential files, complete SBOM, or proprietary image contents in public issues.
