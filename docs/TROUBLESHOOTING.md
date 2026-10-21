# Troubleshooting

Start with the error shown in Sentinel. Most failures are scoped to one profile, Region, network path, image, or SBOM. Direct scans and manual SBOM imports do not need Inspector; the Inspector SBOM option requires that Enhanced Scanning already covers the image.

## Startup and browser session

| Symptom | Likely cause | Recovery |
| --- | --- | --- |
| `npm start` fails because the port is occupied | Another process already listens on port 4173. | Stop the old server or run `PORT=4180 npm start`, then open the newly printed URL. |
| The page says **Open the launch URL from Terminal** | The tab lacks the current server's launch token, or an old server was restarted. | Open the complete URL printed by the **current** `npm start` process, including `#token=...`. Do not share the token. |
| The page loads but API actions fail with an invalid token | A plain loopback URL was opened, the tab was locked, or the server restarted. | Reopen the current private launch URL. |
| **Lock this tab** does not stop another open tab | Locking clears that tab's browser token and MFA field; the server session still exists. | Stop the local server to end its in-memory role sessions and invalidate the per-run token. |
| Profiles do not appear | AWS CLI v2 is missing from the process path, no named profile exists, or configuration changed after loading. | Verify `aws --version` and `aws configure list-profiles` in the same Mac environment; then choose **Refresh profiles** or restart the app. |

The app is started with `npm start` in this version. In-app MFA entry removes the Terminal prompt for supported roles, but a double-click macOS launcher is not yet packaged.

## AWS connection and MFA

| Symptom or error code | Recovery |
| --- | --- |
| `AWS_MFA_REQUIRED` or `AWS_SESSION_EXPIRED` | For a supported role, enter a fresh six-digit code under **Need to enter MFA or sign in?**. For SSO or custom providers, complete the displayed provider/CLI sign-in and select **Retry connection**. |
| `AWS_MFA_FAILED` | Use the current code from the configured device. Confirm local clock and device time are correct, then confirm the source principal can assume the role and its trust policy accepts that identity. |
| `AWS_MFA_UNSUPPORTED` | The profile has a chained or custom source, unexpected MFA device, or unsupported config. Use **Use Terminal instead** and the organization's normal sign-in; do not enter credentials into a new field. |
| `AWS_MFA_BUSY` or `AWS_MFA_RATE_LIMIT` | Wait for the current attempt to finish or one minute after repeated failed attempts. Sentinel allows one in-app role MFA operation at a time and five attempts per profile per minute. |
| `AWS_MFA_SOURCE_UNAVAILABLE` | Sign in to the source profile with its approved method, then retry. |
| `AWS_PROFILE_CHANGED` or `AWS_ACCOUNT_CHANGED` | The profile configuration or resolved account changed during the operation. Reconnect, verify the account shown in the UI, and start a new scan. |
| `CLI_HISTORY_ENABLED` | Disable AWS CLI history for the selected profile before using Sentinel; the app refuses it to avoid persisting sensitive STS or inventory data. |
| `AWS_CREDENTIALS` or `UNKNOWN_PROFILE` | Check the named profile in `aws configure list-profiles`, update expired credentials through the normal provider, then refresh profiles. |
| `AWS_ACCESS_DENIED` | Check the selected account, Region, role, identity policy, repository policy, permissions boundary, and SCP. Inventory needs `ecr:DescribeRepositories` and `ecr:DescribeImages`. See [AWS access](AWS_ACCESS.md). |
| `AWS_CONNECTION` or `AWS_TIMEOUT` | Confirm VPN, DNS, proxy policy, STS/ECR endpoints, and Region. A successful sign-in does not prove the ECR endpoint is reachable. |

The app intentionally returns short user-facing errors instead of raw AWS CLI stderr. For deeper diagnosis, use the organization's approved AWS tooling with the same selected profile and Region. Do not post `~/.aws/credentials`, raw STS output, OTPs, launch URLs, or full environment dumps in a public issue.

## Scanner and ECR image access

| Symptom or error code | Recovery |
| --- | --- |
| Scanner unavailable or `TRIVY_UNSAFE_VERSION` | Install or update Trivy to a trusted stable version 0.71.1 or newer, verify `trivy --version`, then select **Check again**. |
| `TRIVY_DB_UNAVAILABLE` | Permit the configured Trivy database registries, including `mirror.gcr.io` and `ghcr.io`, through the network route. Retry after connectivity returns. First use may download multiple gigabytes including the Java database. |
| Repositories/images appear, but direct scan returns `ECR_PULL_DENIED` | The Mac can read metadata but cannot pull. The selected identity needs the registry token and image pull actions, plus ECR registry/S3 network access. If the restriction is intentional, use an Inspector export for an already monitored image or import an approved build-host SBOM. |
| `SCAN_NETWORK` | Check VPN, DNS, the ECR registry endpoint, S3 image-layer route, and database connectivity. ECR API access alone is insufficient for a direct pull. |
| `IMAGE_NOT_FOUND` or `REPOSITORY_NOT_FOUND` | Refresh inventory and verify the account, Region, and digest. Tags may have moved or images may have been deleted. |
| `IMAGE_ARCHIVED` | Restore the image in ECR using your organization's normal process before direct scanning. |
| `PLATFORM_MISMATCH` | Choose the platform Trivy reports for the image and rescan. An index can contain several platforms. |
| `IMAGE_TOO_LARGE` or `TRIVY_REPORT_TOO_LARGE` | The image/report exceeds a bounded local limit. Use a smaller artifact or a separately engineered scanner with suitable resource limits; do not remove limits casually. |
| `SCAN_QUEUE_FULL` | One job runs at a time and three may wait. Let a job finish or cancel an unneeded one. |
| `TRIVY_TIMEOUT` or `SCAN_DEADLINE` | Check image/SBOM size, VPN throughput, database route, disk space, and the local scanner. Retry after correcting the bottleneck. |
| Zero findings or **No package targets detected** | Inspect the coverage note and database timestamp. Zero findings only covers known vulnerabilities in detected packages; no package targets means the result is especially limited. |

The scanner uses a local cache under the user's temporary directory. If the cache is corrupted, stop Sentinel before removing its `ecr-sentinel-trivy-cache` directory; a later scan will redownload the databases. Follow your organization's data-retention rules before deleting or exporting results.

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

See [the build-host workflow](BUILD_HOST_SBOM.md) for exact generation order and the [security audit](../SECURITY_AUDIT.md) for unsigned provenance and coverage limitations.

## Inspector SBOM export

| Symptom | Recovery |
| --- | --- |
| Inspector reports that the resource is unavailable or export fails | Confirm Enhanced Scanning covers the **exact digest** in the selected account and Region. Archived, removed, or unmonitored images cannot provide an Inspector SBOM. |
| `AccessDenied` when creating or checking the export | Check `inspector2:CreateSbomExport` and `inspector2:GetSbomExport` for the selected profile, plus SCPs and permission boundaries. Verify the approved bucket/KMS service policies. |
| Export succeeds but S3 retrieval is denied | Check prefix-scoped `s3:ListBucket`, `s3:GetObject`, `kms:Decrypt`, bucket policy, key policy, and S3 endpoint connectivity for the selected profile. |
| Destination rejected | Use an approved private bucket and customer-managed symmetric KMS key in the image's Region. Ask the AWS team to configure Inspector service write/encrypt rights using AWS's policy examples. |
| Exported SBOM does not match the selected digest or platform | Refresh inventory and select the exact platform child digest. A multi-platform index and child image may have different digests. Do not manually alter the SBOM metadata. |
| Export wait times out or local job is canceled | Inspector can continue its remote export after the local job stops. Check the bucket's lifecycle policy and retry with the correct image and permissions. |
| Trivy shows zero findings or no package targets | Review the SBOM component count and coverage warning. A third-party SBOM may not have the properties Trivy uses for its most precise matching. |

See [Inspector setup](INSPECTOR_SBOM.md) for a caller policy, S3/KMS prerequisites, and coverage limits.
