# Operator guide

ECR Sentinel is a single-user application that runs on your Mac. It lists private Amazon ECR images through your configured AWS profile and uses local Trivy to check known package vulnerabilities. It does not invoke ECR managed scanning.

## Before you begin

1. Install Node.js 20 or newer, AWS CLI v2, and Trivy 0.71.1 or newer. Keep Trivy updated to a trusted stable release.
2. Configure a named AWS profile that can access the target account. Connect the VPN if your organization requires it.
3. From the project directory, run `npm ci`, then `npm start`.
4. Open the **complete** private launch URL printed by the server, including `#token=...`. Keep that URL private. The browser removes the fragment from its visible address after opening the session.

The Mac needs ECR inventory permissions to browse. Direct image scans need ECR image-pull permission and network access to the registry and layer storage. If the Mac may not read image layers, use a trusted build-host SBOM bundle; see [AWS access](AWS_ACCESS.md) and [the SBOM workflow](BUILD_HOST_SBOM.md).

## Connect an AWS account

1. Select a named **AWS profile** and enter its **AWS Region**.
2. For a simple role profile with `role_arn`, `mfa_serial`, and one `source_profile`, choose **Need to enter MFA or sign in?**, enter the current six-digit code, and select **Verify code and connect**. The code goes to the local server, then AWS STS; Sentinel does not save it.
3. For SSO, console-backed login, IAM-user MFA, chained roles, or a custom credential provider, follow the sign-in guidance shown for that profile. The role MFA panel also has **Use Terminal instead**.
4. Select **Connect to registry**. Check the account and Region displayed before scanning.

The in-app role session lives in the server process and expires before the AWS session does. It is separate from the AWS CLI's own role cache. A cached CLI session can also let **Connect to registry** succeed. When authentication expires, sign in again and retry. **Refresh profiles** reloads the list after you add a profile.

If the app shows the **Open the launch URL from Terminal** screen, reopen the URL printed by the current server run. Restarting the server generates a different token. **Lock this tab** removes the current tab's access and MFA input; closing the server is the way to discard its in-memory role sessions.

## Find an image

1. Select a repository from the overview or sidebar.
2. Use repository search and **Load more repositories** if needed.
3. In a repository, search by tag or digest, sort by push date or tag, and use **Load more images** when available.
4. Choose **Review & scan** for the image digest.
5. Select the platform you run, such as `linux/amd64` or `linux/arm64`. A multi-platform image needs a separate check for each deployed platform.

Repository and image search work on pages already loaded in the browser; use **Load more** to include additional AWS pages. A tag is useful for display, but the immutable digest is the scan target. Archived images cannot be scanned directly until restored in ECR.

## Check vulnerabilities

### Direct image scan

Choose **Scan image with Trivy**, read the confirmation about image-layer transfer, then **Start Trivy scan**. Trivy reads the selected digest from ECR on this Mac and checks the packages it detects against its local vulnerability database. The first scan can take several minutes while Trivy downloads databases. An image scan transfers image layers and may write temporary analysis data; it requires ECR pull authorization.

### SBOM scan

On an authorized build host, generate a Sentinel bundle from the exact final image after push. Transfer the bundle privately to this Mac. In the image drawer, choose **Import SBOM bundle**, select the JSON file, read the confirmation, and choose **Check SBOM with Trivy**. Sentinel checks account, Region, repository, digest, and platform claims, then asks local Trivy to match vulnerabilities against the packages listed in the SBOM. The Mac does not request image layers for this path.

The bundle's image association and producer are **claims**, not signed provenance. Only import from a trusted source. SBOM mode cannot identify packages omitted from the bundle. See [the build-host guide](BUILD_HOST_SBOM.md).

### Inspector SBOM → Trivy

Use this when your Mac may read ECR inventory but may not pull image layers and the image is already covered by Amazon Inspector Enhanced Scanning. In the image drawer, choose **Inspector SBOM → Trivy**. Enter the approved S3 export bucket, prefix, and KMS key ARN supplied by your AWS team, then start the job. Sentinel asks Inspector for a CycloneDX SBOM of the selected digest, waits for export, retrieves the JSON from S3, checks the image identity and platform, and asks local Trivy to find known CVEs in the listed components. The Mac reads the SBOM object, not ECR image layers. You need Inspector export, S3 read/list, and KMS decrypt permissions in addition to ECR inventory rights.

The app shows progress for the Inspector request, export wait, SBOM retrieval, and Trivy scan. The S3 object can remain after a local job ends or is canceled; your AWS team should set retention for the export bucket. If Inspector does not monitor the image, or if an index digest differs from the platform's child digest in the SBOM, the app stops with a mismatch/coverage error rather than presenting a report for the wrong target. [Inspector setup and limitations](INSPECTOR_SBOM.md).

One local scan runs at a time, with up to three waiting. You can close the image drawer while a scan runs. **Cancel scan** asks for confirmation. A server restart discards active jobs and in-memory reports.

## Review and export

The report shows the scanner version, vulnerability database date, selected platform, detected package types, severity counts, affected package and version, available fix, and advisory link when supplied. SBOM reports identify their source and a normalized SBOM SHA-256. A manual bundle's producer is a claim; an Inspector export is associated with the verified Inspector request and SBOM metadata.

- Use **Search findings** and **Filter by severity** to narrow the displayed list. **Show 100 more findings** reveals more of the current report.
- **Refresh** checks the current server's latest job or report for that profile, account, Region, digest, and platform.
- **Export report** downloads a CSV from the current in-memory report. It includes the report findings, regardless of the current UI filter.
- **Switch AWS profile** returns to the connection screen. Verify the account before beginning a new scan.

A report with no findings means Trivy found no *known vulnerabilities in detected packages* at that database date. It is not proof that an image is safe. A report with no detected packages has limited coverage. Trivy warns that third-party SBOMs, including Inspector exports, may give less precise results than a Trivy-generated SBOM. Offline mode can miss dependencies that require remote resolution, especially some Java packages. Rescan when the image or vulnerability database changes.

## Session and data handling

The server binds only to `127.0.0.1`. API requests require a random per-run token from the launch URL. Sentinel holds up to ten reports in memory and does not persist report history. Selected profile and Region are kept in browser session storage; exports are saved only when requested. Trivy's vulnerability database and analysis cache persist under the Mac user's temporary directory. Review [security and retention details](../README.md#local-data-and-retention) and the [security audit](../SECURITY_AUDIT.md) before using the tool in a higher-risk setting.
