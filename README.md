# ECR Sentinel

A local Mac application for finding known package vulnerabilities in private Amazon ECR images. Sentinel uses a named AWS CLI profile to list repositories and immutable image digests. It runs [Trivy](https://trivy.dev/docs/latest/advanced/private-registries/ecr/) against either image layers the profile may pull, an SBOM bundle produced from the final image on an authorized build host, or a CycloneDX SBOM exported by Amazon Inspector for an already monitored image. The two SBOM paths transfer package inventory to the Mac without pulling image layers there. Inspector supplies inventory; Trivy performs the local CVE match.

## Product brief

- **User:** an engineer or security analyst reviewing private ECR images from one Mac.
- **Problem:** operators need an on-demand Trivy report while working within different ECR image-access policies, including profiles that may list images but cannot pull layers.
- **Workflow:** select a profile and Region → authenticate → verify the account → browse repositories and image digests → choose the deployed platform → choose an authorized scan input → review CVEs and coverage → optionally export CSV. The Inspector path has one-time destination setup, then one-click exports.
- **Views:** connection and authentication guidance, repository overview, image inventory, scan methods and progress, findings and export.
- **Data:** AWS profiles, repositories, image digests/tags, Inspector export jobs and S3 destinations, SBOM provenance, local scan jobs, package vulnerability findings. A tag is display context; the digest identifies the artifact.
- **Edge cases:** expired MFA/SSO sessions, missing Inspector or S3/KMS permissions, unmonitored or archived images, mismatched digest/platform, missing image-pull permission, network or database outage, multi-platform indexes, malformed SBOMs, and interrupted scans.
- **Assumptions:** one local operator, private ECR, AWS CLI v2 and a trusted named profile, and Trivy installed on the Mac. Inspector export requires existing Enhanced Scanning coverage plus an administrator-approved S3 bucket and KMS key in the image's Region. A strictly read-only AWS profile cannot request the export. Direct image scanning requires pull access; the build-host path requires an authorized host and private transfer.
- **Done for this version:** live ECR inventory and three scan paths, one-time Inspector destination setup with one-click subsequent scans, bounded local jobs, responsive reports, loopback-only access, clear failure states, and passing checks. Live Inspector export and private image access still require verification with an authorized AWS account.

## Choose the right scan path

| Path | What must already exist | Mac profile needs beyond ECR inventory | What reaches the Mac |
| --- | --- | --- | --- |
| **Scan image with Trivy** | Image in ECR; Trivy installed | ECR registry token and image-layer pull actions | Image layers and scanner databases |
| **Import build-host SBOM** | Matching bundle generated from the final image by an authorized host | No additional AWS action for the import | The private SBOM bundle and scanner databases |
| **Inspector SBOM → Trivy** | Inspector Enhanced Scanning coverage; approved S3 bucket, prefix, and KMS key | `inspector2:CreateSbomExport` and `GetSbomExport`, prefix-scoped S3 list/read, KMS decrypt | The Inspector SBOM JSON and scanner databases |

All paths use `ecr:DescribeRepositories` and `ecr:DescribeImages` for inventory and digest checks. `CreateSbomExport` is an AWS **Write** action and cannot be used by a strictly read-only role. Sentinel cannot create the bucket, key, policies, or IAM exception. A successful ECR inventory connection does not imply that a scan path is authorized. [AWS access](docs/AWS_ACCESS.md) and the [Inspector handoff](docs/INSPECTOR_SBOM.md#request-for-the-aws-administrator) cover the exact boundary.

## Run on your Mac

Requirements: macOS, Node.js 20 or newer, AWS CLI v2, Trivy 0.71.1 or newer from a trusted source, and a named AWS profile with access to the desired account. Install Trivy with the [official Homebrew method](https://www.trivy.dev/docs/latest/getting-started/installation/):

```bash
brew install trivy
trivy --version
```

```bash
git clone https://github.com/jaysonguglietta/ECRSentinel.git
cd ECRSentinel
npm ci
npm start
```

Open the **exact launch URL printed by `npm start`**, including its `#token=...` fragment. A plain `http://127.0.0.1:4173/` URL can display the page but cannot access the API. Select your profile and Region, then choose a repository, image digest, and platform. To use another local port, run `PORT=4180 npm start`.

Restarting the server creates a new private launch URL; reopen that URL in any older browser tab. Once connected, use **Switch AWS profile** in the workspace or image review drawer to return to the profile selector. For **Inspector SBOM → Trivy**, enter the administrator-approved export bucket, prefix, and KMS key once in the app. Later scans of images in that profile, account, and Region use the saved destination with one click. If your role is strictly read-only, give the AWS team the [administrator handoff](docs/INSPECTOR_SBOM.md#request-for-the-aws-administrator) first; Sentinel cannot initiate an Inspector export until they grant `CreateSbomExport`.

### Documentation by task

| If you need to… | Start here |
| --- | --- |
| Connect for the first time, browse images, scan, filter, and export | [Operator guide](docs/USER_GUIDE.md) |
| Set up role MFA, understand profile limitations, or request least-privilege IAM and network access | [AWS access guide](docs/AWS_ACCESS.md) |
| Ask an AWS administrator to enable Inspector exports and operate the one-time destination setup | [Inspector SBOM guide](docs/INSPECTOR_SBOM.md) |
| Generate a bundle after a manual or other-system build and import it without ECR pulls on the Mac | [Build-host SBOM guide](docs/BUILD_HOST_SBOM.md) |
| Diagnose a failed connection, export, pull, database update, or mismatch | [Troubleshooting](docs/TROUBLESHOOTING.md) |
| Review routes, trust boundaries, storage, and job lifecycle | [Architecture and local API](docs/ARCHITECTURE.md) |
| Work on code or run release checks | [Development and verification](docs/DEVELOPMENT.md) |
| Report a vulnerability or assess deployment risk | [Security policy](SECURITY.md) and [adversarial audit](SECURITY_AUDIT.md) |

### Profiles that require MFA

For a role profile configured with `role_arn` and `mfa_serial`, select the profile and Region in Sentinel, enter the current six-digit code in the **One-time MFA code** field, and choose **Verify code and connect**. The local server uses the configured AWS profile to establish a temporary role session. It does not put the code in a command argument or save the code in browser storage or reports. The app keeps the resulting temporary credentials in server memory while they are valid; enter a new code after the session expires or the server restarts.

The in-app session and the AWS CLI's Terminal session have separate caches. If your role profile has a custom sign-in setup that this flow cannot resolve, expand **Use Terminal instead** and run the displayed command. Other profile types still use the AWS CLI or their identity provider in Terminal or a browser. The corresponding fallback commands are:

| Profile type | Command to run in Terminal | Profile to select afterward |
|---|---|---|
| Assume-role profile with `mfa_serial` | `aws sts get-caller-identity --profile YOUR_ROLE_PROFILE` | The same role profile. Use this as a Terminal fallback; the CLI prompts for the one-time code and caches its own role session. |
| IAM Identity Center (SSO) | `aws sso login --profile YOUR_SSO_PROFILE` | The same SSO profile. Complete the browser sign-in and MFA. |
| IAM user whose API policy requires MFA | `aws configure mfa-login --profile YOUR_SOURCE_PROFILE` | Enter the OTP and choose a new destination profile at the CLI prompt. Then choose **Refresh profiles** in Sentinel and connect using that destination profile. Do not choose the source profile as the destination. |
| Console-backed `login_session` profile | `aws login --profile YOUR_PROFILE` | The same profile after browser sign-in. This requires AWS CLI 2.32.0 or newer. |

The IAM-user `mfa-login` command writes temporary credentials to the destination AWS profile and supports software and hardware one-time password devices, but not passkeys or U2F. If your profile uses a custom `credential_process` or a chained identity provider, follow that provider's normal sign-in procedure. A profile can appear in the selector while its credentials are expired; authenticating in Terminal restores the CLI session used by the app.

Prefer an assumed-role or IAM Identity Center profile with temporary credentials. Standard IAM-user profiles with static keys can also work, but those long-lived keys are passed to the local Trivy process during an image scan.

The app uses the AWS SDK credential provider to resolve role-profile MFA and uses AWS CLI for inventory and direct image access. Run `npm ci` after copying the project or updating its dependencies.

### AWS permissions

The selected role needs permissions to discover ECR repositories and image digests. **Direct image scans also need permission to pull image layers.** Imported build-host bundles need only ECR inventory permission on the Mac. The Inspector export path additionally needs `inspector2:CreateSbomExport`, `inspector2:GetSbomExport`, prefix-scoped S3 list/read, and KMS decrypt; the Inspector service needs write/encrypt access to the approved destination. AWS classifies `CreateSbomExport` as [Write](https://docs.aws.amazon.com/service-authorization/latest/reference/list_inspector2.html), so a strictly read-only role **cannot start this workflow** until an AWS administrator grants that exception and prepares the bucket/key. The action currently requires IAM `Resource: "*"`; S3/KMS policies confine the destination. Sentinel can remember the destination once and start future exports with one click, but cannot create AWS resources or override IAM permissions. Neither SBOM path requires ECR layer-pull permission on this Mac. The illustrative policy below is for direct image scanning and uses separate registry and repository scopes. Replace `REGION` and `ACCOUNT_ID`; narrow the repository ARN if appropriate. `sts:GetCallerIdentity` does not need an explicit IAM allow. AWS Organizations SCPs, permission boundaries, and repository policies may impose further limits. See [AWS's ECR pull permissions](https://docs.aws.amazon.com/AmazonECR/latest/userguide/ECR_on_ECS.html), [service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecr.html), and the [Inspector setup guide](docs/INSPECTOR_SBOM.md).

A profile can successfully list repositories and images yet fail a Trivy scan if it lacks pull permissions. For example, `ecr:BatchGetImage` is required on the repository. If that happens, use **Switch AWS profile** or ask an AWS administrator to grant the narrow pull actions below.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RegistryLogin",
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Sid": "InspectAndPullApprovedImages",
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeRepositories",
        "ecr:DescribeImages",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ],
      "Resource": "arn:aws:ecr:REGION:ACCOUNT_ID:repository/*"
    }
  ]
}
```

For an imported build-host bundle, the Mac profile only needs ECR inventory actions. The build host must have its own authorized access to the final image and deliver the file privately. For the **Inspector export** path, use the [Inspector and S3/KMS administrator handoff](docs/INSPECTOR_SBOM.md#request-for-the-aws-administrator). An existing Inspector findings-export bucket and key can be reused if approved. No S3 bucket is required for manual import; an approved bucket is required for Inspector exports.

### Generate an SBOM bundle on the build host

The included helper turns a **locally available final Docker image** into a CycloneDX bundle linked to an ECR repository digest and platform. Copy this project folder to the trusted build host, run `npm ci` there, then run the helper **after pushing the exact image**. Docker's local `RepoDigests` for `--image` must include the ECR `repository@digest` supplied in the command. This check prevents labeling an unrelated local image as the selected ECR image. Record the immutable digest from your push result or [ECR `DescribeImages`](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_DescribeImages.html); do not rely on a mutable tag as the identity. For a multi-platform image, run the helper for each platform you intend to assess. The account ID and image name below are fictional examples.

```bash
node scripts/generate-sbom-bundle.mjs \
  --image 111122223333.dkr.ecr.us-east-1.amazonaws.com/team/service:build-42 \
  --account 111122223333 \
  --region us-east-1 \
  --repository team/service \
  --digest sha256:REPLACE_WITH_THE_64_HEX_DIGIT_ECR_DIGEST \
  --platform linux/amd64 \
  --output ./service-amd64.sentinel-sbom.json
```

The helper requires Node.js 20+, Docker with that image available locally, and Trivy 0.71.1+. It checks the image's OS/architecture and repository digest, then passes Docker's immutable **local image ID** to Trivy with `--image-src=docker`; a tag change during generation cannot redirect the scan. It checks the local image again afterward, caps analyzed images at 4 GB, captures Trivy's SBOM output with a 16 MiB process limit, validates the CycloneDX result, and writes a new file with mode `0600`. It refuses to overwrite an existing file. The file is sensitive inventory data: transfer it through an approved private channel and retain it according to your policy. If your build uses `docker buildx --push` without loading the image locally, the helper will refuse to create a bundle; arrange an authorized build step with local image access or a separately authorized worker. Running this helper on the Mac cannot create an SBOM for an ECR image the Mac is forbidden to read.

On the Mac, select the **same** account, repository, digest, and platform in Sentinel, then import the matching bundle to run `trivy sbom` locally. This performs vulnerability matching against the Mac's Trivy database without transferring ECR image layers to the Mac. The SBOM must originate from the final image, since a source-code-only SBOM may omit operating-system packages and installed artifacts. [Trivy documents CycloneDX generation and SBOM scanning](https://trivy.dev/docs/latest/guide/supply-chain/sbom/). The report's SHA-256 covers normalized SBOM JSON, not the original file bytes. Bundle metadata, that hash, and a Docker `RepoDigests` check are consistency evidence, not a cryptographic signature; use signed provenance or trusted artifact storage if the transfer channel is not trusted.

### How the local scan works

Sentinel resolves the selected CLI profile, lists repositories and images through ECR, then asks Trivy to fetch the selected image by immutable digest. Trivy runs on your Mac, identifies operating system and supported language packages, checks them against its vulnerability database, and returns a JSON report. [Trivy's image scanner](https://trivy.dev/docs/latest/guide/scanner/vulnerability/) covers known package vulnerabilities; a scan with no findings cannot prove that an image has no vulnerabilities.

**Direct local image scanning transfers image-layer bytes to this Mac.** Trivy may temporarily write analysis data even without a separate `docker pull`. This still counts as image access and requires ECR pull permissions. Both SBOM paths transfer package inventory instead of image layers and run local Trivy against it. The build-host path imports a file generated from the final image; the Inspector path exports an SBOM for an already monitored ECR image to S3. Neither path can detect packages omitted from its SBOM, and neither provides the filesystem coverage of an image-layer scan. [ECR image metadata](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_DescribeImages.html) alone cannot reveal installed packages.

Sentinel does not call ECR basic scan APIs or present Inspector's CVE findings as its own. The Inspector SBOM option relies on **existing Inspector Enhanced Scanning** coverage; AWS runs that analysis independently. Trivy then performs a local match against the exported SBOM. The other two paths do not require Inspector.

Choose the platform that matches the deployed workload, such as `linux/amd64` or `linux/arm64`. For a multi-platform image index, a scan covers the **selected platform**, so scan each deployed platform separately. The digest avoids a mutable tag changing between selection and analysis. Results are a snapshot of the image and vulnerability database at scan time; rescan when either changes.

Before the first scan, Sentinel downloads Trivy's vulnerability database. It downloads the Java database if a scan needs it. In a development check, the two databases together used about **3 GB of local cache**, and the Java download took roughly 90 seconds; size and time vary by release and network. Allow several gigabytes of free disk space for Java images. Trivy's default database registries include `mirror.gcr.io` and `ghcr.io`; this version requires access to them because the app fixes Trivy's database sources and attempts an update on each server run. [Internal mirrors and air-gap use](https://trivy.dev/docs/latest/guide/advanced/air-gap/) would require a future app change. ECR image layers are stored in S3, so a Mac whose VPN can reach the ECR API may still fail to pull layers if it cannot reach the registry and S3 download URLs. See [ECR endpoint and S3 layer requirements](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html).

## Security design

- The HTTP server binds to `127.0.0.1`; it checks `Host` and `Origin`, does not enable CORS, and requires a random per-run token on every API request. The token is printed in a launch URL in the starting Terminal and is not embedded in the publicly retrievable app page.
- AWS CLI calls run server-side with `execFile`, fixed operations, validated inputs, and no shell. For **direct image scans**, Sentinel passes the selected role's temporary credentials to the Trivy child process. **SBOM checks do not pass AWS credentials to Trivy.** Inspector export and S3 reads use the selected AWS profile through server-side AWS CLI calls. A static IAM-user profile can supply long-lived keys in direct mode. Browser code never receives AWS credentials.
- For configured role MFA, the code is sent in a token-protected JSON request to the loopback server and then to AWS through the SDK's MFA callback. It is not placed in a CLI command line, saved to disk by Sentinel, logged, or included in reports. Temporary role credentials remain in server memory until expiry or shutdown. Other identity-provider sign-in remains with the AWS CLI or the provider's browser flow. AWS CLI role and SSO sessions have their own cache, and `aws configure mfa-login` writes temporary IAM-user credentials to the chosen AWS profile on disk.
- The app checks the selected profile's `cli_history` setting before AWS calls and refuses profiles with history enabled. [AWS CLI history](https://docs.aws.amazon.com/cli/latest/userguide/data-protection.html) can persist API request and response data, including sensitive STS responses, in its local history database. Disable it for the selected profile if the app reports this error.
- AWS endpoint overrides are ignored by the CLI child process, while normal DNS and VPN routing remain available.
- Inspector destination settings are validated against the verified profile/account/Region and saved in an owner-only local file. The scan API uses that saved destination; it does not accept a bucket/key on each scan. A launch-token holder can still change the setting, so administrator-approved destination enforcement belongs in IAM, S3, and KMS policy.
- CSP restricts scripts and styles to local files. AWS-provided strings are inserted as text, advisory links require HTTPS, and CSV cells are protected against spreadsheet formula injection.
- Trivy reads untrusted image or SBOM content with your Mac user's privileges. Run Sentinel as a standard user and keep Trivy updated. The app selects image references from ECR inventory rather than accepting arbitrary registry URLs. Imported bundles and Inspector exports are bounded, bound to the selected image, and stored temporarily in a private file during local scanning. An Inspector SBOM is checked against its account, image digest, resource type, and architecture; it may omit repository and Region, which remain associated with the verified export request. Trivy's [local cache](https://trivy.dev/docs/latest/configuration/cache/) stores its vulnerability database and may store scan analysis data.
- Database downloads occur before credentials are passed to Trivy. During image analysis, database updates and remote dependency lookup are disabled, and only the vulnerability scanner runs. This limits Trivy's intended outbound activity while it holds the selected profile's credentials to pulling the selected ECR image and its layers. It also means some Java packages may be unidentified without remote lookup.
- One scan runs at a time, with at most three queued. Scans have a 15-minute process limit, Trivy's experimental 4 GB image-size cap, and bounded report output and finding counts. The UI lets you cancel a queued or running scan after confirmation.

The launch token protects against unauthenticated local HTTP requests and malicious websites. Keep the launch URL private; another person with that URL can control this single-user app while it runs. Processes under the same macOS account remain inside the trust boundary. Protect the local AWS profile and prefer temporary role or SSO credentials with least-privilege IAM. Sentinel requires Trivy 0.71.1 or newer; older releases include a [path traversal issue in overridden database repositories](https://github.com/aquasecurity/trivy/security/advisories/GHSA-mcj4-mphf-j9ff), and a [specific 0.69.4 release was compromised](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23). Sentinel uses Trivy's fixed default database repositories and disables local Trivy configuration overrides.

### Local data and retention

The server retains at most ten recent normalized reports **in memory** for the current run. Stopping the server discards them. SBOM bytes are held while queued or scanning; normal completion and cancellation remove the private temporary file. A hard process kill can leave a temporary SBOM file behind. At the next scanner-cache initialization, Sentinel removes its own temporary SBOM files older than one hour. **Inspector export objects remain in S3** until the bucket's lifecycle or an authorized administrator removes them; stopping or canceling a local job does not guarantee a remote export stops. CSV export saves a report only when you request it from the browser. The selected profile and Region are kept in browser tab session storage for reload convenience and cleared by **Lock this tab**; OTPs and AWS credentials are not stored there. The nonsecret Inspector bucket, prefix, and KMS ARN persist across app restarts in `~/Library/Application Support/ECR Sentinel/inspector-destinations.json` by default. Its directory is owner-only (mode `0700`) and the file is mode `0600`. **Lock this tab** leaves these settings in place; use the app's remove control to forget a destination. `ECR_SENTINEL_DATA_DIR` can set a different absolute, private directory.

Trivy's vulnerability databases and analysis cache live under the private `ecr-sentinel-trivy-cache` directory inside your Mac user's operating-system temporary directory. The cache persists across app restarts to avoid repeated multi-gigabyte downloads, but macOS can eventually remove temporary files. Delete this cache directory if your data-retention policy requires it. A database update is attempted on the first scan of each server run and every six hours thereafter. The report's database timestamp comes from Trivy's upstream database metadata.

## Checks

```bash
npm test
node --check server.js
node --check src/aws-cli.js
node --check src/api.js
node --check src/inspector-settings.js
node --check src/trivy.js
node --check public/app.js
node --check public/auth-guide.js
node --check scripts/generate-sbom-bundle.mjs
```

The automated suite, JavaScript syntax checks, and `npm audit --omit=dev` are run for changes. Tests cover AWS CLI/MFA isolation, launch-token access, direct and SBOM credential separation, saved Inspector destination scoping and persistence, exact export filters and destination, stage-specific permission errors, bounded S3 retrieval, image identity checks, cancellation, report retention, and the build-host helper. A test bundle previously completed a real local `trivy sbom` run without ECR layer access. A live Inspector export, genuine build-host bundle, live MFA challenge, and private ECR scan still need testing with an authorized AWS environment.

## Current scope and next improvements

The app shows one account and Region at a time. Repository/image search and sort operate on inventory pages loaded so far; CSV export includes the complete current in-memory findings report. Each scan covers one selected platform and only known package vulnerabilities; both SBOM modes cover only packages listed in their file. Trivy warns that a third-party SBOM can yield less precise matching than its own SBOM. The app does not provide secret scanning, malware analysis, exploitability proof, triage persistence, background scheduling, or deployment gates. The latest reports are available only while the server remains running.

The highest-value next steps are: (1) run a live Inspector/S3/KMS export against a monitored image and test MFA expiry and multi-platform child digests; (2) enforce destinations with administrator-controlled bucket/key/prefix policy and verify bucket write policy and lifecycle; (3) add signed build-host SBOM provenance and stronger Inspector object evidence before considering deployment gates; (4) isolate local Trivy with OS resource and filesystem limits; and (5) add persisted, encrypted report triage and bounded rescans.

## References

- [Trivy installation](https://www.trivy.dev/docs/latest/getting-started/installation/)
- [Trivy ECR authentication](https://trivy.dev/docs/latest/advanced/private-registries/ecr/)
- [Trivy vulnerability scanning](https://trivy.dev/docs/latest/guide/scanner/vulnerability/)
- [Trivy JSON reporting](https://trivy.dev/docs/latest/configuration/reporting/)
- [Trivy database locations and updates](https://trivy.dev/docs/latest/configuration/db/)
- [Trivy restricted-network options](https://trivy.dev/docs/latest/guide/advanced/air-gap/)
- [Inspector SBOM exports](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html)
- [Trivy SBOM scanning and third-party coverage caveat](https://trivy.dev/docs/latest/guide/target/sbom/)
- [AWS CLI export credentials](https://docs.aws.amazon.com/cli/latest/reference/configure/export-credentials.html)
- [ECR image pull permissions](https://docs.aws.amazon.com/AmazonECR/latest/userguide/ECR_on_ECS.html)
- [ECR VPC endpoints and S3 layer storage](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html)
- [AWS CLI role profiles and MFA](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html)
- [IAM Identity Center CLI sign-in](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [IAM-user `mfa-login`](https://docs.aws.amazon.com/cli/latest/reference/configure/mfa-login.html)
- [Console-backed `aws login`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html)
