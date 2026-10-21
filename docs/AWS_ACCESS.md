# AWS profiles, IAM, and network access

Sentinel uses a **named AWS CLI profile** selected in the app. It verifies the caller account with STS, reads ECR repository/image metadata, and performs only the actions for the scan input you choose. It does not call ECR basic-scanning APIs, enable Inspector Enhanced Scanning, or create AWS infrastructure. Permissions must be granted to the **resolved role or principal**, not merely written into `~/.aws/config`.

## Permission matrix

| Workflow | AWS actions needed by the Mac's selected principal | Image layers on this Mac? |
| --- | --- | --- |
| Connect and browse | `ecr:DescribeRepositories`, `ecr:DescribeImages`; `sts:GetCallerIdentity` verifies account identity without an explicit IAM allow | No |
| Import a build-host SBOM | Same ECR inventory actions to verify the selected target; the approved build host has its own image access | No; the bundle file is read locally |
| Scan image layers with Trivy | Inventory plus `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` on approved repositories | **Yes** |
| Inspector SBOM → Trivy | Inventory plus `inspector2:CreateSbomExport`, `inspector2:GetSbomExport`, `s3:ListBucket`, `s3:GetObject`, and `kms:Decrypt` for the approved destination | No; Inspector writes an SBOM to S3 and the Mac downloads those JSON bytes |

The Inspector service also needs its **own** bucket and KMS permissions. AWS labels [`CreateSbomExport` as Write](https://docs.aws.amazon.com/service-authorization/latest/reference/list_inspector2.html), so a strictly read-only role cannot initiate it. The Inspector action currently has no resource-level scope or service condition keys in AWS's authorization table and needs IAM `Resource: "*"`. Its destination is confined by S3/KMS policies and organizational controls. A local bucket setting is not a permission grant or an administrator-owned allowlist. See [Inspector administrator setup](INSPECTOR_SBOM.md).

Sentinel does **not** need `ecr:StartImageScan`, `ecr:DescribeImageScanFindings`, ECR push actions, or image-layer pull actions for either SBOM path. A successful connection proves identity and metadata access only; it does not prove that any scan input is permitted. SCPs, permissions boundaries, session policies, repository/bucket/key resource policies, and explicit denies can further narrow effective access.

## Profile types and MFA

Configure profiles through your organization's approved process. This **fictional example** of a simple role profile belongs in the user's local `~/.aws/config` and must never be copied with real identifiers into the repository:

```ini
[profile sentinel-review]
role_arn = arn:aws:iam::111122223333:role/EcrReviewRole
source_profile = approved-source
mfa_serial = arn:aws:iam::111122223333:mfa/operator
region = us-east-1
```

The source profile must already be usable, the source principal needs `sts:AssumeRole` on this exact role, and the role trust policy must allow that principal and any MFA conditions. The role's own policy must grant the ECR and optional scan actions. [AWS role profiles and MFA](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html) explain the underlying configuration.

Sentinel's **in-app role MFA** handles one `role_arn`, one `source_profile`, and one configured `mfa_serial`. Select the role profile and Region, expand **Need to enter MFA or sign in?**, enter the current six-digit code, and choose **Verify code and connect**. The OTP reaches the loopback server and AWS STS but is not stored in Sentinel's browser session or report. Temporary assumed-role credentials remain in server memory and expire; the AWS CLI role cache remains separate. When the app asks again, use a fresh code. Sentinel deliberately rejects chained roles, custom `credential_process` sources, `credential_source`, web identity, a source profile with its own sign-in step, or an unexpected AWS partition for in-app MFA. Use the displayed Terminal fallback or your provider's sign-in flow for those cases.

| Profile type | Sign-in or fallback | After sign-in |
| --- | --- | --- |
| Simple role profile with `mfa_serial` | Prefer the in-app OTP. If unsupported, run `aws sts get-caller-identity --profile YOUR_ROLE_PROFILE` in Terminal and answer the CLI prompt. | Choose **Retry connection** for that role profile. CLI and in-app role sessions have separate caches. |
| IAM Identity Center (SSO) | `aws sso login --profile YOUR_SSO_PROFILE`; complete browser sign-in. | Select the same profile and retry. |
| IAM user with API MFA | `aws configure mfa-login --profile YOUR_SOURCE_PROFILE`; choose a **new destination profile** at the CLI prompt. | Choose **Refresh profiles**, then select the temporary destination profile. AWS CLI writes those temporary credentials to its profile store. |
| Console-backed `login_session` | `aws login --profile YOUR_PROFILE` with a compatible AWS CLI v2 release; finish provider/browser sign-in. | Select the same profile and retry. |
| Custom provider or chained role | Follow that provider's approved instructions. | Refresh profiles if the provider created a new profile, then retry. |

[AWS documents IAM-user `mfa-login`](https://docs.aws.amazon.com/cli/latest/reference/configure/mfa-login.html), [Identity Center sign-in](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html), and [console-backed `aws login`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html). The `mfa-login` command supports software and hardware OTP, not passkeys or U2F. A profile may be listed even while its credentials are expired. Sentinel rejects a selected profile with AWS CLI `cli_history` enabled because CLI history can persist sensitive AWS API request/response data. Disable that setting for the profile before retrying.

**Credential handling:** The browser does not receive AWS access keys. For direct image scans only, the local server exports the selected profile's credentials into the Trivy child process environment so Trivy can access ECR. With a static IAM-user profile, those could be long-lived keys; prefer temporary role/SSO credentials. For both SBOM paths, local Trivy receives no AWS credentials. The local server uses the selected profile for Inspector and S3 calls. Keep the launch URL private because a holder can control this single-user server while it runs.

## Inventory-only IAM example

Apply to the assumed role or other resolved principal. Replace `REGION`, `ACCOUNT_ID`, and the repository pattern with approved values. This supports inventory and manual SBOM import; it does **not** grant image pulls or Inspector exports:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadApprovedEcrInventory",
      "Effect": "Allow",
      "Action": ["ecr:DescribeRepositories", "ecr:DescribeImages"],
      "Resource": "arn:aws:ecr:REGION:ACCOUNT_ID:repository/*"
    }
  ]
}
```

Narrow the repository path where possible. Broad repository browsing requires authorization across all intended repositories; a policy scoped to one repository will only allow that scope. [ECR's authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecr.html) identifies resource-scoped actions. `sts:GetCallerIdentity` does not need an explicit IAM allow, though an unusable profile or network route still prevents the identity check.

## Direct image-scan extension

If your policy **allows image layers on the Mac**, add the following to the inventory permission. Replace and narrow the ARN:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GetEcrRegistryToken",
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Sid": "PullApprovedEcrImages",
      "Effect": "Allow",
      "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
      "Resource": "arn:aws:ecr:REGION:ACCOUNT_ID:repository/*"
    }
  ]
}
```

The registry authorization token uses `Resource: "*"`; repository pull actions can be restricted to approved ARNs. A repository policy or organization guardrail may also matter. [AWS ECR repository policies](https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html) and the [service authorization table](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecr.html) provide the current IAM details. If ECR inventory works but this mode returns `ECR_PULL_DENIED`, distinguish IAM denial from VPN blockage of the registry or S3 layer route. Do not grant pull actions merely to bypass a deliberate read restriction.

## Inspector export extension

For an already monitored image, the selected principal needs this **separate** capability. The example matches a configured `sentinel-exports` base prefix; Sentinel appends a unique `ecr-sentinel/<job-id>/` path beneath it for each export. Replace every placeholder with AWS-team-approved values and adjust the prefix consistently if your team chooses another. It does not include ECR inventory permissions, which still apply:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequestInspectorSbom",
      "Effect": "Allow",
      "Action": ["inspector2:CreateSbomExport", "inspector2:GetSbomExport"],
      "Resource": "*"
    },
    {
      "Sid": "ListApprovedExportPrefix",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::APPROVED_PRIVATE_BUCKET",
      "Condition": {"StringLike": {"s3:prefix": "sentinel-exports/*"}}
    },
    {
      "Sid": "ReadApprovedExportObjects",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::APPROVED_PRIVATE_BUCKET/sentinel-exports/*"
    },
    {
      "Sid": "DecryptApprovedExportKey",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/APPROVED_KEY_ID"
    }
  ]
}
```

The policy alone cannot make Inspector write objects. The AWS administrator must approve a same-Region private S3 bucket and customer-managed symmetric KMS key and configure their resource policies for the Inspector service. An existing Inspector findings-export destination can be reused if approved. The app does not create those resources, grant IAM permissions, or enable Enhanced Scanning. [Inspector setup](INSPECTOR_SBOM.md) contains the service-policy handoff and validation steps. Since `CreateSbomExport` currently requires `Resource: "*"`, control permitted destinations with the bucket/key policies and an organization-owned approval process; the app's local setting is not an enforcement point.

## Network routes to check

| Task | Required route from the Mac or service |
| --- | --- |
| Connect and browse | Mac → STS and ECR API for selected Region through approved DNS/VPN/proxy path. |
| Direct Trivy image scan | Above, plus Mac → ECR registry and S3 image-layer download route. A VPN path that reaches only the ECR API is insufficient. |
| Manual SBOM import | Mac → STS/ECR API for target verification; private file-transfer route for the bundle; no ECR layer endpoint from the Mac. |
| Inspector SBOM scan | Mac → STS, ECR API, Inspector API, and approved S3 bucket; Inspector service → S3/KMS through AWS service integration. The Mac does not request ECR image layers. |
| Trivy database refresh | Mac → current configured database registries, including `mirror.gcr.io` and `ghcr.io`; disk space for the cache. |

[ECR's VPC endpoint guide](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html) describes the registry and S3 layer dependencies. The app currently has no UI for an internal Trivy database mirror; an air-gapped installation needs an application change. DNS, VPN, corporate proxy, and TLS policy remain organization-specific.

## A safe preflight for a new profile

1. Confirm `aws --version` and `aws configure list-profiles` on the Mac. Do not paste credential file contents into a support ticket.
2. In Sentinel, select the intended profile and Region, complete MFA or provider sign-in, then choose **Connect to registry**.
3. Verify the account ID displayed in the app against an independent approved source. If it is wrong, stop before choosing a scan input.
4. Open the intended repository/image. If inventory fails, check `DescribeRepositories`/`DescribeImages`, role trust and `sts:AssumeRole`, SCP/boundary/repository policy, and STS/ECR network routes.
5. For direct mode, confirm pull authorization **and** registry/S3 layer reachability. For Inspector mode, confirm Enhanced Scanning coverage, the Write exception, destination policies, and S3 read/decrypt. For manual import, confirm the exact matching bundle and its producer route.

See [Troubleshooting](TROUBLESHOOTING.md) for error-code recovery. Never share real account IDs, access keys, MFA serials/codes, STS responses, or the private launch URL in public diagnostics.
