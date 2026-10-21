# AWS profiles, permissions, and network access

Sentinel runs under one named AWS CLI profile on a Mac. It asks AWS STS for the caller identity, lists ECR repositories and image metadata, and, only for a direct image scan, lets Trivy retrieve the selected image digest. The application does not call ECR managed-scanning APIs.

## Profile setup

Configure the profile using your organization's approved AWS CLI process. A simple role profile that qualifies for in-app MFA has this shape in `~/.aws/config`:

```ini
[profile sentinel-review]
role_arn = arn:aws:iam::111122223333:role/EcrReviewRole
source_profile = approved-source
mfa_serial = arn:aws:iam::111122223333:mfa/operator
region = us-east-1
```

This is an **example only**. Do not commit real account identifiers, MFA device ARNs, access keys, or the contents of `~/.aws` to this repository. The source profile must already exist and be authorized to assume the role. The role also needs a trust policy that permits that source identity; the profile entry alone does not grant access. [AWS explains role-profile setup and MFA](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html).

Sentinel's in-app MFA supports one role step, one `source_profile`, and one MFA prompt. It deliberately refuses a chained role, `credential_source`, `credential_process`, a source profile with its own sign-in step, web-identity input, or a mismatched AWS partition. Use the displayed Terminal fallback or the organization's provider flow for those profiles. In-app role credentials are temporary and held in the local server's memory; they do not update the AWS CLI role cache.

For SSO, run `aws sso login --profile YOUR_SSO_PROFILE`. For a role-profile Terminal fallback, run `aws sts get-caller-identity --profile YOUR_ROLE_PROFILE` and enter the AWS CLI prompt. See the app's profile-specific guidance and the [operator guide](USER_GUIDE.md). If your selected profile enables AWS CLI history, Sentinel will reject it because history can persist sensitive API data.

## Least-privilege ECR actions

Apply the following to the **assumed role** or other selected principal, replacing `REGION`, `ACCOUNT_ID`, and the repository scope. The source principal separately needs `sts:AssumeRole` permission for the exact role ARN, and the role trust policy must admit it. [AWS's ECR authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecr.html) identifies which ECR actions can be scoped to repositories.

### Inventory and SBOM-only use

This is sufficient for Sentinel's ECR metadata calls and SBOM checks, assuming the role can be assumed and the network can reach STS and ECR:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadEcrInventory",
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeRepositories",
        "ecr:DescribeImages"
      ],
      "Resource": "arn:aws:ecr:REGION:ACCOUNT_ID:repository/*"
    }
  ]
}
```

Narrow the repository ARN where practical. Browsing the whole registry requires permission across the repositories you want to see. Sentinel uses `sts:GetCallerIdentity` to verify the account; AWS does not require an explicit allow for that operation. A repository resource policy, permissions boundary, SCP, or explicit deny can further restrict the effective permission.

### Direct image scanning

Add these permissions to the selected principal if policy allows image-layer access on the Mac:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GetRegistryToken",
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Sid": "PullSelectedRepositories",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ],
      "Resource": "arn:aws:ecr:REGION:ACCOUNT_ID:repository/*"
    }
  ]
}
```

This supplements the inventory policy. Replace the repository wildcard with approved repository paths where possible. [AWS documents the registry token and repository-policy behavior](https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html). A successful repository listing does **not** imply the ability to scan layers. If the profile may list but not pull, choose the SBOM workflow; do not weaken a read restriction just to make the scan button work.

The Mac profile does not need `ecr:StartImageScan`, `ecr:DescribeImageScanFindings`, Amazon Inspector permissions, or image-push permissions. The build host that generates an SBOM uses its **own** approved image access and transfer permissions; no SBOM storage service is built into Sentinel.

## Network checklist

| Workflow | Required destinations |
| --- | --- |
| Connection and inventory | AWS STS and ECR API endpoints for the selected Region, using the organization's VPN/DNS route where required. |
| Direct image scan | The above, plus the ECR registry endpoint and the image-layer download route through S3. |
| SBOM scan on the Mac | STS and ECR API for identity and digest verification; no ECR image-layer endpoint. |
| First scan and database refresh | Trivy database registries, including its default `mirror.gcr.io` and `ghcr.io` sources in the current app configuration. |

An ECR API call can work while an image pull fails because the registry or S3 layer route is blocked. [AWS documents ECR endpoint and S3 requirements](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html). Sentinel currently does not expose an internal Trivy database mirror setting; a restricted or air-gapped network requires an application change.

## Permission triage

1. Verify the selected account and Region shown in Sentinel.
2. Confirm the role source can assume the role and its trust policy permits that identity, including MFA conditions.
3. If **Connect to registry** succeeds but the list is empty or denied, check `ecr:DescribeRepositories` and `ecr:DescribeImages` for the relevant repository ARNs, plus organization-level denies.
4. If only a direct scan fails, check `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, repository policies, and network access to ECR/S3.
5. If an SBOM check fails, verify that the bundle refers to the same account, Region, repository, digest, and platform selected in the app. See [troubleshooting](TROUBLESHOOTING.md).
