# Inspector SBOM export → local Trivy

This workflow lets the Mac assess a private ECR image **without ECR image-layer pull permission**. Amazon Inspector exports a CycloneDX SBOM for an image it already monitors, writes the JSON to an approved S3 bucket, and Sentinel retrieves that SBOM. Local `trivy sbom` then matches known vulnerabilities against the components in the exported inventory. The result is a **Trivy** report; Sentinel does not present Inspector's own CVE findings as Trivy findings.

The distinction matters: this path uses Inspector's existing analysis to obtain packages. It cannot derive an SBOM from ECR repository metadata alone, enable Enhanced Scanning, or inspect an unmonitored image. AWS requires an S3 destination on every [`CreateSbomExport`](https://docs.aws.amazon.com/inspector/v2/APIReference/API_CreateSbomExport.html) request. Sentinel remembers the approved destination locally **once per verified profile, account, and Region**, then supplies it automatically on future one-click scans. The API returns an export ID, not the SBOM bytes. [AWS's SBOM export guide](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html) explains the service behavior.

## Feasibility for a read-only profile

The selected role needs `inspector2:CreateSbomExport`, which AWS classifies as **Write**. If the role is strictly read-only and the AWS team cannot grant that exception, this workflow **cannot run**, even if someone gives you a bucket name. It also cannot run if no principal or host may read the image **and** Inspector does not already monitor it. If a separately authorized system can supply a bundle from the final image, the [manual build-host path](BUILD_HOST_SBOM.md) uses only ECR inventory permission on this Mac. [Inspector's service authorization table](https://docs.aws.amazon.com/service-authorization/latest/reference/list_inspector2.html) currently gives `CreateSbomExport` no resource-level scope or service condition keys; the caller statement therefore uses `Resource: "*"`. Confinement of the export destination comes from S3/KMS policy and AWS administration, not from an Inspector resource ARN in caller IAM.

## One-time AWS administrator setup

The AWS administrator must complete these steps **before** the operator saves a destination in Sentinel. An existing private bucket and customer-managed symmetric KMS key configured for Inspector findings export may be reused if approved; [AWS explicitly allows that reuse](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html).

1. **Confirm coverage.** Verify Amazon Inspector Enhanced Scanning is enabled for the relevant ECR registry/repository and that Inspector actively monitors the exact image digest in the selected account and Region. An inactive, archived, deleted, or not-yet-covered image will not yield the intended SBOM. [Inspector's ECR scanning guide](https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html) describes coverage and rescans.
2. **Choose an export location.** Approve a private S3 bucket in the image's Region, with a dedicated base prefix such as `sentinel-exports`. Enable S3 Block Public Access, define lifecycle expiration for sensitive SBOM objects, and configure audit logging appropriate to your organization. Decide whether an existing Inspector findings-export location can be shared or a separate one is needed.
3. **Choose a key.** Use a customer-managed **symmetric** KMS key in the same Region. The app saves a full key ARN such as `arn:aws:kms:REGION:ACCOUNT_ID:key/APPROVED_KEY_ID`, not an alias. Confirm its policy permits Inspector to encrypt exports and the caller to decrypt the resulting S3 object. Cross-account storage/key arrangements need approval from all resource owners.
4. **Authorize the Inspector service.** Add bucket and key policy statements for the appropriate Inspector service principal. AWS's [S3 policy example](https://docs.aws.amazon.com/inspector/latest/user/findings-managing-exporting-reports.html) uses `s3:PutObject`, `s3:PutObjectAcl`, and `s3:AbortMultipartUpload` on the export object path. Its [KMS example](https://docs.aws.amazon.com/inspector/latest/user/findings-managing-exporting-reports.html) uses `kms:Decrypt` and `kms:GenerateDataKey*`. Constrain both statements with `aws:SourceAccount` and an `aws:SourceArn` matching `arn:aws:inspector2:REGION:ACCOUNT_ID:report/*`. The standard principal is `inspector2.amazonaws.com`; manually enabled Regions can require a Region-qualified service principal. Copy the current AWS examples into your existing policies and review the final merged policies with the AWS team. A caller policy alone cannot make the service write the object.
5. **Authorize the operator's assumed role.** Grant ECR inventory actions, `inspector2:CreateSbomExport` and `GetSbomExport`, `s3:ListBucket` limited to the approved prefix, `s3:GetObject` limited to its objects, and `kms:Decrypt` for the selected key. Confirm that the KMS key policy and any bucket policy also allow that principal. Check SCPs, permission boundaries, session policies, and explicit denies. The full [caller policy example](AWS_ACCESS.md#inspector-export-extension) uses placeholders and should be adapted to your account.
6. **Return the approved values.** Give the operator the bucket **name**, base prefix, and KMS **key ARN** for that profile/account/Region. Sentinel validates syntax and Region but cannot itself prove the destination has administrative approval. Never put secrets or customer names into an export prefix.

### Request for the AWS administrator

Provide the selected role ARN, verified account ID, Region, and repository/digest through an approved channel. Sentinel's **Copy admin request** control provides a concise message. This expanded version can be pasted into your normal internal request system:

> Please enable ECR Sentinel's Inspector SBOM export workflow for the selected role in this account and Region. Verify Inspector Enhanced Scanning actively covers the target image digest. Approve a private same-Region S3 export bucket and customer-managed symmetric KMS key; reuse the existing Inspector findings-export destination if suitable. Reserve a base prefix such as `sentinel-exports`, with Block Public Access, lifecycle retention, and access logging. Configure bucket and key policies so Inspector can write encrypted exports from this account's Inspector report ARN. Give the selected role `inspector2:CreateSbomExport` and `inspector2:GetSbomExport`, list/read access only to the approved S3 prefix, and decrypt access to the key. `CreateSbomExport` is Write and uses IAM `Resource: "*"`; please review the exception and confine destination access through S3/KMS policies. Return the bucket name, base prefix, and KMS key ARN. No ECR image-layer pull permission is requested.

### Caller policy shape

The following is a **template**, not a policy to apply without review. Replace every placeholder and narrow the S3 prefix consistently with the saved base prefix. The source profile separately needs `sts:AssumeRole` and appropriate role trust where applicable. The resolved role still needs the [ECR inventory policy](AWS_ACCESS.md#inventory-only-iam-example).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequestAndPollInspectorSbom",
      "Effect": "Allow",
      "Action": ["inspector2:CreateSbomExport", "inspector2:GetSbomExport"],
      "Resource": "*"
    },
    {
      "Sid": "ListApprovedExports",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::APPROVED_PRIVATE_BUCKET",
      "Condition": {"StringLike": {"s3:prefix": "sentinel-exports/*"}}
    },
    {
      "Sid": "ReadApprovedExports",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::APPROVED_PRIVATE_BUCKET/sentinel-exports/*"
    },
    {
      "Sid": "DecryptApprovedExports",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/APPROVED_KEY_ID"
    }
  ]
}
```

`GetSbomExport` is Read in AWS's authorization table but also uses `Resource: "*"` in this example. Both actions remain subject to organization guardrails. Scope S3/KMS by bucket, prefix, key, principal, and conditions as your AWS team requires. Bucket/key policies are separate from this identity policy. Sentinel does not expose a scan-time bucket field; the selected launch-token holder can change the saved destination, so this version has no administrator-enforced app allowlist.

## First setup in the app

1. Connect with the intended AWS profile, finish MFA or provider sign-in, and confirm the account and Region shown in Sentinel.
2. Open the repository and **Review & scan** for an immutable digest. Choose the deployed `linux/amd64` or `linux/arm64` platform **without a variant**. Inspector's SBOM metadata reports architecture but not sufficient OS/variant detail for Sentinel to verify a variant-bearing platform.
3. Choose **Inspector SBOM → Trivy**. Enter the approved bucket name, base prefix, and key ARN once, then save. The app stores this nonsecret destination in an owner-only local file, scoped to the resolved profile/account/Region. It is reused after restarting the server. A different account or Region needs its own approved setting.
4. Choose **Start Inspector SBOM scan**. There is no separate Terminal export command and no per-image S3 form after setup. **Change destination** updates the local setting; **Remove** asks for confirmation and forgets it from this Mac. Neither changes or deletes AWS resources.

For the example base prefix `sentinel-exports`, Sentinel creates a unique request prefix like `sentinel-exports/ecr-sentinel/<unique-id>/`. The prefix prevents concurrent jobs from mixing objects. Configure the role's list/read policy and service write policy to cover this nested path. Sentinel expects exactly one object under each unique request prefix and rejects a response that is ambiguous or larger than 16 MiB.

## What happens when you start the scan

1. Sentinel rechecks the selected AWS account and ECR digest through STS and `DescribeImages` and refuses an archived image.
2. It calls `CreateSbomExport` with `CYCLONEDX_1_4`, a generated S3 destination, and exact account ID, ECR resource ID, and `AWS_ECR_CONTAINER_IMAGE` filters. It polls `GetSbomExport` for at most 12 minutes. The entire local job has a 30-minute deadline.
3. On success, Sentinel checks the returned format, destination, and filters; lists the unique S3 job prefix; and reads the single object using an ETag precondition, bounded byte range, and size check. The Mac receives the **SBOM JSON**, not ECR image layers. S3/KMS access is exercised at this step.
4. It verifies CycloneDX structure plus Inspector metadata for account, image digest, ECR resource type, and architecture. Repository and Region may not appear in the SBOM JSON; those are bound to the verified request/export context. A mismatched index digest and child digest are rejected.
5. It removes the private temporary download after validation, updates/uses the local Trivy vulnerability database, runs `trivy sbom` without AWS credentials, and displays a report identifying the Inspector source and coverage. The report contains Trivy CVE matches, not Inspector's own findings.

The S3 object persists independently of the Mac. **Cancel scan** stops the local job; it does not call Inspector's remote cancel API or delete S3 objects. A timeout or server restart likewise does not ensure the remote export stops. Apply lifecycle retention and review storage/audit costs in AWS. The app keeps at most ten normalized reports in server memory; a requested CSV export is a separate local file.

## Coverage, provenance, and interpretation

- Inspector exports SBOMs for **actively monitored** resources. If Inspector has no inventory for the exact image, Sentinel has no package list to scan. [AWS's SBOM documentation](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html) describes this prerequisite and says unresolved component hashes can appear without enough identity for vulnerability matching.
- Trivy checks only components present in the SBOM. It cannot reconstruct omitted files/packages, prove the inventory complete, or reproduce a direct filesystem/image scan. [Trivy's SBOM guidance](https://trivy.dev/docs/latest/guide/target/sbom/) warns that third-party SBOMs can give less precise matching.
- Sentinel's metadata checks bind the object to the export request, but the SBOM is not a signed completeness attestation. A party able to replace an allowed S3 object before retrieval could supply matching metadata and false package content. Restrict S3 writers to Inspector, use AWS source-account/source-ARN conditions, monitor object access, and do not use this report alone as a deployment gate.
- A zero-finding result means no known match in the exported components at the Trivy database date. It is not a statement that the image is safe. Scan each deployed platform separately and reassess when the image or vulnerability database changes.

## Failure guide

| Stage or message | What to check |
| --- | --- |
| Destination form appears | No destination is saved for **this** verified profile/account/Region. Obtain approved values, then save once. |
| `INSPECTOR_CREATE_DENIED` | Caller lacks the Write-classified `CreateSbomExport` action, or Inspector cannot use the bucket/key. Inspect caller IAM and Inspector service policies separately. |
| `INSPECTOR_STATUS_DENIED` | Caller lacks `GetSbomExport` or another policy denies it. |
| `INSPECTOR_EXPORT_FAILED` with no monitored resource | Confirm Enhanced Scanning coverage of the exact active digest; allow service processing time. |
| `INSPECTOR_EXPORT_FAILED` with bucket/key permissions | Verify bucket/key Region, key type, Inspector service principal, `SourceAccount`/`SourceArn`, and service write/encrypt actions. |
| `INSPECTOR_S3_LIST_DENIED` or `INSPECTOR_S3_READ_DENIED` | Check caller `ListBucket` condition for the nested job prefix, `GetObject`, KMS decrypt and key policy, plus S3 VPN/endpoint reachability. |
| `INSPECTOR_EXPORT_AMBIGUOUS` or `SBOM_TOO_LARGE` | The unique prefix has zero/multiple objects or exceeds the 16 MiB cap. Inspect the AWS export and size; do not bypass the bound. |
| `INSPECTOR_EXPORT_MISMATCH`, `INSPECTOR_SBOM_INVALID`, or platform mismatch | Stop; verify exact account, repository child digest, platform, and export response. Do not relabel the SBOM. |
| `INSPECTOR_EXPORT_TIMEOUT` or canceled local job | The remote job may continue. Check Inspector/S3 state and bucket lifecycle before retrying. |
| Trivy database failure or no package targets | Restore database registry access and inspect SBOM coverage before interpreting a clean report. |

See [Troubleshooting](TROUBLESHOOTING.md) for the full error matrix and [AWS access](AWS_ACCESS.md) for MFA and network prerequisites.
