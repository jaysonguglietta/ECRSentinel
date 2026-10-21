# Inspector SBOM to local Trivy

Use this path when your Mac may list ECR image metadata but may not pull image layers. Sentinel asks Amazon Inspector to export a CycloneDX SBOM for the selected ECR image, retrieves that JSON report from an approved S3 bucket, verifies its image identity, then runs `trivy sbom` on the Mac. The Trivy result is a fresh vulnerability match against the packages Inspector listed; the app does not display Inspector's CVE findings as Trivy findings.

Amazon Inspector **must already monitor the image** through ECR Enhanced Scanning. This workflow uses Inspector's existing image analysis to obtain package inventory; it does not create package information from ECR metadata alone. Inspector may already identify CVEs as part of its normal scanning. Sentinel does not enable Enhanced Scanning or start an ECR basic scan. [AWS describes Inspector SBOM exports](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html) and [ECR Enhanced Scanning](https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html).

## Before you start

1. Confirm the selected image and Region are covered by Inspector. The image must still be available and monitored. An archived or unmonitored image cannot provide a current Inspector SBOM.
2. Ask the AWS team for an **approved private S3 export bucket and customer-managed symmetric KMS key in the same Region**. The bucket and key policies must let the Inspector service write and encrypt the export. Use the [AWS bucket and KMS policy examples](https://docs.aws.amazon.com/inspector/latest/user/findings-managing-exporting-reports.html#findings-managing-exporting-reports-configure-s3), scoped to your account, Region, and export prefix. The Inspector service principal is `inspector2.amazonaws.com` in standard Regions; check the AWS guide for opt-in Region variations.
3. Grant the selected AWS profile the export, status, and narrowly scoped read actions shown below. Sentinel does not need ECR layer-pull actions for this path.
4. Install AWS CLI v2 and a trusted Trivy 0.71.1 or newer on the Mac. The first local scan needs access to Trivy's vulnerability database registries.

Illustrative **caller** policy for a bucket dedicated to these exports. Replace every placeholder and narrow the account, Region, bucket, prefix, and KMS key. The IAM team must separately configure the Inspector **service** permissions on the bucket and key; this caller policy alone cannot make exports succeed. An SCP, permissions boundary, bucket policy, or key policy can further restrict access. See the [Inspector service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_inspector2.html).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequestAndCheckSbomExport",
      "Effect": "Allow",
      "Action": ["inspector2:CreateSbomExport", "inspector2:GetSbomExport"],
      "Resource": "*"
    },
    {
      "Sid": "ListOnlyApprovedExportPrefix",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::APPROVED_PRIVATE_BUCKET",
      "Condition": {"StringLike": {"s3:prefix": "sentinel-exports/*"}}
    },
    {
      "Sid": "ReadOnlyApprovedExportObjects",
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

The profile also needs `ecr:DescribeRepositories` and `ecr:DescribeImages` for browsing and rechecking the selected digest. `sts:GetCallerIdentity` identifies the active account. The Inspector service needs its own `s3:PutObject` and KMS data-key permissions. The S3/KMS setup is often the reason a valid export request fails.

## Run the workflow

1. Connect with the intended AWS profile. If it is a role profile with `mfa_serial`, enter the one-time code in Sentinel.
2. Select a repository and immutable image digest. Choose the deployed platform, such as `linux/amd64`.
3. In **Review & scan**, choose **Inspector SBOM → Trivy**. Enter the approved bucket, export prefix, and KMS key ARN. These are destination configuration, not AWS access keys.
4. Start the export. Sentinel requests a CycloneDX 1.4 SBOM with an exact image resource filter, waits for Inspector, finds the object under a unique job prefix, validates the returned SBOM against the selected digest, account, resource type, and architecture, and scans it with local Trivy.
5. Review the report's **Inspector SBOM** source, selected image, platform, package coverage, Trivy database date, and CVE findings. Export CSV only when needed. A zero-finding report means no known matches among detected packages at that database date; it is not a declaration that the image is vulnerability-free.

Inspector writes an S3 object that persists independently of the local scan. Set a bucket lifecycle policy and access logging/CloudTrail practices that match your organization's retention requirements. The app reads the report but does not manage the bucket or delete its objects. Avoid putting customer names or secrets in the export prefix. The SBOM discloses package names and versions, so handle it as sensitive inventory. Sentinel currently validates the destination's syntax and Region but does **not** have an administrator bucket/key allowlist; use only your organization's approved destination and restrict its bucket/key policies.

## Identity and coverage limits

The export request is filtered to one ECR image resource ID and the downloaded CycloneDX metadata is checked again. An Inspector SBOM can identify the image digest, account, resource type, and architecture, but may not identify the repository or Region in the JSON itself. Sentinel ties those fields to the verified request and export job. A multi-platform index digest can differ from the child image digest reported by Inspector; select the child digest or use another workflow if Sentinel reports a mismatch. Do not relabel a child SBOM as a whole index.

Trivy documents that scans of SBOMs produced by another tool may be less precise than scans using Trivy's own SBOM properties. Inspector may include unresolved component hashes or omit packages it could not identify. The Trivy report covers **only the components present in that exported SBOM**; it cannot reproduce a filesystem scan, discover omitted files, or attest that the package inventory is complete. [Trivy SBOM guidance](https://trivy.dev/docs/latest/guide/target/sbom/) and [AWS export notes](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html).

The Inspector export is AWS-generated data but not a signed package-completeness attestation in this app. Keep the S3 bucket private, restrict writers to Inspector with source account/ARN conditions, restrict `GetObject` and `ListBucket`, and do not treat a clean report as a deployment approval without a separate policy and provenance review. An S3 writer could replace an object before Sentinel lists it with a forged SBOM containing matching image metadata; the app's ETag check cannot authenticate who wrote that object.

## Common failures

| Symptom | Check |
| --- | --- |
| Inspector says no covered resource or export fails | Confirm Enhanced Scanning covers that exact digest in the selected Region and account. Check whether the image was archived or removed. |
| Export is denied | Check the selected profile's `inspector2:CreateSbomExport`/`GetSbomExport`, the Inspector service's S3/KMS policies, the bucket and key Region, and SCPs. |
| Export succeeds but Sentinel cannot read it | Check the caller's prefix-scoped `s3:ListBucket`, `s3:GetObject`, and `kms:Decrypt` rights, S3 endpoint access, and bucket/key policies. |
| Digest, account, resource type, or platform mismatch | Do not scan the object as the selected image. Verify the chosen ECR child digest and re-export. |
| Trivy returns no package targets | Inspect the SBOM component count and coverage warning. Try a direct scan only if policy allows it; otherwise treat the result as incomplete. |
| Trivy database update fails | Restore access to the configured database registries or use an approved internal mirror after the app supports one. |

See [AWS access](AWS_ACCESS.md), [the operator guide](USER_GUIDE.md), and [troubleshooting](TROUBLESHOOTING.md) for the related workflows.
