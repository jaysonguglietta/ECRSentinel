# Generate and import a build-host image SBOM

This path is for teams whose review Mac may read ECR **repository and image metadata** but may not pull image layers. A **separately authorized build host** uses its already local copy of the final image to produce a CycloneDX SBOM. The Mac imports a Sentinel JSON bundle and runs local Trivy CVE matching against the recorded components. No ECR image layers are pulled to the Mac in this path; the SBOM file itself is transferred and read locally.

**Access boundary:** someone must be authorized to read the final image somewhere to generate package inventory. If no role, host, or existing service may read it and no existing Inspector inventory is available, neither this helper nor Sentinel can reconstruct an SBOM from `DescribeImages` metadata. Do not run the helper on the read-restricted Mac and expect it to obtain the image remotely. The [Inspector path](INSPECTOR_SBOM.md) may work only for images Inspector already monitors and only if the selected role may request an export.

## Required environment on the producer

- A trusted host with Node.js 20+, Docker running, Trivy 0.71.1+ from a trusted release, and a trusted checkout of this repository. Run `npm ci` in that checkout because the helper imports the application's validation modules and their dependencies.
- The **final pushed image** available in the host's local Docker daemon. Docker must report the exact ECR `repository@sha256:...` value in that image's `RepoDigests` after the push. A mutable tag alone is insufficient.
- The exact AWS account, Region, ECR repository path, immutable digest, and deployed platform that the reviewer will later choose in Sentinel. Use a **platform-specific child digest** where the local Docker image is associated with that digest.
- A private, approved way to deliver the JSON bundle to the reviewer or an approved artifact store. Sentinel does not provide an uploader, CI pipeline, registry push, S3 artifact integration, or automatic synchronization.

The helper reads the local Docker image only. It supplies Docker's immutable local image ID to `trivy image --image-src=docker`, sets AWS credential-file paths to `/dev/null`, disables instance metadata resolution, and does not ask Trivy to pull from ECR. It uses an isolated temporary Trivy cache on the producer. The build/push system itself may have AWS permissions, but this helper does not use them to inspect the image.

## Worked manual procedure

The following account ID and repository are **fictional examples**. Replace them with approved values in your own environment and use the real 64-hex-character digest returned by the push. Never commit actual credentials, profile files, SBOMs, or private image identifiers to this repository.

1. Build and push the final image through your existing approved process. Keep the exact image loaded in the authorized host's Docker daemon after pushing. Confirm Node, Docker, and Trivy work there:

   ```bash
   node --version
   docker version
   trivy --version
   npm ci
   ```

2. Record the ECR repository, account, Region, and immutable digest from the push result or an approved ECR metadata query. Inspect the local image's repository digest association:

   ```bash
   docker image inspect --format '{{json .RepoDigests}}' \
     111122223333.dkr.ecr.us-east-1.amazonaws.com/team/service:build-42
   ```

   The output must include `111122223333.dkr.ecr.us-east-1.amazonaws.com/team/service@sha256:<64 hex digits>` for the digest you will supply. If it does not, stop and resolve the artifact association. Do not change the bundle claim by hand.

3. From the trusted repository checkout on that host, run the helper. The example digest placeholder below is deliberately **not** a real digest:

   ```bash
   node scripts/generate-sbom-bundle.mjs \
     --image 111122223333.dkr.ecr.us-east-1.amazonaws.com/team/service:build-42 \
     --account 111122223333 \
     --region us-east-1 \
     --repository team/service \
     --digest sha256:REPLACE_WITH_THE_EXACT_64_HEX_DIGIT_DIGEST \
     --platform linux/amd64 \
     --output ./service-amd64.sentinel-sbom.json
   ```

4. Verify the helper prints `Created ... for ... · linux/amd64`. It refuses to overwrite an existing path. Treat the new mode-`0600` JSON file as sensitive package inventory; send it only through an approved private route with a defined retention period.
5. On the review Mac, connect Sentinel to the **same AWS account and Region**. Open the **same repository and digest**, select `linux/amd64`, choose **Import build-host SBOM**, select the JSON file, review the confirmation, and choose **Check SBOM with Trivy**.
6. Review the report's bundle source, package coverage, normalized SBOM SHA-256, Trivy database date, and findings. The hash identifies analyzed content but does not authenticate the producer.

For `linux/arm64`, produce a separate bundle from the corresponding final image and select that platform in Sentinel. A multi-platform index digest and each child manifest digest can differ. This helper requires the local Docker image to advertise the exact supplied ECR repository digest; if your `docker buildx --push` process leaves only a remote image or only an index digest, it will refuse to create the bundle. Arrange an authorized workflow that retains the exact pushed child image locally, or use a separately designed and approved producer.

## Integration with a manual or other build system

The same sequence can be run by a human or a build system without any Sentinel-specific CI plugin:

1. Build the final image.
2. Push it to ECR through the normal approved path.
3. Resolve the immutable repository digest and platform and confirm the local Docker image's `RepoDigests` includes that digest.
4. Run the helper **once per deployed platform** on a worker that has the matching local image.
5. Retain the generated bundle in an approved private artifact channel; record who generated it, when, and from which build, if your review process requires traceability.
6. Review the matching digest/platform in Sentinel on the Mac.

The helper does not make a remote ECR request or grant the Mac image access. It also does not sign the file. If the build worker itself lacks image read access, this path is unavailable. A source-code-only SBOM is a different artifact and can miss operating-system packages and files installed into the final image; the included helper intentionally scans the final image.

## Bundle format and validation

The helper writes a **version 1 ECR Sentinel JSON bundle** with these top-level fields:

| Field | Purpose |
| --- | --- |
| `schemaVersion` | Currently `1`, required by the importer. |
| `image` | Claimed AWS account, Region, repository, immutable ECR digest, and platform. |
| `generatedAt` | UTC generation timestamp. |
| `producer` | Helper name and Trivy version as declared producer metadata. |
| `sbom` | CycloneDX JSON generated by Trivy from the final local Docker image. |

Sentinel rejects a raw standalone CycloneDX/SPDX file because it lacks the bundle's image-target wrapper. Its importer can validate a supported CycloneDX or SPDX JSON SBOM **inside** a version 1 wrapper; the supplied helper generates CycloneDX. It compares declared target fields to the selected AWS account/Region/repository/digest/platform and checks the SBOM structure and size before scanning. The helper checks Docker `RepoDigests` before and after generation, verifies the local image ID did not change, verifies platform, and rejects a Trivy-reported repository digest that disagrees with the ECR target.

Limits include 16 MiB for the generated file/normalized SBOM, 20 MiB for the upload request, and 100,000 package entries in the importer. The helper caps the analyzed image at 4 GB and its Trivy process at 15 minutes. Sentinel's local scan jobs have their own 30-minute overall deadline. These bounds are safety limits; if a legitimate image exceeds them, use a separately engineered scanner and review resulting coverage instead of hand-editing JSON or simply removing bounds.

## Provenance and interpretation

The helper's Docker checks reduce accidental mismatch, but `image`, `producer`, and `generatedAt` remain **claims inside an unsigned file**. A party who can replace the file can forge those claims and recompute its SHA-256. The bundle hash is useful to identify exactly which normalized SBOM Sentinel analyzed; it is not a digital signature, trusted build attestation, or proof that the SBOM came from the deployed digest. For deployment gates or compliance evidence, add signed provenance from the authorized build system and verify it before import.

Trivy can match vulnerabilities only in packages the SBOM lists. It cannot discover omitted packages/files, prove exploitability, or prove the final deployed artifact still has the same contents. A zero-finding report means no known match in the listed package set at that database date, **not** that the image is safe. Keep the SBOM and exported CSV private, update the Trivy database, and rescan when the image digest or advisory data changes. [Trivy's SBOM documentation](https://trivy.dev/docs/latest/guide/supply-chain/sbom/) describes generation and scanning; [Troubleshooting](TROUBLESHOOTING.md#sbom-generation-and-import) covers mismatches and size errors.
