# Generate and import an image SBOM

Use this workflow when the Mac can see ECR repository and image metadata but is **not authorized to pull image layers**. A separately authorized build host produces a package inventory from the final image; Sentinel uses that inventory to run Trivy vulnerability matching on the Mac. The app does not download the image in SBOM mode and does not use ECR managed scanning.

## What must exist

- An authorized host with Node.js 20+, Docker, and Trivy 0.71.1 or newer.
- The **final image** available to Docker on that host after it has been pushed to ECR.
- The exact ECR account, Region, repository, immutable digest, and platform selected later in Sentinel.
- A private, approved transfer route for the JSON bundle. Sentinel does not include S3 or CI integration.

Run the helper after the push. It checks that Docker's local `RepoDigests` includes the exact `repository@digest` you supply and that the local image platform matches. It then scans Docker's immutable local image ID, rechecks the local association, and writes a new private JSON file. The helper does not ask Trivy to pull from ECR and does not read AWS credential files.

## Manual procedure

1. Build and push the final image with your normal approved process. Keep that image available in local Docker on the authorized host.
2. Record the digest from the push result or ECR metadata. Use the digest for the platform artifact you will review; do not use a mutable tag as the identity.
3. Check that the local image has the expected repository digest:

   ```bash
   docker image inspect --format '{{json .RepoDigests}}' \
     111122223333.dkr.ecr.us-east-1.amazonaws.com/team/service:build-42
   ```

4. From a trusted checkout of ECR Sentinel on that host, generate the bundle:

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

5. Transfer the new `.json` file through an approved private channel. Treat it as sensitive software inventory.
6. On the Mac, connect Sentinel to the **same account and Region**, select that repository, digest, and platform, choose **Import SBOM bundle**, and confirm the local check.

The digest placeholder is illustrative; replace it with an actual 64-character SHA-256 hex digest. The helper refuses to overwrite an existing output file. If the Docker metadata does not contain that ECR digest, stop and verify the build/push artifact association instead of editing the bundle's claim by hand.

For a multi-platform image, generate and scan a separate bundle for each deployed platform. A manifest-list or index digest may differ from a platform-specific child digest. The helper requires the supplied digest to match the local Docker image's `RepoDigests` exactly; an index-only push that never loaded a matching local image cannot use this helper as-is.

## Build-system-neutral integration

The same ordered steps fit a manual host, Jenkins job, CodeBuild job, or another build system:

1. Build final image.
2. Push the final image to ECR.
3. Resolve the immutable repository digest and platform.
4. On the authorized worker **with the exact local image**, run the helper once per platform.
5. Deliver the generated file privately to the reviewer or an approved artifact store.
6. Review it in Sentinel against the matching ECR digest.

No CI workflow, artifact store, uploader, or automated synchronization is included in this version. Use your build system's own access control and retention policy for the artifact. If the host uses `docker buildx --push` without loading an image locally, the helper will refuse; arrange a build step that retains the exact pushed image locally or use a separately designed authorized worker.

## Bundle contract and limits

The helper writes a version 1 Sentinel bundle containing:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Bundle format version, currently `1`. |
| `image` | Claimed account, Region, repository, digest, and platform. |
| `generatedAt` | UTC generation time. |
| `producer` | Helper name and Trivy version. |
| `sbom` | CycloneDX JSON package inventory generated from the final Docker image. |

Sentinel validates the bundle structure, claimed target fields, supported SBOM format, and size before starting a scan. The helper generates CycloneDX; the importer also recognizes supported SPDX JSON bundles inside a version 1 Sentinel wrapper. The file and normalized SBOM are limited to 16 MiB; the API request is limited to 20 MiB. The helper also caps analyzed images at 4 GB and its Trivy process at 15 minutes. It creates the output with mode `0600`.

The app computes hashes of the normalized SBOM and bundle metadata for report identification. **These hashes do not authenticate the producer or prove the packages came from that image.** A malicious actor who can replace the bundle can replace its claimed digest and recompute hashes. If findings will be used for deployment gates or compliance evidence, add a signed build attestation and verify it before import. Until then, accept files only from a trusted build host and transfer route.

## Interpretation

Trivy checks known vulnerabilities in packages listed in the SBOM using the Mac's vulnerability database. It cannot discover packages that the build-host SBOM omitted, inspect image files omitted by the SBOM, prove exploitability, or prove that the final deployed image still matches the claimed digest. The app labels imported association as unverified and shows a coverage note in the report. A zero-finding SBOM report is limited to the recorded package set and database date. [Trivy's SBOM documentation](https://trivy.dev/docs/latest/guide/supply-chain/sbom/) describes generation and scanning behavior.

For mismatch, size, or database errors, see [troubleshooting](TROUBLESHOOTING.md).
