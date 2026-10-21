# Security policy

ECR Sentinel handles AWS identities, private registry metadata, image contents during direct scans, and sensitive package inventories in imported SBOMs. It is designed for **one local macOS operator** and binds to `127.0.0.1`. Do not deploy the current server on a public network or share its launch URL. See the [architecture](docs/ARCHITECTURE.md) and [adversarial audit](SECURITY_AUDIT.md) for trust boundaries and known residual risks.

## Report a vulnerability

Use GitHub's private **Report a vulnerability** option for this repository if it is available. If it is not available, contact the repository maintainer through a private channel before sending exploit details. Do not put live credentials, MFA codes, launch tokens, private image names, or sensitive SBOM contents in a public issue. A concise report should include the affected version or commit, entry point, reproduction steps with dummy data, expected and actual result, and impact.

There is no committed production response SLA or supported release branch policy yet. Fixes and disclosures should be coordinated with the maintainer before public release.

## Operator security requirements

- Run as a standard macOS user, use an approved VPN and named AWS profile, and grant only the ECR actions needed for the selected workflow.
- Prefer temporary role or SSO credentials. A direct image scan can pass a static IAM user's long-lived access keys to the local Trivy child process if that is the selected profile.
- Keep Node.js, AWS CLI, Trivy, and npm dependencies current. Trivy must be at least 0.71.1 in this app; install from a trusted source.
- Open only the private URL printed by the current server run and stop the server when finished. **Lock this tab** clears that tab, but does not revoke the server token or its in-memory role sessions.
- Treat SBOM bundles and CSV exports as sensitive data. Verify a bundle's source through an approved private route; the current app checks consistency but does not verify a signature.
- Review local scanner cache retention and remove data according to your organization's policy.

The app's controls and outstanding risks are detailed in [SECURITY_AUDIT.md](SECURITY_AUDIT.md). Security reports about AWS, Trivy, or another upstream component should also be directed to the relevant upstream maintainer.
