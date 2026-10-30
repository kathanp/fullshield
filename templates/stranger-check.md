# Stranger check

Run these steps yourself after a release is on npm. This file is a template. It is not a GitHub workflow and it does not post a status.

1. `npx fullshield@<version> --version`
2. `npx fullshield@<version> scan` on a project you own
3. `npx fullshield@<version> scan --json`
4. `npx fullshield@<version> scan --sarif`
5. `npx fullshield@<version> scan --fail-on high`
6. `npx fullshield@<version> fix --dry-run`
7. `npx fullshield@<version> init`
8. `npx fullshield@<version> sbom`

No company quote belongs in this file.
