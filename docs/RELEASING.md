# Releasing

1. Change the code. Bump `src/usr/local/pkg/webauthn/VERSION` and add a `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md` (and to `docs/UPGRADE.md` if users must do something).
2. Run `sh tests/run_all.sh` locally, push, and wait until every job of the **tests** workflow is green.
3. Pin the README install command to that commit:
   ```sh
   sh tools/pin_install.sh <full commit ID>
   git commit -am "README: pin the install command to version X.Y.Z"
   ```
   Push and wait for the **README install command** job to pass: it checks that the pinned commit exists and that its tarball has the pinned sha256.
4. Tag the pin commit and push the tag:
   ```sh
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```
   The **release** workflow checks that the tag's installed files are byte-identical to the pinned commit, that VERSION and CHANGELOG match the tag, and that the tarball has the pinned sha256. It then publishes a GitHub Release with `web-auth-pfsense-X.Y.Z.tar.gz`, `SHA256SUMS` and a build provenance attestation (`gh attestation verify web-auth-pfsense-X.Y.Z.tar.gz -R Lukas0923xcv/web-auth-pfsense`).

The release tarball is the same file the README command downloads, so its hash in `SHA256SUMS` is the one the command checks.
