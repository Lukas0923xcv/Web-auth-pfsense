#!/bin/sh
# Point the README install command at a commit, with its tarball checksum.
#   sh tools/pin_install.sh <full commit ID>
# The commit must already be pushed to GitHub. Commit the README change
# afterwards (the README itself is not part of what gets installed).
set -eu
cd "$(dirname "$0")/.."
commit=${1:?usage: tools/pin_install.sh <full commit ID>}
case "$commit" in
*[!0-9a-f]*) echo "not a commit ID: $commit" >&2; exit 1 ;;
esac
[ ${#commit} -eq 40 ] || { echo "give the full 40-character commit ID" >&2; exit 1; }

url="https://codeload.github.com/Lukas0923xcv/web-auth-pfsense/tar.gz/$commit"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL -o "$tmp" "$url"
# Same check as on pfSense: the tarball must hold the files of that commit.
tar tzf "$tmp" | grep -q "^web-auth-pfsense-$commit/install.sh$" || {
	echo "the tarball does not look like commit $commit" >&2
	exit 1
}
hash=$(sha256sum "$tmp" | cut -d' ' -f1)
version=$(git show "$commit:src/usr/local/pkg/webauthn/VERSION")

sed -i -E \
	-e "s#(codeload\.github\.com/Lukas0923xcv/web-auth-pfsense/tar\.gz/)[0-9a-f]{40}#\1$commit#" \
	-e "s#(sha256 -c )[0-9a-f]{64}#\1$hash#" \
	-e "s#(<!-- pinned-version -->)[^<]*(<!-- /pinned-version -->)#\1$version\2#" \
	README.md
echo "README now installs version $version, commit $commit, sha256 $hash"
