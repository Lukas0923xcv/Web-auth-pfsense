#!/bin/sh
# Check the install command in README.md: the commit it pins exists in this
# repository's history, its VERSION matches the version the README names,
# and the tarball GitHub serves for it has the sha256 the command checks.
#   sh tools/check_pin.sh
# Needs the full git history (CI: fetch-depth 0) and network access.
set -eu
cd "$(dirname "$0")/.." || exit 1

commit=$(grep -oE 'codeload\.github\.com/Lukas0923xcv/web-auth-pfsense/tar\.gz/[0-9a-f]{40}' README.md | head -n 1 | sed 's#.*/##')
hash=$(grep -oE 'sha256 -c [0-9a-f]{64}' README.md | head -n 1 | sed 's#.* ##')
version=$(sed -nE 's#.*<!-- pinned-version -->([^<]*)<!-- /pinned-version -->.*#\1#p' README.md | head -n 1)
fail() {
	echo "README pin: $*" >&2
	exit 1
}
[ -n "$commit" ] || fail "no pinned commit found in the install command"
[ -n "$hash" ] || fail "no sha256 found in the install command"
[ -n "$version" ] || fail "no pinned version found"
case "$commit" in
0000000000000000000000000000000000000000) fail "the commit is still the placeholder" ;;
esac

git cat-file -e "$commit^{commit}" 2>/dev/null || fail "commit $commit is not in this repository"
git merge-base --is-ancestor "$commit" HEAD || fail "commit $commit is not part of this branch's history"
pinned_version=$(git show "$commit:src/usr/local/pkg/webauthn/VERSION")
[ "$pinned_version" = "$version" ] || fail "the README says version $version, but commit $commit has VERSION $pinned_version"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp" "https://codeload.github.com/Lukas0923xcv/web-auth-pfsense/tar.gz/$commit" ||
	fail "cannot download the tarball of $commit"
actual=$(sha256sum "$tmp" | cut -d' ' -f1)
[ "$actual" = "$hash" ] || fail "the tarball of $commit has sha256 $actual, the README checks for $hash"
tar tzf "$tmp" | grep -q "^web-auth-pfsense-$commit/install.sh$" || fail "the tarball does not contain install.sh"

echo "README pin ok: version $version, commit $commit, sha256 $hash"
