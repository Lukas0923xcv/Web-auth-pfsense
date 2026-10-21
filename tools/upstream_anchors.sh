#!/bin/sh
# Check the WebAuthn hooks against pfSense's own copies of the patched
# files (authgui.inc, auth_check.inc, xmlrpc.php):
#
#   sh tools/upstream_anchors.sh release   the files pfSense CE 2.8.1 ships, from
#                                          the pfSense-base package of the official
#                                          2.8.1 repository
#   sh tools/upstream_anchors.sh master    pfsense/pfsense's default branch on GitHub
#
# pfsense/pfsense on GitHub has no tag or branch for 2.8.x (its tags stop
# at v2.5.2, its RELENG branches at 2_7_2), so the released files come from
# the release's own package. Exits 1 if a hook does not apply.
set -eu
cd "$(dirname "$0")/.." || exit 1
php=${PHP:-php}
which=${1:?usage: tools/upstream_anchors.sh release|master}
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

case "$which" in
master)
	raw=https://raw.githubusercontent.com/pfsense/pfsense/master
	for f in src/etc/inc/authgui.inc src/etc/inc/auth_check.inc src/usr/local/www/xmlrpc.php; do
		curl -fsSL --retry 3 -o "$dir/$(basename "$f")" "$raw/$f"
	done
	echo "pfsense/pfsense master at $(git ls-remote https://github.com/pfsense/pfsense refs/heads/master | cut -f1)"
	;;
release)
	repo=${PFSENSE_REPO:-https://pkg.pfsense.org/pfSense_v2_8_1_amd64-core}
	curl -fsSL --retry 3 -o "$dir/packagesite.pkg" "$repo/packagesite.pkg"
	tar -xf "$dir/packagesite.pkg" -C "$dir" packagesite.yaml
	path=$(grep '"name":"pfSense-base"' "$dir/packagesite.yaml" | head -n 1 | sed 's/.*"repopath":"\([^"]*\)".*/\1/')
	version=$(grep '"name":"pfSense-base"' "$dir/packagesite.yaml" | head -n 1 | sed 's/.*"version":"\([^"]*\)".*/\1/')
	[ -n "$path" ] || { echo "pfSense-base not found in $repo"; exit 1; }
	echo "pfSense-base $version from $repo/$path"
	curl -fsSL --retry 3 -o "$dir/base.pkg" "$repo/$path"
	mkdir "$dir/x"
	tar -xf "$dir/base.pkg" -C "$dir/x" --wildcards '*etc/inc/authgui.inc' '*etc/inc/auth_check.inc' '*usr/local/www/xmlrpc.php'
	for f in authgui.inc auth_check.inc xmlrpc.php; do
		find "$dir/x" -name "$f" -exec cp {} "$dir/$f" \;
	done
	;;
*)
	echo "usage: tools/upstream_anchors.sh release|master" >&2
	exit 2
	;;
esac

"$php" tools/check_anchors.php "$dir"
