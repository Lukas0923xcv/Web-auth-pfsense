#!/bin/sh
# Check the WebAuthn hooks against pfSense's own copies of the patched
# files (authgui.inc, auth_check.inc, xmlrpc.php):
#
#   sh tools/upstream_anchors.sh release   the files pfSense CE 2.8.1 ships, from the
#                                          pfSense package of the official 2.8.1
#                                          package repository
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
	# pfSense's pkg repositories are found through DNS SRV records
	# (_https._tcp.pkg.pfsense.org): the name itself has no address.
	if [ -z "${PFSENSE_REPO:-}" ]; then
		srv=$(dig +short SRV _https._tcp.pkg.pfsense.org 2>/dev/null | sort -n | head -n 1)
		echo "SRV _https._tcp.pkg.pfsense.org: ${srv:-none}"
		host=$(echo "$srv" | awk '{print $4}' | sed 's/\.$//')
		PFSENSE_REPO="https://${host:-pkg.pfsense.org}/pfSense_v2_8_1_amd64-core"
	fi
	repo=$PFSENSE_REPO
	curl -fsSL --retry 3 -o "$dir/packagesite.pkg" "$repo/packagesite.pkg"
	tar -xf "$dir/packagesite.pkg" -C "$dir" packagesite.yaml
	# Look for the GUI's PHP files in the core pfSense packages (not the
	# add-on pfSense-pkg-* ones), smallest first.
	# shellcheck disable=SC2016 # PHP code, not shell
	names=$("$php" -r '$c = []; foreach (file($argv[1]) as $l) { $p = json_decode($l, true);
		if (str_starts_with($p["name"] ?? "", "pfSense") && !str_starts_with($p["name"], "pfSense-pkg-")) { $c[$p["name"]] = $p["pkgsize"] ?? 0; } }
		asort($c); echo implode(" ", array_keys($c));' "$dir/packagesite.yaml")
	echo "core packages: $names"
	found=0
	for name in $names; do
		# One JSON object per line; take this package's path and version.
		# shellcheck disable=SC2016 # PHP code, not shell
		info=$("$php" -r 'foreach (file($argv[1]) as $l) { $p = json_decode($l, true);
			if (($p["name"] ?? "") === $argv[2]) { echo $p["repopath"], " ", $p["version"]; break; } }' "$dir/packagesite.yaml" "$name")
		[ -n "$info" ] || continue
		path=${info% *}
		version=${info##* }
		curl -fsSL --retry 3 -o "$dir/pkg" "$repo/$path"
		if tar -tf "$dir/pkg" | grep -q 'etc/inc/authgui\.inc$'; then
			echo "$name $version from $repo/$path"
			mkdir -p "$dir/x"
			tar -xf "$dir/pkg" -C "$dir/x" --wildcards '*etc/inc/authgui.inc' '*etc/inc/auth_check.inc' '*usr/local/www/xmlrpc.php'
			found=1
			break
		fi
		echo "$name $version: no etc/inc/authgui.inc in it"
	done
	[ "$found" = 1 ] || { echo "authgui.inc not found in the 2.8.1 packages of $repo"; exit 1; }
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
