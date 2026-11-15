#!/bin/sh
# Rebuilds a published release from this checkout and compares it with the published SHA256SUMS:
#
#   scripts/reproduce.sh <version> <SHA256SUMS of the release>
#
# Check out the tag first (git checkout v<version>) in a clean clone: Go records the commit and
# whether the tree had changes in the binaries, so untracked files change the result. Use the Go
# version the release was built with: `go version -m smoke-collector_linux_amd64` prints it on the
# first line, and GOTOOLCHAIN=go<that version> makes the go command use it. Releases before 0.4.1
# were built from commits whose messages were later rewritten, so they record a revision that is
# not in the public history (README, "Versions before 0.4.1"); they cannot be reproduced bit for
# bit from it.
set -eu
cd "$(dirname "$0")/.."

die() { echo "reproduce: error: $*" >&2; exit 1; }
[ $# -eq 2 ] || die "usage: scripts/reproduce.sh <version> <SHA256SUMS>"
VERSION=${1#v}
SUMS=$2
[ -r "$SUMS" ] || die "cannot read $SUMS"
command -v git >/dev/null || die "git not found"
[ -z "$(git status --porcelain)" ] || die "the checkout has changes or untracked files; use a clean clone"
tag=$(git rev-parse -q --verify "refs/tags/v$VERSION^{commit}") || die "no tag v$VERSION (git fetch --tags)"
[ "$(git rev-parse HEAD)" = "$tag" ] || die "HEAD is not v$VERSION (git checkout v$VERSION)"

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
echo "reproduce: building v$VERSION at $tag with $(go env GOVERSION)"
sh scripts/build.sh "$VERSION" "$out"

status=0
while read -r sum file; do
	want=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$SUMS")
	if [ -z "$want" ]; then
		echo "missing  $file (not in $SUMS)"
		status=1
	elif [ "$want" = "$sum" ]; then
		echo "match    $file  $sum"
	else
		echo "DIFFERS  $file  built $sum, published $want"
		status=1
	fi
done <"$out/SHA256SUMS"
[ "$status" = 0 ] && echo "reproduce: all four binaries are identical to the release" ||
	echo "reproduce: differences found (Go version, an unclean checkout, or another source)" >&2
exit "$status"
