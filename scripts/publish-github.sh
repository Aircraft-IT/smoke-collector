#!/bin/sh
# Publishes a release on GitHub after release.sh and tagging:
#
#   scripts/publish-github.sh <version> [--dry-run]
#
# Checks first, changes nothing until all pass:
#   - tag v<version> exists and dist/v<version> holds the four binaries, SHA256SUMS and its
#     minisign signature, the files match SHA256SUMS and the signature verifies;
#   - every binary records the tag's commit with no local changes and the module version
#     v<version> (go version -m), so the published source is the source of the published files.
# Then pushes the tag's commit to GitHub's main (fast-forward only, never forced) and the tag, and
# creates the GitHub release with the files and notes naming the commit and the Go version.
# Development stays in the internal repository; GitHub only gets released commits.
#
# Environment:
#   GITHUB_REPO  owner/name (default Aircraft-IT/smoke-collector); gh must be logged in
#   DIST_DIR     release.sh's output directory (default ./dist)
set -eu
cd "$(dirname "$0")/.."

die() { echo "publish: error: $*" >&2; exit 1; }
VERSION=""
DRY=0
for a in "$@"; do
	case $a in
	--dry-run) DRY=1 ;;
	-*) die "unknown option $a" ;;
	*) [ -z "$VERSION" ] || die "one version only"; VERSION=${a#v} ;;
	esac
done
[ -n "$VERSION" ] || die "usage: scripts/publish-github.sh <version> [--dry-run]"
REPO=${GITHUB_REPO:-Aircraft-IT/smoke-collector}
DIST=${DIST_DIR:-dist}
rel="$DIST/v$VERSION"
command -v gh >/dev/null || die "gh not found (https://cli.github.com)"
command -v go >/dev/null || die "go not found (needed to read the binaries' build info)"

commit=$(git rev-parse -q --verify "refs/tags/v$VERSION^{commit}") || die "no tag v$VERSION"
[ "$(git cat-file -t "v$VERSION")" = tag ] || die "v$VERSION is not an annotated tag (git tag -a)"
files="smoke-collector_linux_amd64 smoke-collector_linux_arm64 smoke-container-collector_linux_amd64 smoke-container-collector_linux_arm64"
for f in $files SHA256SUMS SHA256SUMS.minisig; do
	[ -f "$rel/$f" ] || die "$rel/$f missing (run scripts/release.sh $VERSION first)"
done
for f in install.sh smoke-collector.pub; do
	[ -f "$DIST/$f" ] || die "$DIST/$f missing"
done
if command -v sha256sum >/dev/null; then
	(cd "$rel" && sha256sum -c --quiet SHA256SUMS) || die "files do not match SHA256SUMS"
else
	(cd "$rel" && shasum -a 256 -c --quiet SHA256SUMS) || die "files do not match SHA256SUMS"
fi
if command -v minisign >/dev/null; then
	minisign -V -q -p "$DIST/smoke-collector.pub" -m "$rel/SHA256SUMS" -x "$rel/SHA256SUMS.minisig" ||
		die "the minisign signature does not verify"
else
	echo "publish: warning: minisign not found; signature not checked here" >&2
fi
gover=""
for f in $files; do
	info=$(go version -m "$rel/$f") || die "cannot read the build info of $f"
	rev=$(printf '%s\n' "$info" | awk '$2 ~ /^vcs.revision=/ { sub(/^vcs.revision=/, "", $2); print $2 }')
	mod=$(printf '%s\n' "$info" | awk '$2 ~ /^vcs.modified=/ { sub(/^vcs.modified=/, "", $2); print $2 }')
	[ "$rev" = "$commit" ] || die "$f was built from ${rev:-an unknown commit}, not v$VERSION ($commit)"
	[ "$mod" = false ] || die "$f was built from a tree with changes (vcs.modified=$mod)"
	modver=$(printf '%s\n' "$info" | awk '$1 == "mod" { print $3 }')
	[ "$modver" = "v$VERSION" ] || die "$f records module version $modver, not v$VERSION (built before tagging?)"
	gover=$(printf '%s\n' "$info" | sed -n '1s/.*: //p')
done

notes=$(mktemp)
trap 'rm -f "$notes"' EXIT
{
	git tag -l --format='%(contents)' "v$VERSION" | sed '/^-----BEGIN/,$d'
	cat <<EOF

**Source:** commit \`$commit\`, built with $gover.

**Verify** (the public key is \`smoke-collector.pub\`, also served by Smoke at \`/downloads/collector/smoke-collector.pub\`):

\`\`\`sh
minisign -Vm SHA256SUMS -p smoke-collector.pub
sha256sum -c --ignore-missing SHA256SUMS
go version -m smoke-collector_linux_amd64   # vcs.revision=$commit
\`\`\`

**Rebuild and compare** in a clean clone: \`git checkout v$VERSION\`, then
\`GOTOOLCHAIN=$gover scripts/reproduce.sh $VERSION /path/to/SHA256SUMS\`.
EOF
} >"$notes"

echo "publish: v$VERSION = $commit ($gover) to github.com/$REPO"
if [ "$DRY" = 1 ]; then
	echo "publish: dry run; release notes:"
	cat "$notes"
	exit 0
fi
git push "https://github.com/$REPO.git" "$commit:refs/heads/main" "refs/tags/v$VERSION"
gh release create "v$VERSION" --repo "$REPO" --verify-tag --title "smoke-collector $VERSION" \
	--notes-file "$notes" \
	"$rel/smoke-collector_linux_amd64" "$rel/smoke-collector_linux_arm64" \
	"$rel/smoke-container-collector_linux_amd64" "$rel/smoke-container-collector_linux_arm64" \
	"$rel/SHA256SUMS" "$rel/SHA256SUMS.minisig" "$DIST/install.sh" "$DIST/smoke-collector.pub"
echo "publish: done: https://github.com/$REPO/releases/tag/v$VERSION"
