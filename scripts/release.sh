#!/bin/sh
# Release smoke-collector (OS detection plan §5.4). Run on your own machine: the minisign
# secret key never goes to CI.
#
#   scripts/release.sh <version> [--no-image] [--no-push] [--allow-dirty]
#
# 1. builds smoke-collector and smoke-container-collector for linux amd64 and arm64
#    (CGO_ENABLED=0, version stamped in);
# 2. writes SHA256SUMS and signs it with `minisign -S -l` (legacy: a plain Ed25519 signature
#    over the file, which install.sh verifies with openssl); minisign asks for the key password;
# 3. writes install.sh with the public key embedded, LATEST and smoke-collector.pub;
# 4. builds the image $SMOKE_REGISTRY/smoke/smoke-collector/dist:<version> (Dockerfile.dist) and
#    pushes it.
#
# The binaries come from scripts/build.sh, which reproduce.sh also uses. Then tag the commit
# (git tag -a v<version>), push it to the internal repository and run
# scripts/publish-github.sh <version> to publish the source and the release on GitHub.
#
# The download tree is left in $DIST_DIR (default ./dist), laid out like /downloads/collector/:
#   install.sh  LATEST  smoke-collector.pub  v<version>/{smoke-collector_linux_amd64,
#   smoke-collector_linux_arm64, smoke-container-collector_linux_amd64,
#   smoke-container-collector_linux_arm64, SHA256SUMS, SHA256SUMS.minisig}
#
# Environment:
#   MINISIGN_SECRET_KEY  default ~/.minisign/smoke-collector.key
#   MINISIGN_PUBLIC_KEY  default ~/.minisign/smoke-collector.pub
#   SMOKE_REGISTRY       registry host for the image (required unless --no-image or --no-push)
#   DIST_DIR             output directory (default ./dist)
#   DIST_PLATFORM        image platform (default linux/amd64)
set -eu
cd "$(dirname "$0")/.."

usage() { sed -n '2,/^set -eu/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; }
die() { echo "release: error: $*" >&2; exit 1; }

VERSION=""
NO_IMAGE=0
NO_PUSH=0
ALLOW_DIRTY=0
for a in "$@"; do
	case $a in
	--no-image) NO_IMAGE=1 ;;
	--no-push) NO_PUSH=1 ;;
	--allow-dirty) ALLOW_DIRTY=1 ;;
	-h | --help) usage; exit 0 ;;
	-*) die "unknown option $a" ;;
	*) [ -z "$VERSION" ] || die "one version only"; VERSION=${a#v} ;;
	esac
done
[ -n "$VERSION" ] || { usage; exit 1; }
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || die "invalid version $VERSION"

SECRET=${MINISIGN_SECRET_KEY:-$HOME/.minisign/smoke-collector.key}
PUBLIC=${MINISIGN_PUBLIC_KEY:-$HOME/.minisign/smoke-collector.pub}
DIST=${DIST_DIR:-dist}
PLATFORM=${DIST_PLATFORM:-linux/amd64}
command -v go >/dev/null || die "go not found"
command -v minisign >/dev/null || die "minisign not found (brew install minisign / apt-get install minisign)"
[ -r "$SECRET" ] || die "cannot read the minisign secret key $SECRET (set MINISIGN_SECRET_KEY)"
[ -r "$PUBLIC" ] || die "cannot read the minisign public key $PUBLIC (set MINISIGN_PUBLIC_KEY)"
if [ "$NO_IMAGE" = 0 ]; then
	command -v docker >/dev/null || die "docker not found (or pass --no-image)"
	[ "$NO_PUSH" = 1 ] || [ -n "${SMOKE_REGISTRY:-}" ] || die "set SMOKE_REGISTRY (or pass --no-push)"
fi
if [ "$ALLOW_DIRTY" = 0 ] && command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then
	[ -z "$(git status --porcelain 2>/dev/null)" ] || die "the working tree has changes (commit them, or pass --allow-dirty)"
fi

rel="$DIST/v$VERSION"
rm -rf "$DIST"
mkdir -p "$rel"

echo "release: building $VERSION ($(go env GOVERSION))"
sh scripts/build.sh "$VERSION" "$rel"

echo "release: signing SHA256SUMS (minisign -S -l)"
minisign -S -l -s "$SECRET" -m "$rel/SHA256SUMS" -x "$rel/SHA256SUMS.minisig" \
	-t "smoke-collector $VERSION SHA256SUMS"
minisign -V -q -p "$PUBLIC" -m "$rel/SHA256SUMS" -x "$rel/SHA256SUMS.minisig" ||
	die "minisign cannot verify the signature it just made (wrong public key?)"

sh scripts/embed-pubkey.sh install.sh "$PUBLIC" "$DIST/install.sh"
cp "$PUBLIC" "$DIST/smoke-collector.pub"
printf '%s\n' "$VERSION" >"$DIST/LATEST"
chmod 0755 "$rel"/smoke-collector_linux_* "$rel"/smoke-container-collector_linux_*
chmod 0644 "$DIST/install.sh" "$DIST/LATEST" "$DIST/smoke-collector.pub" "$rel/SHA256SUMS" "$rel/SHA256SUMS.minisig"

# The same check install.sh makes on the host (needs OpenSSL 3 here; macOS: brew install openssl).
if openssl version 2>/dev/null | grep -q '^OpenSSL [3-9]'; then
	sh "$DIST/install.sh" --verify-signature "$rel/SHA256SUMS" "$rel/SHA256SUMS.minisig" ||
		die "install.sh cannot verify the signature"
else
	echo "release: warning: OpenSSL 3 not found; install.sh's own signature check was not run" >&2
fi

if [ "$NO_IMAGE" = 0 ]; then
	image="${SMOKE_REGISTRY:-local}/smoke/smoke-collector/dist:$VERSION"
	echo "release: building $image"
	docker build --platform "$PLATFORM" -f Dockerfile.dist -t "$image" "$DIST"
	if [ "$NO_PUSH" = 0 ]; then
		docker push "$image"
	fi
fi
echo "release: done"
find "$DIST" -type f | sort
