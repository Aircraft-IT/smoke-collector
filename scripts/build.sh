#!/bin/sh
# Builds the release binaries exactly as published, so release.sh and reproduce.sh cannot drift:
#
#   scripts/build.sh <version> <output directory>
#
# smoke-collector and smoke-container-collector for linux amd64 and arm64, CGO off, -trimpath,
# the version stamped in, and SHA256SUMS over the four files. Go also records the commit
# (vcs.revision), its time and whether the tree had changes (vcs.modified); `go version -m` shows
# them. The same commit, the same Go version and a clean checkout give the same bytes.
set -eu
cd "$(dirname "$0")/.."

die() { echo "build: error: $*" >&2; exit 1; }
[ $# -eq 2 ] || die "usage: scripts/build.sh <version> <output directory>"
VERSION=${1#v}
OUT=$2
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || die "invalid version $VERSION"
command -v go >/dev/null || die "go not found"

if command -v sha256sum >/dev/null; then sha() { sha256sum "$@"; }; else sha() { shasum -a 256 "$@"; }; fi

mkdir -p "$OUT"
for prog in smoke-collector smoke-container-collector; do
	for arch in amd64 arm64; do
		CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
			-ldflags "-s -w -X github.com/aircraft-it/smoke-collector/internal/version.Version=$VERSION" \
			-o "$OUT/${prog}_linux_$arch" "./cmd/$prog"
	done
done
(cd "$OUT" && sha smoke-collector_linux_amd64 smoke-collector_linux_arm64 \
	smoke-container-collector_linux_amd64 smoke-container-collector_linux_arm64 >SHA256SUMS)
