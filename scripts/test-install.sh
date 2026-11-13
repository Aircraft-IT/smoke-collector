#!/bin/sh
# End-to-end install.sh test in containers (systemd does not run there, so the cron path is
# exercised). A throwaway minisign key signs a release made by scripts/release.sh
# (--no-image); test/fakesmoke serves it under /downloads/collector/ and accepts reports on
# localhost, so nothing leaves the container (--network none).
# Images: buildpack-deps:noble-curl (Ubuntu 24.04) and buildpack-deps:bookworm-curl (Debian 12),
# which have curl and OpenSSL 3, and alpine:3.21 (busybox wget, no openssl: signature check
# skipped after checking that install.sh refuses without it).
# Needs Docker, Go, minisign.
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
command -v minisign >/dev/null || { echo "minisign is not installed (brew install minisign)" >&2; exit 2; }
arch=$(docker version --format '{{.Server.Arch}}')
t=$(mktemp -d "${TMPDIR:-/tmp}/sc-install.XXXXXX")
trap 'rm -rf "$t"' EXIT

minisign -G -W -f -p "$t/test.pub" -s "$t/test.key" >/dev/null
DIST_DIR="$t/dist" MINISIGN_SECRET_KEY="$t/test.key" MINISIGN_PUBLIC_KEY="$t/test.pub" \
	sh scripts/release.sh 0.1.0 --no-image --allow-dirty >"$t/release.log" 2>&1 || { cat "$t/release.log"; exit 1; }
echo "release.sh with a throwaway key: ok ($(find "$t/dist" -type f | wc -l | tr -d ' ') files)"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$t/fakesmoke" ./test/fakesmoke
printf 'smk_install_test_%s\n' "$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')" >"$t/token"
printf 'smk_wrong_token_%s\n' "$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')" >"$t/wrong-token"
chmod -R a+rX "$t"

fail=0
# INSTALL_TEST_IMAGES overrides the list ("image:tag:deb image:tag:apk"; images that have curl
# or busybox wget).
for spec in ${INSTALL_TEST_IMAGES:-buildpack-deps:noble-curl:deb buildpack-deps:bookworm-curl:deb alpine:3.21:apk}; do
	image=${spec%:*} kind=${spec##*:}
	name="sc-install-$(echo "$image" | tr ':.' '--' | sed 's#.*/##')"
	echo "=== $image"
	docker rm -f "$name" >/dev/null 2>&1 || true
	docker run --name "$name" --network none -v "$t:/t:ro" -v "$root/install.sh:/repo/install.sh:ro" \
		-v "$root/scripts/install-inner.sh:/inner.sh:ro" "$image" sh /inner.sh "$kind" || fail=1
	docker rm -f "$name" >/dev/null 2>&1 || true
done
[ "$fail" = 0 ] && echo "install test: all passed" || { echo "install test: FAILED"; exit 1; }
