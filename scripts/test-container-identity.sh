#!/bin/sh
# Container collector identity check (spec FR-COL-09): for each test image, start a container,
# read it the way smoke-container-collector does (Docker API archive reads, test/containeridentity)
# and compare the #os-release and #packages sections with what the page command
# (testdata/plan-commands, plan §2.1/§2.2) prints inside the same container.
#   IDENTICAL  byte for byte
#   SAME SET   the same lines in another order (the backend does not depend on the order)
# Other kinds: unsupported (rpm images), nopkg (no package database), distroless (no shell:
# only checks that packages were read from status.d).
#
# Only the test's own containers (scci-*) are read; nothing else on the Docker host is listed.
# Images are never pulled (--pull never): missing ones are skipped.
#   scripts/test-container-identity.sh
#   CONTAINER_IDENTITY_IMAGES="ubuntu:24.04:deb nginx:alpine:apk" scripts/test-container-identity.sh
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
socket=${DOCKER_SOCKET:-$(docker context inspect --format '{{.Endpoints.docker.Host}}' | sed 's#^unix://##')}
images=${CONTAINER_IDENTITY_IMAGES:-"ubuntu:24.04:deb debian:12:deb alpine:3.21:apk gcr.io/distroless/base-debian12:latest:distroless rockylinux:9:unsupported busybox:1.36:nopkg"}
t=$(mktemp -d "${TMPDIR:-/tmp}/scci.XXXXXX")
names=""
cleanup() {
	for n in $names; do docker rm -f "$n" >/dev/null 2>&1 || true; done
	rm -rf "$t"
}
trap cleanup EXIT
go build -o "$t/containeridentity" ./test/containeridentity
mkdir -p "$t/out"
sections() { awk '/^#/ { keep = ($0 == "#smoke-host 1" || $0 == "#os-release" || $0 ~ /^#packages /) } keep'; }

fail=0 ran=0
for spec in $images; do
	image=${spec%:*} kind=${spec##*:}
	tag=$(echo "${image##*/}" | tr ':.' '--')
	name="scci-$tag"
	names="$names $name"
	docker rm -f "$name" >/dev/null 2>&1 || true
	if ! docker run -d --pull never --network none --name "$name" -v "$root/testdata/plan-commands:/t:ro" \
		--entrypoint sleep "$image" 600 >/dev/null 2>"$t/run.err"; then
		echo "SKIP       $image ($(head -1 "$t/run.err"))"
		continue
	fi
	ran=$((ran + 1))
	id=$(docker inspect -f '{{.Id}}' "$name")
	imageid=$(docker inspect -f '{{.Image}}' "$name")
	"$t/containeridentity" -socket "$socket" -out "$t/out" "$tag=$id,$imageid,$image" 2>"$t/col.err" ||
		{ echo "FAIL       $image: $(cat "$t/col.err")"; fail=1; continue; }
	status=$(sed -n 1p "$t/out/$tag.txt")
	sed 1d "$t/out/$tag.txt" >"$t/got.txt"
	case $kind in
	deb | apk)
		docker exec "$name" sh -c "cd /tmp && sh /t/$kind.sh >/dev/null && cat smoke-host.txt" | sections >"$t/want.txt"
		if [ "$status" != status=ok ]; then
			echo "FAIL       $image: $status"; fail=1
		elif cmp -s "$t/want.txt" "$t/got.txt"; then
			echo "IDENTICAL  $image  $(grep -c . "$t/got.txt") lines"
		elif [ "$(sort "$t/want.txt")" = "$(sort "$t/got.txt")" ]; then
			echo "SAME SET   $image  $(grep -c . "$t/got.txt") lines (order differs)"
		else
			echo "DIFFERENT  $image"; diff -u "$t/want.txt" "$t/got.txt" | head -40; fail=1
		fi
		;;
	distroless)
		n=$(grep -c '^ii ' "$t/got.txt" || true)
		if [ "$status" = status=ok ] && [ "$n" -gt 0 ]; then echo "OK         $image  $n packages from status.d"; else echo "FAIL       $image: $status, $n packages"; fail=1; fi
		;;
	unsupported | nopkg)
		want=status=unsupported
		[ "$kind" = nopkg ] && want=status=no_packages
		if [ "$status" = "$want" ]; then echo "OK         $image  $status"; else echo "FAIL       $image: $status, want $want"; fail=1; fi
		;;
	*) echo "unknown kind $kind" >&2; exit 2 ;;
	esac
done
[ "$ran" -gt 0 ] || { echo "no image could be started"; exit 1; }
[ "$fail" = 0 ] && echo "container identity: all passed" || { echo "container identity: FAILED"; exit 1; }
