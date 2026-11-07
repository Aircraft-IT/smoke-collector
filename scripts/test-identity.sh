#!/bin/sh
# Byte-identity check (OS detection plan §5.1): on ubuntu:24.04, debian:12, alpine:3.21,
# rockylinux:9, almalinux:9 and Red Hat UBI 9, `smoke-collector run --dry-run` must print exactly
# what the plan's shell command writes to smoke-host.txt. Runs as root and as an unprivileged
# user; on Debian/Ubuntu and the rpm distributions also with a reboot pending
# (/var/run/reboot-required, or a stand-in needs-restarting that exits 1) and with a stand-in
# systemctl (containers have none).
# When the smoke-backend checkout sits next to this repo, every output is also parsed with the
# backend's host-text.ts parser (node:26-alpine).
#   scripts/test-identity.sh            # needs Docker
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
arch=$(docker version --format '{{.Server.Arch}}')
bin=$(mktemp -d "${TMPDIR:-/tmp}/sc-identity.XXXXXX")
out="$bin/out"
mkdir -p "$out" && chmod 777 "$out"
trap 'rm -rf "$bin"' EXIT
echo "building linux/$arch"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$bin/smoke-collector" ./cmd/smoke-collector

fake_systemctl='printf "%s\n" "cron.service loaded active running Regular background program processing daemon" "ssh.service    loaded active running OpenBSD Secure Shell server" "user@1000.service loaded active running User Manager for UID 1000"'

fail=0
run() { # name user image command...
	name=$1 user=$2 image=$3
	shift 3
	docker rm -f "$name" >/dev/null 2>&1 || true
	if ! docker run --name "$name" --user "$user" --network none \
		-v "$bin:/opt/sc:ro" -v "$out:/out" -v "$root/testdata:/t/testdata:ro" -v "$root/scripts:/t/scripts:ro" \
		"$image" sh -c "$*"; then
		fail=1
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
}

for spec in ubuntu:24.04:deb debian:12:deb alpine:3.21:apk rockylinux:9:rpm almalinux:9:rpm \
	registry.access.redhat.com/ubi9/ubi:latest:rpm; do
	image=${spec%:*} kind=${spec##*:}
	tag=$(echo "${image##*/}" | tr ':.' '--')
	run "sc-identity-$tag-root" 0:0 "$image" "sh /t/scripts/identity-inner.sh $kind $tag-root /out"
	run "sc-identity-$tag-nobody" 65534:65534 "$image" "sh /t/scripts/identity-inner.sh $kind $tag-nonroot /out"
	if [ "$kind" = deb ]; then
		run "sc-identity-$tag-reboot" 0:0 "$image" \
			"touch /var/run/reboot-required && sh /t/scripts/identity-inner.sh $kind $tag-reboot-required /out"
	elif [ "$kind" = rpm ]; then
		run "sc-identity-$tag-reboot" 0:0 "$image" \
			"printf '#!/bin/sh\nexit 1\n' >/usr/bin/needs-restarting && chmod 755 /usr/bin/needs-restarting && sh /t/scripts/identity-inner.sh $kind $tag-reboot-required /out"
	fi
	if [ "$kind" != apk ]; then
		run "sc-identity-$tag-systemctl" 0:0 "$image" \
			"printf '#!/bin/sh\n%s\n' '$fake_systemctl' >/usr/bin/systemctl && chmod 755 /usr/bin/systemctl && sh /t/scripts/identity-inner.sh $kind $tag-services /out"
	fi
done

backend="$root/../smoke-backend/src/inventory/parsers"
if [ "$fail" = 0 ] && [ -f "$backend/host-text.ts" ]; then
	echo "parsing every output with smoke-backend host-text.ts"
	parser="$bin/parser"
	mkdir -p "$parser"
	sed "s#'./errors.js'#'./errors.ts'#" "$backend/host-text.ts" >"$parser/host-text.ts"
	# errors.ts uses parameter properties, which node's type stripping rejects: a stand-in with
	# the same constructor. host-text.ts itself is used unchanged (apart from the import suffix).
	cat >"$parser/errors.ts" <<'TS'
export class InventoryParseError extends Error {
  code: string;
  constructor(code: string, message: string, _params?: unknown) { super(message); this.code = code; }
}
TS
	cat >"$parser/check.ts" <<'TS'
import { readFileSync, readdirSync } from 'node:fs';
import { parseHostText } from './host-text.ts';
let bad = 0;
for (const f of readdirSync('/out').sort()) {
  try {
    const h = parseHostText(readFileSync(`/out/${f}`, 'utf8'));
    console.log(`PARSED     ${f}: ${h.distro.id} ${h.distro.versionId} ${h.packageManager} packages=${h.packages.length} services=${h.services.length} reboot=${h.rebootRequired} dropped=${JSON.stringify(h.dropped)}`);
  } catch (e) { bad++; console.log(`REJECTED   ${f}: ${(e as Error).message}`); }
}
process.exit(bad ? 1 : 0);
TS
	docker rm -f sc-identity-parser >/dev/null 2>&1 || true
	docker run --name sc-identity-parser --network none -v "$out:/out:ro" -v "$parser:/p:ro" node:26-alpine \
		node --experimental-strip-types --no-warnings /p/check.ts || fail=1
	docker rm -f sc-identity-parser >/dev/null 2>&1 || true
fi
[ "$fail" = 0 ] && echo "all identical" || { echo "FAILED"; exit 1; }
