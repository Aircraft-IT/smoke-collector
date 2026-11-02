#!/bin/sh
# Signing round trip with a throwaway minisign key pair (never a real key):
#   - minisign -S -l (legacy) signs a file;
#   - minisign -V and install.sh's openssl check (--verify-signature, the code path the
#     installer uses) both accept it, here and, when Docker is available, inside
#     buildpack-deps:bookworm-curl (dash, OpenSSL 3.0);
#   - a tampered file, a prehashed (non -l) signature and a signature from another key are
#     rejected by both; the unreleased install.sh (placeholder key) refuses to verify.
# Needs minisign and OpenSSL 3 (macOS: brew install minisign openssl).
set -eu
LC_ALL=C
export LC_ALL
cd "$(dirname "$0")/.."
command -v minisign >/dev/null || { echo "minisign is not installed (brew install minisign)" >&2; exit 2; }
openssl version 2>/dev/null | grep -q '^OpenSSL [3-9]' || { echo "OpenSSL 3 is needed (found: $(openssl version 2>&1))" >&2; exit 2; }

t=$(mktemp -d "${TMPDIR:-/tmp}/sc-signing.XXXXXX")
trap 'rm -rf "$t"' EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "PASS  $*"; }
bad() { fail=$((fail + 1)); echo "FAIL  $*"; }
expect() { # expect <0|1> <description> command...
	want=$1 what=$2
	shift 2
	if "$@" >"$t/out" 2>&1; then got=0; else got=1; fi
	if [ "$got" = "$want" ]; then ok "$what"; else bad "$what"; sed 's/^/      /' "$t/out"; fi
}

minisign -G -W -f -p "$t/test.pub" -s "$t/test.key" >/dev/null
minisign -G -W -f -p "$t/other.pub" -s "$t/other.key" >/dev/null
sh scripts/embed-pubkey.sh install.sh "$t/test.pub" "$t/install.sh"

printf '%s  smoke-collector_linux_amd64\n%s  smoke-collector_linux_arm64\n' \
	"$(printf a | openssl dgst -sha256 -r | cut -d' ' -f1)" "$(printf b | openssl dgst -sha256 -r | cut -d' ' -f1)" >"$t/SHA256SUMS"
minisign -S -l -s "$t/test.key" -m "$t/SHA256SUMS" -x "$t/SHA256SUMS.minisig" -t "test" >/dev/null
alg=$(sed -n 2p "$t/SHA256SUMS.minisig" | openssl base64 -d -A | dd bs=1 count=2 2>/dev/null)
[ "$alg" = Ed ] && ok "minisign -S -l writes a legacy (Ed) signature" || bad "signature algorithm is $alg, want Ed"

expect 0 "minisign -V accepts the signature" minisign -V -q -p "$t/test.pub" -m "$t/SHA256SUMS" -x "$t/SHA256SUMS.minisig"
expect 0 "install.sh (openssl) accepts the signature" sh "$t/install.sh" --verify-signature "$t/SHA256SUMS" "$t/SHA256SUMS.minisig"

cp "$t/SHA256SUMS" "$t/tampered"
cp "$t/SHA256SUMS.minisig" "$t/tampered.minisig"
sed 's/^\(.\)/f/' "$t/SHA256SUMS" >"$t/tampered" # change the first hex digit of each line
cmp -s "$t/SHA256SUMS" "$t/tampered" && bad "tampering did not change the file"
expect 1 "minisign -V rejects a tampered file" minisign -V -q -p "$t/test.pub" -m "$t/tampered" -x "$t/tampered.minisig"
expect 1 "install.sh rejects a tampered file" sh "$t/install.sh" --verify-signature "$t/tampered" "$t/tampered.minisig"
printf ' ' >>"$t/tampered2" && cat "$t/SHA256SUMS" >>"$t/tampered2"
cp "$t/SHA256SUMS.minisig" "$t/tampered2.minisig"
expect 1 "install.sh rejects a file with one extra byte" sh "$t/install.sh" --verify-signature "$t/tampered2" "$t/tampered2.minisig"

minisign -S -s "$t/test.key" -m "$t/SHA256SUMS" -x "$t/prehashed.minisig" -t "test" >/dev/null
expect 0 "minisign -V accepts a prehashed signature" minisign -V -q -p "$t/test.pub" -m "$t/SHA256SUMS" -x "$t/prehashed.minisig"
expect 1 "install.sh rejects a prehashed (no -l) signature" sh "$t/install.sh" --verify-signature "$t/SHA256SUMS" "$t/prehashed.minisig"
grep -q "prehashed" "$t/out" && ok "  ...with a message saying so" || bad "  ...message: $(cat "$t/out")"

minisign -S -l -s "$t/other.key" -m "$t/SHA256SUMS" -x "$t/other.minisig" -t "test" >/dev/null
expect 1 "minisign -V rejects another key's signature" minisign -V -q -p "$t/test.pub" -m "$t/SHA256SUMS" -x "$t/other.minisig"
expect 1 "install.sh rejects another key's signature" sh "$t/install.sh" --verify-signature "$t/SHA256SUMS" "$t/other.minisig"
# Same key id, forged signature bytes: the key-id check passes, openssl must still fail.
sed -n 2p "$t/SHA256SUMS.minisig" | openssl base64 -d -A >"$t/sig.bin"
{ dd if="$t/sig.bin" bs=1 count=10 2>/dev/null; dd if="$t/sig.bin" bs=1 skip=10 count=64 2>/dev/null | tr '\000-\377' '\001-\377\000'; } >"$t/forged.bin"
{ echo "untrusted comment: forged"; openssl base64 -A -in "$t/forged.bin"; echo; sed -n '3,4p' "$t/SHA256SUMS.minisig"; } >"$t/forged.minisig"
expect 1 "install.sh rejects a forged signature with the right key id" sh "$t/install.sh" --verify-signature "$t/SHA256SUMS" "$t/forged.minisig"
expect 1 "unreleased install.sh (placeholder key) refuses to verify" sh install.sh --verify-signature "$t/SHA256SUMS" "$t/SHA256SUMS.minisig"

if command -v docker >/dev/null 2>&1 && docker image inspect buildpack-deps:bookworm-curl >/dev/null 2>&1; then
	docker rm -f sc-signing-debian >/dev/null 2>&1 || true
	if docker run --name sc-signing-debian --network none -v "$t:/t:ro" buildpack-deps:bookworm-curl sh -c '
		openssl version
		sh /t/install.sh --verify-signature /t/SHA256SUMS /t/SHA256SUMS.minisig || exit 1
		if sh /t/install.sh --verify-signature /t/tampered /t/tampered.minisig 2>/dev/null; then exit 1; fi
	' >"$t/out" 2>&1; then
		ok "in debian:12 (dash, $(head -1 "$t/out" | cut -d' ' -f1-2)): valid accepted, tampered rejected"
	else
		bad "in debian:12"; sed 's/^/      /' "$t/out"
	fi
	docker rm -f sc-signing-debian >/dev/null 2>&1 || true
fi

echo "signing test: $pass passed, $fail failed"
[ "$fail" = 0 ]
