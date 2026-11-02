#!/bin/sh
# Writes a copy of install.sh with the minisign public key in place of the placeholder.
# Used by release.sh and by the tests, so both exercise the same substitution.
#   scripts/embed-pubkey.sh <install.sh> <minisign .pub file> <output>
set -eu
[ $# -eq 3 ] || { echo "usage: $0 <install.sh> <pubkey.pub> <output>" >&2; exit 1; }
src=$1 pub=$2 out=$3
# A minisign public key file: an "untrusted comment:" line, then the base64 key (42 bytes:
# "Ed", 8-byte key id, 32-byte Ed25519 key = 56 base64 characters).
key=$(sed -n 2p "$pub" | tr -d '\r')
case $key in
RW*) ;;
*) echo "$pub does not look like a minisign public key" >&2; exit 1 ;;
esac
[ "${#key}" -eq 56 ] || { echo "$pub: unexpected key length" >&2; exit 1; }
case $key in *[!A-Za-z0-9+/=]*) echo "$pub: key is not base64" >&2; exit 1 ;; esac
grep -q '^PUBKEY="__SMOKE_COLLECTOR_PUBKEY__"$' "$src" || { echo "$src has no public key placeholder" >&2; exit 1; }
sed "s#^PUBKEY=\"__SMOKE_COLLECTOR_PUBKEY__\"\$#PUBKEY=\"$key\"#" "$src" >"$out"
grep -q "^PUBKEY=\"$key\"\$" "$out" || { echo "substitution failed" >&2; exit 1; }
