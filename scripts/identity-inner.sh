#!/bin/sh
# Runs inside a test container (see test-identity.sh): runs the plan's shell command
# (testdata/plan-commands/<kind>.sh, verbatim from OS-DETECTION-PLAN §2.1/§2.2) and
# `smoke-collector run --dry-run`, and compares the two outputs byte for byte.
#   identity-inner.sh <deb|apk> <label> <outdir>
set -eu
kind=$1 label=$2 out=$3
work=$(mktemp -d)
cd "$work"
sh "/t/testdata/plan-commands/$kind.sh" >saved.txt
/opt/sc/smoke-collector run --dry-run >dry-run.txt
if cmp -s smoke-host.txt dry-run.txt; then
	echo "IDENTICAL  $label  $(wc -c <dry-run.txt | tr -d ' ') bytes  $(grep -c . dry-run.txt) lines  user=$(id -un 2>/dev/null || id -u)"
	cp dry-run.txt "$out/$label.txt" 2>/dev/null || true
else
	echo "DIFFERENT  $label"
	diff -u smoke-host.txt dry-run.txt || true
	exit 1
fi
