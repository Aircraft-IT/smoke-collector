#!/bin/sh
# Runs inside a test container as root (see test-install.sh). /t holds the signed download tree
# (/t/dist), fakesmoke, the token files; /repo/install.sh is the unreleased copy.
#   install-inner.sh <deb|apk>
set -u
kind=$1
TOKEN=$(cat /t/token)
URL=http://localhost:8080
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "PASS  $*"; }
bad() { fail=$((fail + 1)); echo "FAIL  $*"; sed 's/^/      /' /tmp/out; }
# expect <exit code> <text the output must contain> <description> command...
expect() {
	want=$1 text=$2 what=$3
	shift 3
	"$@" >/tmp/out 2>&1 </dev/null
	got=$?
	cat /tmp/out >>/tmp/all-output
	if [ "$got" != "$want" ]; then bad "$what (exit $got, want $want)"; return; fi
	if [ -n "$text" ] && ! grep -qF -- "$text" /tmp/out; then bad "$what (output lacks: $text)"; return; fi
	ok "$what"
}
check() { # check <description> test-args...
	what=$1
	shift
	if "$@"; then ok "$what"; else echo "$*" >/tmp/out; bad "$what"; fi
}
mode() { stat -c '%a %U:%G' "$1" 2>/dev/null; }

if command -v curl >/dev/null; then fetch="curl -fsSL"; else fetch="wget -qO-"; fi
cp -R /t/dist /tmp/www
/t/fakesmoke -addr :8080 -dir /tmp/www -token-file /t/token -save /tmp/last-report.txt >/tmp/fakesmoke.log 2>&1 &
i=0
until $fetch "$URL/downloads/collector/LATEST" >/dev/null 2>&1; do
	i=$((i + 1)); [ $i -lt 50 ] || { echo "fakesmoke did not start"; cat /tmp/fakesmoke.log; exit 1; }
	sleep 0.1
done
[ "$kind" = deb ] && mkdir -p /etc/cron.d # the cron path (no cron package in the image, so no /etc/cron.d)
sigflag=""
if ! command -v openssl >/dev/null; then sigflag=--skip-signature; fi
$fetch "$URL/downloads/collector/install.sh" >/tmp/install.sh
pipe_install() { $fetch "$URL/downloads/collector/install.sh" | sh -s -- --url "$URL/" --insecure-http "$@"; }

expect 1 "no public key" "repository install.sh (placeholder key) refuses without --skip-signature" \
	sh /repo/install.sh --url "$URL" --insecure-http --token-file /t/token
expect 1 "never given on the command line" "--token on the command line is refused" \
	sh /repo/install.sh --url "$URL" --token smk_x
expect 1 "must use https://" "http:// without --insecure-http is refused" \
	sh /tmp/install.sh --url "$URL" --token-file /t/token --no-run
expect 1 "must use https://" "http:// to a non-localhost host is refused" \
	sh /repo/install.sh --url http://smoke.example.com --insecure-http --skip-signature --token-file /t/token
if [ -n "$sigflag" ]; then
	expect 1 "apk add openssl" "without openssl the signature check stops and says how to fix it" \
		pipe_install --token-file /t/token
fi
expect 1 "no terminal" "without a terminal and without --token-file it stops" pipe_install $sigflag --no-service

# Fresh install through the documented pipe, signature checked when openssl exists.
expect 0 "report created" "install (curl|wget ... | sh -s -- --url ...) and first run: 201 created" \
	pipe_install --token-file /t/token $sigflag
[ -z "$sigflag" ] && { grep -q "signature of SHA256SUMS verified" /tmp/out && ok "signature verified with openssl" || bad "signature not verified"; }
grep -q "report created" /tmp/fakesmoke.log && ok "fakesmoke received a gzip report with the token" || bad "fakesmoke log: $(cat /tmp/fakesmoke.log)"
check "binary 0755 root:root" [ "$(mode /usr/local/bin/smoke-collector)" = "755 root:root" ]
check "config dir 0750 root:smoke-collector" [ "$(mode /etc/smoke-collector)" = "750 root:smoke-collector" ]
check "config 0640 root:smoke-collector" [ "$(mode /etc/smoke-collector/config)" = "640 root:smoke-collector" ]
check "config holds url and token" grep -qx "token=$TOKEN" /etc/smoke-collector/config
check "config url has no trailing slash" grep -qx "url=$URL" /etc/smoke-collector/config
check "system user without a login shell" sh -c 'id smoke-collector >/dev/null && ! grep "^smoke-collector:" /etc/passwd | grep -q "sh$"'
if [ "$kind" = deb ]; then
	check "cron entry in /etc/cron.d runs as smoke-collector" \
		grep -Eq '^[0-9]+ [0-9]+ \* \* \* smoke-collector /usr/local/bin/smoke-collector run' /etc/cron.d/smoke-collector
else
	check "crontab /etc/crontabs/smoke-collector (busybox crond, per-user)" \
		grep -Eq '^[0-9]+ [0-9]+ \* \* \* /usr/local/bin/smoke-collector run' /etc/crontabs/smoke-collector
fi
runas() { su -s /bin/sh smoke-collector -c "$1"; }
expect 0 "" "smoke-collector run --dry-run as the smoke-collector user" runas "/usr/local/bin/smoke-collector run --dry-run"
cp /tmp/out /tmp/dry-run.txt
check "the uploaded report is exactly what --dry-run prints" cmp -s /tmp/dry-run.txt /tmp/last-report.txt
expect 0 "${TOKEN%"${TOKEN#????????}"}…" "print-config as smoke-collector shows the first 8 characters" \
	runas "/usr/local/bin/smoke-collector print-config --insecure-http"
check "print-config does not show more of the token" sh -c "! grep -qF '${TOKEN%"${TOKEN#?????????}"}' /tmp/out"
expect 1 "permission denied" "another unprivileged user cannot read the config" \
	su -s /bin/sh nobody -c "/usr/local/bin/smoke-collector print-config"
expect 0 "report unchanged" "smoke-collector run again: 200 unchanged" runas "/usr/local/bin/smoke-collector run --insecure-http"

# Upgrade: no terminal, no --token-file: the existing token is kept.
expect 0 "keeping the token" "re-running install.sh keeps the existing token (no prompt)" pipe_install $sigflag --no-service
grep -q "report unchanged" /tmp/out && ok "  ...and the run reports unchanged" || bad "  ...run output"

# Wrong token: the install completes but the first run is rejected (exit 3, 401).
expect 3 "HTTP 401 UNAUTHENTICATED" "a wrong token gives exit 3 with the server's code" \
	pipe_install --token-file /t/wrong-token $sigflag --no-service

# Tampered downloads.
if [ -z "$sigflag" ]; then
	cp /tmp/www/v*/SHA256SUMS /tmp/sums.bak
	sed -i '1s/^./0/' /tmp/www/v*/SHA256SUMS
	expect 1 "SIGNATURE CHECK FAILED" "a tampered SHA256SUMS is rejected" pipe_install --token-file /t/token --no-run
	cp /tmp/sums.bak /tmp/www/v*/SHA256SUMS
fi
for f in /tmp/www/v*/smoke-collector_linux_*; do cp "$f" "$f.bak" && printf 'x' >>"$f"; done
expect 1 "SHA-256 mismatch" "a tampered binary is rejected" pipe_install --token-file /t/token $sigflag --no-run
for f in /tmp/www/v*/smoke-collector_linux_*.bak; do mv "$f" "${f%.bak}"; done

# Never print the token.
cat /tmp/fakesmoke.log >>/tmp/all-output
if grep -qF -- "$TOKEN" /tmp/all-output; then echo "token printed" >/tmp/out; bad "the token never appears in any output"; else ok "the token never appears in any output"; fi

expect 0 "removed" "--uninstall" sh /repo/install.sh --uninstall
check "binary, config, cron entries and user are gone" sh -c '! [ -e /usr/local/bin/smoke-collector ] && ! [ -e /etc/smoke-collector ] &&
	! [ -e /etc/cron.d/smoke-collector ] && ! [ -e /etc/crontabs/smoke-collector ] && ! id smoke-collector >/dev/null 2>&1'

# Interactive install: the token is typed at the /dev/tty prompt (a pty from script(1)) with
# echo off, so it must not appear in what the terminal shows.
if command -v script >/dev/null; then
	cmd="sh /tmp/install.sh --url $URL --insecure-http $sigflag --no-service --no-run"
	(sleep 2; printf '%s\n' "$TOKEN"; sleep 1) | script -q -c "$cmd" /dev/null >/tmp/out 2>&1
	if grep -q "input hidden" /tmp/out && grep -qx "token=$TOKEN" /etc/smoke-collector/config && ! grep -qF -- "$TOKEN" /tmp/out; then
		ok "token typed at the /dev/tty prompt is stored and not echoed"
	else
		bad "token typed at the /dev/tty prompt"
	fi
	sh /repo/install.sh --uninstall >/dev/null 2>&1
else
	echo "SKIP  no script(1) for the interactive prompt test"
fi

echo "RESULT $pass passed, $fail failed"
[ "$fail" = 0 ]
