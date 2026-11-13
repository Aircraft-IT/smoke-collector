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
expect 1 "terms must be accepted first" "without a terminal and without --accept-terms it stops" \
	pipe_install --token-file /t/token $sigflag
check "  ...and nothing was installed" sh -c '! id smoke-collector >/dev/null 2>&1 && ! [ -e /usr/local/bin/smoke-collector ] && ! [ -e /etc/smoke-collector ]'
expect 1 "no terminal" "without a terminal and without --token-file it stops" pipe_install $sigflag --no-service --accept-terms
expect 0 "安裝與使用條款" "--show-terms --lang zh-TW prints the terms (no root needed)" \
	su -s /bin/sh nobody -c "sh /tmp/install.sh --show-terms --lang zh-TW --url $URL"
grep -qF -- "--uninstall" /tmp/out && grep -q "免責聲明" /tmp/out && ok "  ...with the disclaimer and the uninstall command" || bad "  ...terms text"
expect 0 "installation terms" "--show-terms in English" sh /tmp/install.sh --show-terms --lang en
expect 1 "--lang must be" "--lang fr is refused" sh /tmp/install.sh --show-terms --lang fr

# Fresh install through the documented pipe, signature checked when openssl exists.
expect 0 "report created" "install (curl|wget ... | sh -s -- --url ...) and first run: 201 created" \
	pipe_install --token-file /t/token $sigflag --accept-terms
grep -q "accepted with --accept-terms" /tmp/out && ok "  ...terms accepted with --accept-terms" || bad "  ...terms message"
check "terms record 0644 root:root with version and how" sh -c '[ "$(stat -c "%a %U:%G" /etc/smoke-collector/terms-accepted)" = "644 root:root" ] &&
	grep -q "^terms_version=" /etc/smoke-collector/terms-accepted && grep -qx "accepted_with=--accept-terms" /etc/smoke-collector/terms-accepted'
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
grep -q "already accepted on this host" /tmp/out && ok "  ...and the accepted terms are not asked again" || bad "  ...terms asked again"

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
	cmd="sh /tmp/install.sh --url $URL --insecure-http $sigflag --no-service --no-run --lang en"
	(sleep 2; printf 'n\n'; sleep 1) | script -q -c "$cmd" /dev/null >/tmp/out 2>&1
	if grep -q "Type y to accept" /tmp/out && grep -q "terms not accepted" /tmp/out && ! [ -e /usr/local/bin/smoke-collector ]; then
		ok "answering n at the terms prompt installs nothing"
	else
		bad "answering n at the terms prompt"
	fi
	(sleep 2; printf 'y\n'; sleep 2; printf '%s\n' "$TOKEN"; sleep 1) | script -q -c "$cmd" /dev/null >/tmp/out 2>&1
	if grep -q "Disclaimer" /tmp/out && grep -q "input hidden" /tmp/out && grep -qx "token=$TOKEN" /etc/smoke-collector/config && ! grep -qF -- "$TOKEN" /tmp/out; then
		ok "terms accepted with y, then the token typed at the /dev/tty prompt is stored and not echoed"
	else
		bad "terms prompt, then token typed at the /dev/tty prompt"
	fi
	check "  ...recorded as accepted at the prompt" grep -qx "accepted_with=prompt" /etc/smoke-collector/terms-accepted
	sh /repo/install.sh --uninstall >/dev/null 2>&1
else
	echo "SKIP  no script(1) for the interactive prompt test"
fi

# --- container collector (install.sh --containers) ---------------------------------------------
# A second fakesmoke on :8081 also serves a fake Docker Engine on /var/run/docker.sock (group
# docker, 0660) whose one container is this test container's own file system.
URL2=http://localhost:8081
pipe_c() { $fetch "$URL/downloads/collector/install.sh" | sh -s -- --url "$URL2" --insecure-http --containers "$@"; }

expect 1 "no docker group" "--containers without a docker group is refused" pipe_c --token-file /t/token $sigflag --yes --no-run
if command -v groupadd >/dev/null; then groupadd --system docker; else addgroup -S docker; fi
gid=$(awk -F: '$1 == "docker" { print $3 }' /etc/group)
mkdir -p /var/run
/t/fakesmoke -addr :8081 -dir /tmp/www -token-file /t/token -save-containers /tmp/last-containers.json \
	-docker-socket /var/run/docker.sock -docker-gid "$gid" >/tmp/fakesmoke2.log 2>&1 &
i=0
until [ -S /var/run/docker.sock ] && $fetch "$URL2/downloads/collector/LATEST" >/dev/null 2>&1; do
	i=$((i + 1)); [ $i -lt 50 ] || { echo "fakesmoke 2 did not start"; cat /tmp/fakesmoke2.log; exit 1; }
	sleep 0.1
done
expect 1 "--accept-terms" "without a terminal and without --accept-terms the container collector is not installed" pipe_c --token-file /t/token $sigflag --no-run
check "  ...and nothing was installed" sh -c '! id smoke-container >/dev/null 2>&1 && ! [ -e /usr/local/bin/smoke-container-collector ]'

# Both collectors on one host: the OS collector first, then the container collector.
expect 0 "" "OS collector installed again" pipe_install --token-file /t/token $sigflag --no-service --no-run --accept-terms
expect 0 "report accepted (HTTP 200, 1 images" "install --containers --accept-terms and first run: report accepted" \
	pipe_c --token-file /t/token $sigflag --accept-terms
check "  ...container terms recorded separately" sh -c '[ -f /etc/smoke-collector/containers.terms-accepted ] && [ -f /etc/smoke-collector/terms-accepted ]' 
grep -q "added smoke-container to the docker group" /tmp/out && ok "  ...smoke-container added to the docker group" || bad "  ...docker group message"
grep -q "local/install-test:1: created" /tmp/out && ok "  ...per-image result printed" || bad "  ...per-image result"
grep -q "container report accepted: 1 images" /tmp/fakesmoke2.log && ok "fakesmoke received the gzip container report" || bad "fakesmoke 2 log: $(cat /tmp/fakesmoke2.log)"
check "the fake Docker Engine was asked for nothing outside the allowlist" sh -c '! grep -q "docker: refused" /tmp/fakesmoke2.log'
check "binary 0755 root:root" [ "$(mode /usr/local/bin/smoke-container-collector)" = "755 root:root" ]
check "containers.config 0640 root:smoke-container" [ "$(mode /etc/smoke-collector/containers.config)" = "640 root:smoke-container" ]
check "OS config still 0640 root:smoke-collector" [ "$(mode /etc/smoke-collector/config)" = "640 root:smoke-collector" ]
check "shared config dir 0751 root:smoke-collector" [ "$(mode /etc/smoke-collector)" = "751 root:smoke-collector" ]
check "smoke-container is in the docker group" sh -c 'id -nG smoke-container | tr " " "\n" | grep -qx docker'
check "smoke-collector is not in the docker group" sh -c '! id -nG smoke-collector | tr " " "\n" | grep -qx docker'
if [ "$kind" = deb ]; then
	check "cron entry runs as smoke-container" \
		grep -Eq '^[0-9]+ [0-9]+ \* \* \* smoke-container /usr/local/bin/smoke-container-collector run' /etc/cron.d/smoke-container-collector
else
	check "crontab /etc/crontabs/smoke-container" \
		grep -Eq '^[0-9]+ [0-9]+ \* \* \* /usr/local/bin/smoke-container-collector run' /etc/crontabs/smoke-container
fi
if [ "$kind" = deb ]; then pm='#packages dpkg'; else pm='#packages apk'; fi
check "the report has the image reference and this container's packages" \
	sh -c "grep -q '\"reference\":\"local/install-test:1\"' /tmp/last-containers.json && grep -q '\"status\":\"ok\"' /tmp/last-containers.json && grep -qF '$pm' /tmp/last-containers.json"
runas_c() { su -s /bin/sh smoke-container -c "$1"; }
expect 0 "" "smoke-container-collector run --dry-run as smoke-container" runas_c "/usr/local/bin/smoke-container-collector run --dry-run"
check "the uploaded container report is exactly what --dry-run prints" cmp -s /tmp/out /tmp/last-containers.json
expect 1 "ermission denied" "smoke-container cannot read the OS collector's config" runas_c "cat /etc/smoke-collector/config"
expect 1 "ermission denied" "smoke-collector cannot read the container collector's config" runas "cat /etc/smoke-collector/containers.config"
expect 0 "status:        ok" "smoke-collector print-config still works" runas "/usr/local/bin/smoke-collector print-config --insecure-http"
expect 0 "already accepted on this host" "re-running --containers (upgrade) needs no confirmation and keeps the token" pipe_c $sigflag --no-run
grep -q "keeping the token" /tmp/out && ok "  ...token kept" || bad "  ...token not kept"

expect 0 "removed" "--uninstall --containers" sh /repo/install.sh --uninstall --containers
check "container collector gone, OS collector kept, dir back to 0750" sh -c '! [ -e /usr/local/bin/smoke-container-collector ] &&
	! [ -e /etc/smoke-collector/containers.config ] && ! [ -e /etc/smoke-collector/containers.terms-accepted ] &&
	[ -f /etc/smoke-collector/terms-accepted ] && ! id smoke-container >/dev/null 2>&1 &&
	[ -x /usr/local/bin/smoke-collector ] && [ -f /etc/smoke-collector/config ] && [ "$(stat -c %a /etc/smoke-collector)" = 750 ]'
expect 0 "" "install --containers again" pipe_c --token-file /t/token $sigflag --yes --no-run
expect 0 "removed" "--uninstall (OS collector) keeps the container collector" sh /repo/install.sh --uninstall
check "  ...containers.config and its terms record kept, dir 0751 root:root" sh -c '[ -f /etc/smoke-collector/containers.config ] &&
	[ -f /etc/smoke-collector/containers.terms-accepted ] && ! [ -e /etc/smoke-collector/terms-accepted ] &&
	! [ -e /etc/smoke-collector/config ] && [ "$(stat -c "%a %U:%G" /etc/smoke-collector)" = "751 root:root" ]'
expect 0 "" "the container collector still reads its config" runas_c "/usr/local/bin/smoke-container-collector print-config --insecure-http"
expect 0 "removed" "--uninstall --containers last" sh /repo/install.sh --uninstall --containers
check "  ...everything gone" sh -c '! [ -e /etc/smoke-collector ] && ! [ -e /usr/local/bin/smoke-container-collector ]'

# --docker-host: a proxy socket (here a third fakesmoke, group smoke-proxy) instead of the docker group.
if command -v groupadd >/dev/null; then groupadd --system smoke-proxy; else addgroup -S smoke-proxy; fi
pgid=$(awk -F: '$1 == "smoke-proxy" { print $3 }' /etc/group)
/t/fakesmoke -addr :8082 -dir /tmp/www -token-file /t/token -save-containers /tmp/last-proxy.json \
	-docker-socket /run/smoke-docker.sock -docker-gid "$pgid" >/tmp/fakesmoke3.log 2>&1 &
URL3=http://localhost:8082
i=0
until [ -S /run/smoke-docker.sock ] && $fetch "$URL3/downloads/collector/LATEST" >/dev/null 2>&1; do
	i=$((i + 1)); [ $i -lt 50 ] || { echo "fakesmoke 3 did not start"; cat /tmp/fakesmoke3.log; exit 1; }
	sleep 0.1
done
pipe_p() { $fetch "$URL/downloads/collector/install.sh" | sh -s -- --url "$URL3" --insecure-http --containers "$@"; }
in_docker() { id -nG smoke-container 2>/dev/null | tr ' ' '\n' | grep -qx docker; }
expect 1 "only unix sockets" "--docker-host tcp:// is refused" pipe_p --docker-host tcp://127.0.0.1:2375 --token-file /t/token $sigflag --yes --no-run
expect 1 "only for --containers" "--docker-host without --containers is refused" \
	sh /repo/install.sh --url "$URL3" --insecure-http --skip-signature --docker-host unix:///run/x.sock --token-file /t/token
expect 0 "not added to the docker group" "install --containers --docker-host --yes" \
	pipe_p --docker-host unix:///run/smoke-docker.sock --token-file /t/token $sigflag --yes --no-run
check "  ...smoke-container is not in the docker group" sh -c "! id -nG smoke-container | tr ' ' '\n' | grep -qx docker"
check "  ...containers.config has docker_host" grep -qx "docker_host=unix:///run/smoke-docker.sock" /etc/smoke-collector/containers.config
expect 2 "cannot reach Docker" "without access to the proxy socket the run fails (exit 2)" \
	runas_c "/usr/local/bin/smoke-container-collector run --insecure-http"
if command -v usermod >/dev/null; then usermod -aG smoke-proxy smoke-container; else addgroup smoke-container smoke-proxy; fi
expect 0 "report accepted" "with the proxy socket's group the run succeeds" runas_c "/usr/local/bin/smoke-container-collector run --insecure-http"
grep -q "container report accepted: 1 images" /tmp/fakesmoke3.log && ok "  ...through the proxy socket" || bad "fakesmoke 3 log: $(cat /tmp/fakesmoke3.log)"
expect 0 "keeping docker_host=unix:///run/smoke-docker.sock" "upgrade without --docker-host keeps the proxy socket" pipe_p $sigflag --no-run
if in_docker; then echo "in docker group" >/tmp/out; bad "  ...still not in the docker group"; else ok "  ...still not in the docker group"; fi
expect 0 "removed" "--uninstall --containers (proxy)" sh /repo/install.sh --uninstall --containers
# From the docker group to a proxy socket: the docker group is taken away.
expect 0 "added smoke-container to the docker group" "install --containers with the docker group" pipe_c --token-file /t/token $sigflag --yes --no-run
expect 0 "removed smoke-container from the docker group" "re-install with --docker-host leaves the docker group" \
	pipe_p --docker-host unix:///run/smoke-docker.sock $sigflag --yes --no-run
if in_docker; then echo "in docker group" >/tmp/out; bad "  ...not in the docker group any more"; else ok "  ...not in the docker group any more"; fi
expect 0 "removed" "--uninstall --containers" sh /repo/install.sh --uninstall --containers
cat /tmp/fakesmoke3.log >>/tmp/all-output

cat /tmp/fakesmoke2.log >>/tmp/all-output
if grep -qF -- "$TOKEN" /tmp/all-output; then echo "token printed" >/tmp/out; bad "the token never appears in any output (containers)"; else ok "the token never appears in any output (containers)"; fi

echo "RESULT $pass passed, $fail failed"
[ "$fail" = 0 ]
