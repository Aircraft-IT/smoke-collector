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
/t/fakesmoke -addr :8080 -dir /tmp/www -token-file /t/token -save /tmp/last-report.txt -save-lockfiles /tmp/last-lockfiles.json >/tmp/fakesmoke.log 2>&1 &
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
# --replace-token: the existing token is not kept, so without a terminal or token file it stops
# before anything changes.
expect 1 "no terminal to read the smoke-collector token" "--replace-token asks for a new token even when one is set" \
	pipe_install --replace-token $sigflag --no-service
check "  ...and the configured token is unchanged" grep -qx "token=$TOKEN" /etc/smoke-collector/config

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
	cmd="sh /tmp/install.sh --url $URL --insecure-http $sigflag --no-service --no-run --lang en --scan os"
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
expect 1 "no terminal to read the smoke-container-collector token" "--replace-token asks for the container collector's new token" \
	pipe_c --replace-token $sigflag --no-run

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

# --- lockfiles and --scan (plan §4b, decision 8) ------------------------------------------------
# Fixtures: a Capistrano-style symlinked release with a .env next to the lockfile, an app under
# /home that smoke-collector cannot enter, and a lockfile it cannot read.
mkdir -p /srv/billing/releases/1 /home/app/shop /home/app/other /srv/closed /root/app
printf '{"lockfileVersion": 3, "packages": {}}\n' >/srv/billing/releases/1/package-lock.json
printf 'SECRET=never-sent\n' >/srv/billing/releases/1/.env
ln -s /srv/billing/releases/1 /srv/billing/current
printf 'flask==3.0.0\n' >/home/app/shop/requirements.txt
printf 'module example.com/other\n' >/home/app/other/go.mod
ln -s /home/app/other /srv/otherlink
printf 'version = 1\n' >/root/app/uv.lock
chmod 0700 /home/app
printf '# yarn lockfile v1\n' >/srv/closed/yarn.lock
chmod 0600 /srv/closed/yarn.lock
reports() { grep -cE 'report (created|unchanged)' /tmp/fakesmoke.log; }

expect 1 "add --lockfile PATH" "--scan lockfiles without a path and without a terminal stops" \
	pipe_install --scan lockfiles --token-file /t/token $sigflag --yes
check "  ...and nothing was installed" sh -c '! [ -e /usr/local/bin/smoke-collector ] && ! [ -e /etc/smoke-collector ]'
expect 1 "needs lockfiles in --scan" "--lockfile with --scan os is refused" pipe_install --scan os --lockfile /srv/x --token-file /t/token $sigflag --yes
expect 1 "must be an absolute path" "a relative --lockfile is refused" pipe_install --scan lockfiles --lockfile srv/x --token-file /t/token $sigflag --yes
expect 1 "must be a clean path" "--lockfile with .. is refused" pipe_install --scan lockfiles --lockfile /srv/../etc --token-file /t/token $sigflag --yes
expect 1 "accepts only letters" "--lockfile with a blank is refused" pipe_install --scan lockfiles --lockfile "/srv/my app" --token-file /t/token $sigflag --yes
expect 1 "unknown item docker2" "--scan with an unknown item is refused" pipe_install --scan os,docker2 --token-file /t/token $sigflag --yes

# Lockfiles only: no OS report.
before=$(reports)
expect 0 "lockfile report accepted (HTTP 200, 3 paths" "install --scan lockfiles: only the lockfile report is sent" \
	pipe_install --scan lockfiles --lockfile /srv/billing/current/ --lockfile /home/app/shop --lockfile /srv/closed --token-file /t/token $sigflag --yes
check "  ...no OS report" [ "$(reports)" = "$before" ]
grep -q 'lockfile report accepted: 3 paths, [0-9]* bytes scans="lockfiles"' /tmp/fakesmoke.log && ok "  ...with X-Smoke-Collector-Scans: lockfiles" || bad "  ...scans header: $(tail -3 /tmp/fakesmoke.log)"
grep -q "/srv/billing/current: created" /tmp/out && ok "  ...per-path results printed" || bad "  ...per-path results"
grep -qF "cannot read /home/app/shop" /tmp/out && grep -qF "setfacl -m u:smoke-collector:rX /home/app/shop" /tmp/out &&
	ok "  ...warns that smoke-collector cannot enter /home/app/shop, with a setfacl example" || bad "  ...unreadable directory warning"
grep -qF "setfacl -m u:smoke-collector:r /srv/closed/yarn.lock" /tmp/out && ok "  ...and that it cannot read /srv/closed/yarn.lock" || bad "  ...unreadable file warning"
check "  ...permissions not changed" sh -c '[ "$(stat -c %a /home/app)" = 700 ] && [ "$(stat -c %a /srv/closed/yarn.lock)" = 600 ]'
check "config: scan=lockfiles and the three paths (trailing / removed)" sh -c 'grep -qx "scan=lockfiles" /etc/smoke-collector/config &&
	[ "$(grep -c "^lockfile=" /etc/smoke-collector/config)" = 3 ] && grep -qx "lockfile=/srv/billing/current" /etc/smoke-collector/config &&
	grep -qx "lockfile=/home/app/shop" /etc/smoke-collector/config && grep -qx "lockfile=/srv/closed" /etc/smoke-collector/config'
check "the report: the symlinked release read, unreadable paths reported, .env not sent" sh -c '
	grep -qF "\"path\":\"/srv/billing/current\",\"status\":\"ok\",\"files\":[{\"name\":\"package-lock.json\"" /tmp/last-lockfiles.json &&
	grep -qF "\"path\":\"/home/app/shop\",\"status\":\"unreadable\"" /tmp/last-lockfiles.json &&
	grep -qF "\"path\":\"/srv/closed\",\"status\":\"unreadable\"" /tmp/last-lockfiles.json && ! grep -q never-sent /tmp/last-lockfiles.json'
check "terms record: version 2026-11-13.2, scans=lockfiles" sh -c 'grep -qx "terms_version=2026-11-13.2" /etc/smoke-collector/terms-accepted &&
	grep -qx "scans=lockfiles" /etc/smoke-collector/terms-accepted'
expect 0 "scan:          lockfiles (config file)" "print-config shows the scan" runas "/usr/local/bin/smoke-collector print-config --insecure-http"
grep -qx "lockfile:      /srv/billing/current" /tmp/out && ok "  ...and the lockfile paths" || bad "  ...lockfile paths"
expect 0 "#lockfile /srv/billing/current/package-lock.json (" "--dry-run as smoke-collector prints every lockfile in full" \
	runas "/usr/local/bin/smoke-collector run --dry-run"
grep -qF '{"lockfileVersion": 3, "packages": {}}' /tmp/out && grep -q "^/home/app/shop: unreadable" /tmp/out && ! grep -q "#smoke-host" /tmp/out &&
	ok "  ...contents, statuses, no OS report" || bad "  ...dry-run content"

# Upgrade without --scan: the scan list, the paths and the token are kept.
expect 0 "keeping what the existing installation scans: lockfiles" "upgrade without --scan keeps the scan" pipe_install $sigflag --no-run
grep -q "keeping the lockfile paths" /tmp/out && grep -q "already accepted on this host" /tmp/out && grep -q "keeping the token" /tmp/out &&
	ok "  ...and the paths, the terms and the token" || bad "  ...upgrade messages"
check "  ...config unchanged" sh -c 'grep -qx "scan=lockfiles" /etc/smoke-collector/config && [ "$(grep -c "^lockfile=" /etc/smoke-collector/config)" = 3 ]'

# os,lockfiles: os was not accepted for this host yet, so the terms are asked again.
expect 1 "terms must be accepted first" "adding os to the scan asks for the terms again" pipe_install --scan os,lockfiles $sigflag --no-run
before=$(reports)
expect 0 "lockfile report accepted" "install --scan os,lockfiles --yes: both reports" pipe_install --scan os,lockfiles $sigflag --yes
check "  ...one OS report" [ "$(reports)" = $((before + 1)) ]
check "  ...both with X-Smoke-Collector-Scans: os,lockfiles" sh -c 'tail -2 /tmp/fakesmoke.log | grep -c "scans=\"os,lockfiles\"" | grep -qx 2'
check "  ...config scan=os,lockfiles with the paths kept" sh -c 'grep -qx "scan=os,lockfiles" /etc/smoke-collector/config && [ "$(grep -c "^lockfile=" /etc/smoke-collector/config)" = 3 ]'
check "  ...terms record scans=os,lockfiles" grep -qx "scans=os,lockfiles" /etc/smoke-collector/terms-accepted

# --lockfile none.
expect 1 "no lockfile path is set" "--scan os,lockfiles --lockfile none without a terminal stops" \
	pipe_install --scan os,lockfiles --lockfile none $sigflag --no-run
expect 0 "" "--scan os --lockfile none" pipe_install --scan os --lockfile none $sigflag --no-run
check "  ...config scan=os without lockfile lines" sh -c 'grep -qx "scan=os" /etc/smoke-collector/config && ! grep -q "^lockfile=" /etc/smoke-collector/config'

# A terms record of the previous version (0.2.1) is asked again.
sed -i -e 's/^terms_version=.*/terms_version=2026-11-13/' -e '/^scans=/d' /etc/smoke-collector/terms-accepted
expect 1 "terms must be accepted first" "terms of an older version are asked again on upgrade" pipe_install $sigflag --no-run
expect 0 "accepted with --accept-terms" "  ...and accepted with --yes" pipe_install $sigflag --no-run --yes
check "  ...record updated" sh -c 'grep -qx "terms_version=2026-11-13.2" /etc/smoke-collector/terms-accepted && grep -qx "scans=os" /etc/smoke-collector/terms-accepted'
expect 0 "removed" "--uninstall" sh /repo/install.sh --uninstall

# The terms list only the chosen items.
expect 0 "Application lockfiles (smoke-collector)" "--show-terms --scan lockfiles" sh /tmp/install.sh --show-terms --scan lockfiles --lang en
grep -q ".env" /tmp/out && grep -q "within 24" /tmp/out && ! grep -q "installed packages" /tmp/out && ! grep -q "docker group" /tmp/out &&
	ok "  ...the lockfile section (.env not read, originals deleted within 24 h), no OS or Docker section" || bad "  ...lockfile terms sections"
expect 0 "24 小時內刪除" "--show-terms --scan lockfiles --lang zh-TW" sh /tmp/install.sh --show-terms --scan lockfiles --lang zh-TW
grep -q "\.env" /tmp/out && ! grep -q "docker 群組" /tmp/out && ok "  ...in Chinese, without Docker" || bad "  ...zh lockfile terms"
expect 0 "docker 群組" "--show-terms --scan os,docker --lang zh-TW" sh /tmp/install.sh --show-terms --scan os,docker --lang zh-TW
grep -q "OS 套件（smoke-collector）" /tmp/out && ! grep -q "應用程式 lockfile（" /tmp/out && grep -qF -- "--uninstall --containers" /tmp/out &&
	ok "  ...OS and Docker sections, no lockfile section, both uninstall commands" || bad "  ...os,docker terms"

# systemd drop-in, with a stand-in systemctl (no systemd runs in these containers): the real unit
# and drop-in files are written, systemctl calls are only logged.
mkdir -p /run/systemd/system /etc/systemd/system
printf '#!/bin/sh\necho "systemctl $*" >>/tmp/systemctl.log\n' >/usr/local/bin/systemctl
chmod 0755 /usr/local/bin/systemctl
dropin=/etc/systemd/system/smoke-collector.service.d/lockfiles.conf
expect 0 "wrote $dropin" "lockfiles under /home: the systemd drop-in is written" \
	pipe_install --scan lockfiles --lockfile /home/app/shop --lockfile /srv/billing/current --lockfile /srv/otherlink \
	--token-file /t/token $sigflag --yes --no-run
check "  ...ProtectHome=tmpfs and one BindReadOnlyPaths per path under /home (a symlink resolved), none for /srv" sh -c "
	grep -qx 'ProtectHome=tmpfs' $dropin && grep -qx 'BindReadOnlyPaths=-/home/app/shop' $dropin &&
	grep -qx 'BindReadOnlyPaths=-/home/app/other' $dropin && [ \$(grep -c '^BindReadOnlyPaths=' $dropin) = 2 ] &&
	grep -qx '\[Service\]' $dropin && [ \"\$(stat -c %a $dropin)\" = 644 ]"
check "  ...units installed, daemon-reload and timer enabled" sh -c 'grep -q "^ProtectHome=yes" /etc/systemd/system/smoke-collector.service &&
	grep -q "^systemctl daemon-reload" /tmp/systemctl.log && grep -q "^systemctl enable --now smoke-collector.timer" /tmp/systemctl.log'
expect 0 "removed $dropin" "no path under /home any more: the drop-in is removed" \
	pipe_install --scan lockfiles --lockfile /srv/billing/current $sigflag --no-run
check "  ...with its directory" sh -c '! [ -e /etc/systemd/system/smoke-collector.service.d ]'
expect 0 "wrote $dropin" "a path under /root" pipe_install --scan os,lockfiles --lockfile /root/app $sigflag --yes --no-run
check "  ...BindReadOnlyPaths=-/root/app" grep -qx "BindReadOnlyPaths=-/root/app" "$dropin"
expect 0 "removed" "--uninstall removes the drop-in" sh /repo/install.sh --uninstall
check "  ...units and drop-in gone" sh -c '! [ -e /etc/systemd/system/smoke-collector.service.d ] && ! [ -e /etc/systemd/system/smoke-collector.service ]'
rm -f /usr/local/bin/systemctl
rmdir /run/systemd/system

# Both programs in one run, two token files. A fourth fakesmoke checks each program's token; the
# container collector reads the fake Docker Engine on /var/run/docker.sock (fakesmoke 2), never a
# real Docker.
printf 'smk_container_test_%s\n' "$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')" >/tmp/ctoken
CTOKEN=$(cat /tmp/ctoken)
/t/fakesmoke -addr :8083 -dir /tmp/www -token-file /t/token -containers-token-file /tmp/ctoken \
	-save-lockfiles /tmp/last-lockfiles4.json >/tmp/fakesmoke4.log 2>&1 &
URL4=http://localhost:8083
i=0
until $fetch "$URL4/downloads/collector/LATEST" >/dev/null 2>&1; do
	i=$((i + 1)); [ $i -lt 50 ] || { echo "fakesmoke 4 did not start"; cat /tmp/fakesmoke4.log; exit 1; }
	sleep 0.1
done
pipe4() { $fetch "$URL/downloads/collector/install.sh" | sh -s -- --url "$URL4" --insecure-http "$@"; }
expect 1 "only for --containers" "--containers-token-file without docker is refused" \
	pipe4 --scan os --token-file /t/token --containers-token-file /tmp/ctoken $sigflag --yes
expect 0 "report accepted (HTTP 200, 1 images" "install --scan os,docker with two token files: both programs, both first runs" \
	pipe4 --scan os,docker --token-file /t/token --containers-token-file /tmp/ctoken $sigflag --yes
grep -q "report created" /tmp/out && ok "  ...the OS report with the OS token" || bad "  ...OS report"
grep -q "downloading smoke-collector smoke-container-collector" /tmp/out && ok "  ...one download step for both" || bad "  ...download"
if [ -z "$sigflag" ]; then
	check "  ...SHA256SUMS verified once" [ "$(grep -c "signature of SHA256SUMS verified" /tmp/out)" = 1 ]
fi
check "  ...each configuration has its own token" sh -c "grep -qx 'token=$TOKEN' /etc/smoke-collector/config && grep -qx 'token=$CTOKEN' /etc/smoke-collector/containers.config"
check "  ...two terms records: scans=os and scans=docker" sh -c 'grep -qx "scans=os" /etc/smoke-collector/terms-accepted &&
	grep -qx "scans=docker" /etc/smoke-collector/containers.terms-accepted &&
	grep -qx "terms_version=2026-11-13.2" /etc/smoke-collector/containers.terms-accepted'
check "  ...shared dir 0751, smoke-container in the docker group" sh -c '[ "$(stat -c %a /etc/smoke-collector)" = 751 ] &&
	id -nG smoke-container | tr " " "\n" | grep -qx docker && ! id -nG smoke-collector | tr " " "\n" | grep -qx docker'
grep -q "container report accepted: 1 images" /tmp/fakesmoke4.log && grep -q 'report created: .* scans="os"' /tmp/fakesmoke4.log &&
	ok "fakesmoke 4: OS report (scans os) and container report, each with its token" || bad "fakesmoke 4 log: $(cat /tmp/fakesmoke4.log)"
check "the fake Docker Engine was asked for nothing outside the allowlist" sh -c '! grep -q "docker: refused" /tmp/fakesmoke2.log'
cp /etc/smoke-collector/containers.config /tmp/containers.config.before
expect 0 "lockfile report accepted" "--scan lockfiles leaves the container collector alone" pipe4 --scan lockfiles --lockfile /srv/billing/current $sigflag --yes
check "  ...containers.config unchanged and no container run" sh -c 'cmp -s /tmp/containers.config.before /etc/smoke-collector/containers.config &&
	! grep -q smoke-container-collector /tmp/out && grep -qx "scan=lockfiles" /etc/smoke-collector/config'
expect 0 "report accepted (HTTP 200, 1 images" "--scan docker leaves smoke-collector alone" pipe4 --scan docker $sigflag --yes
check "  ...smoke-collector not reinstalled or run" sh -c '! grep -q "installed /usr/local/bin/smoke-collector " /tmp/out && ! grep -q "running smoke-collector " /tmp/out &&
	grep -qx "scan=lockfiles" /etc/smoke-collector/config'
expect 0 "keeping what the existing installation scans: lockfiles,docker" "upgrade without --scan upgrades both programs" pipe4 $sigflag --no-run
grep -q "installed /usr/local/bin/smoke-collector " /tmp/out && grep -q "installed /usr/local/bin/smoke-container-collector " /tmp/out &&
	ok "  ...both binaries installed" || bad "  ...both binaries"
expect 0 "removed" "--uninstall --scan lockfiles,docker removes both" sh /repo/install.sh --uninstall --scan lockfiles,docker
check "  ...everything gone" sh -c '! [ -e /etc/smoke-collector ] && ! [ -e /usr/local/bin/smoke-collector ] &&
	! [ -e /usr/local/bin/smoke-container-collector ] && ! id smoke-collector >/dev/null 2>&1 && ! id smoke-container >/dev/null 2>&1'

# At a terminal: the items are asked one by one, then the lockfile paths, the terms (one y) and
# the two tokens, each prompt naming its program.
if command -v script >/dev/null; then
	cmd="sh /tmp/install.sh --url $URL4 --insecure-http $sigflag --no-service --no-run --lang en"
	(sleep 2; printf '\n'; sleep 1; printf 'y\n'; sleep 1; printf 'y\n'; sleep 1; printf '/srv/billing/current /home/app/shop\n'; sleep 2
		printf 'y\n'; sleep 3; printf '%s\n' "$TOKEN"; sleep 2; printf '%s\n' "$CTOKEN"; sleep 1) |
		script -q -c "$cmd" /dev/null >/tmp/out 2>&1
	cat /tmp/out >>/tmp/all-output
	if grep -q "Scan OS packages (smoke-collector)? \[Y/n\]" /tmp/out && grep -q "Scan Docker containers" /tmp/out &&
		grep -q "Lockfile paths for smoke-collector" /tmp/out && grep -q "Scanning: OS packages, application lockfiles, Docker containers" /tmp/out &&
		grep -q "Asset token for smoke-collector (OS packages and lockfiles) (smk_..., input hidden)" /tmp/out &&
		grep -q "Container collector token for smoke-container-collector (Docker) (smk_..., input hidden)" /tmp/out &&
		[ "$(grep -c "Type y to accept" /tmp/out)" = 1 ]; then
		ok "terminal: items asked one by one, paths asked, one terms prompt, token prompts name their program"
	else
		bad "terminal prompts"
	fi
	check "  ...config scan=os,lockfiles with both paths, both tokens stored and not echoed" sh -c "grep -qx 'scan=os,lockfiles' /etc/smoke-collector/config &&
		grep -qx 'lockfile=/home/app/shop' /etc/smoke-collector/config && grep -qx 'token=$TOKEN' /etc/smoke-collector/config &&
		grep -qx 'token=$CTOKEN' /etc/smoke-collector/containers.config && ! grep -qF -- '$TOKEN' /tmp/out && ! grep -qF -- '$CTOKEN' /tmp/out"
	check "  ...both records accepted at the prompt" sh -c 'grep -qx "accepted_with=prompt" /etc/smoke-collector/terms-accepted &&
		grep -qx "accepted_with=prompt" /etc/smoke-collector/containers.terms-accepted'
	sh /repo/install.sh --uninstall --scan os,docker >/dev/null 2>&1
else
	echo "SKIP  no script(1) for the terminal prompt tests"
fi
cat /tmp/fakesmoke4.log >>/tmp/all-output
if grep -qF -- "$CTOKEN" /tmp/all-output; then echo "token printed" >/tmp/out; bad "the container token never appears in any output"; else ok "the container token never appears in any output"; fi

cat /tmp/fakesmoke2.log >>/tmp/all-output
if grep -qF -- "$TOKEN" /tmp/all-output; then echo "token printed" >/tmp/out; bad "the token never appears in any output (containers)"; else ok "the token never appears in any output (containers)"; fi

echo "RESULT $pass passed, $fail failed"
[ "$fail" = 0 ]
