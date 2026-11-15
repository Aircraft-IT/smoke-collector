#!/bin/sh
# smoke-collector installer (OS detection plan §5.4 and §4b). POSIX sh; Ubuntu, Debian, Alpine, RHEL,
# Rocky Linux and AlmaLinux.
#
#   curl -fsSL https://<smoke>/downloads/collector/install.sh | sudo sh -s -- --url https://<smoke> \
#     [--scan os,lockfiles,docker] [--lockfile /srv/app/current]...
#
# What to scan (--scan, any non-empty comma-separated subset):
#   os         OS packages, by smoke-collector: /usr/local/bin/smoke-collector, run daily by a
#              systemd timer (cron without systemd) as the unprivileged smoke-collector user,
#              configured in /etc/smoke-collector/config with the host's asset token.
#   lockfiles  the application lockfiles at the --lockfile paths, also by smoke-collector (the
#              scan= and lockfile= lines of its configuration; same token).
#   docker     the running Docker containers, by smoke-container-collector (spec FR-COL-08):
#              /usr/local/bin/smoke-container-collector, run daily as smoke-container, which is
#              added to the docker group (equivalent to root), configured in
#              /etc/smoke-collector/containers.config with its own token.
# One run installs both programs when docker and os or lockfiles are chosen. Without --scan, an
# existing installation keeps its choice (the run upgrades what is installed); a new installation
# asks at the terminal (os yes, the others no), or scans os when there is no terminal. --scan never
# removes the other program; with os or lockfiles in it, it replaces smoke-collector's scan list
# (for example --scan lockfiles turns OS package scanning off).
#
# For each program it downloads the binary from <url>/downloads/collector/, verifies the minisign
# signature of SHA256SUMS (once) with openssl (legacy minisign signatures are plain Ed25519) and the
# binary's SHA-256, reads the token from the terminal (never from the command line; smoke-collector's
# first, then the container collector's), creates the user, installs the binary and configuration,
# schedules the daily run and runs it once.
#
# Before anything is downloaded or changed, the installation terms for the chosen items (what is
# installed, what is collected and sent, your responsibilities, the disclaimer) are shown and must
# be accepted by typing y once. Each program records the acceptance, with the version and the items
# (scans=), in /etc/smoke-collector/terms-accepted or containers.terms-accepted; a later run asks
# again only when the terms change or an item is chosen that was not accepted before.
#
# Options:
#   --url URL            Smoke address (https://). Required unless --uninstall.
#   --scan LIST          what to scan: os, lockfiles, docker (comma-separated).
#   --lockfile PATH      with lockfiles: an absolute directory (only the supported lockfile names
#                        directly inside it are read) or lockfile. Repeatable, at most 20; letters,
#                        digits and . _ - / @ + only. The paths given replace the configured ones;
#                        --lockfile none clears them. Without it, an upgrade keeps them. Paths
#                        under /home, /root or /run/user get a systemd drop-in that makes them
#                        readable (read-only) despite ProtectHome. Permissions are only checked.
#   --token-file FILE    read smoke-collector's token from FILE instead of the terminal
#                        (non-interactive; when only docker is chosen: the container collector's).
#                        Without it, an existing installation keeps its token.
#   --containers-token-file FILE
#                        read the container collector's token from FILE.
#   --replace-token      replace the token of each program this run installs that already has
#                        one: ask for the new token at the terminal (or read it from the token
#                        file). Smoke revokes the old token after the new one's first report.
#                        (0.3.1+)
#   --containers         the same as --scan docker (with --uninstall: the container collector).
#   --version VERSION    install VERSION instead of the one in LATEST.
#   --skip-signature     do not verify the signature (not recommended; SHA-256 is still checked).
#   --no-service         do not install the systemd timers or cron entries.
#   --no-run             do not run the collectors at the end.
#   --insecure-http      allow an http:// URL for localhost (testing only).
#   --show-terms         print the installation terms for --scan (default os) and exit (no root
#                        needed).
#   --accept-terms       accept the installation terms without being asked (non-interactive
#                        installs; read them first with --show-terms). --yes is the same.
#   --lang zh-TW|en      language of the terms (default: from LANG, otherwise English).
#   --docker-host unix:///PATH
#                        with docker: read Docker through this socket (for example a filtering
#                        proxy that allows only the collector's four GET paths) instead of
#                        /var/run/docker.sock. The user is then NOT added to the docker group:
#                        give it access to that socket yourself (for example its group).
#   --uninstall          remove smoke-collector (with --containers or --scan docker: the container
#                        collector; --scan os,docker: both): the program, its configuration, terms
#                        record, timer or cron entry, systemd drop-in and user.
#   --verify-signature FILE SIGFILE
#                        only verify FILE against the minisign signature SIGFILE with the embedded
#                        public key, then exit (no root needed).
#
# Exit code: 0 when everything was installed and every first run succeeded; 1 when install.sh
# stops (nothing of that step installed); otherwise the code of the first failing first run
# (smoke-collector first): 1 configuration, 2 collection, 3 rejected by Smoke, 4 network or server.
set -eu
umask 022
# The caller's locale, before it is replaced: it picks the language of the terms.
ORIG_LOCALE=${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}
LC_ALL=C
export LC_ALL

# minisign public key (the base64 line of smoke-collector.pub), written by scripts/release.sh.
PUBKEY="__SMOKE_COLLECTOR_PUBKEY__"
PLACEHOLDER="__SMOKE_COLLECTOR""_PUBKEY__"

CONF_DIR=/etc/smoke-collector
OS_CONF=$CONF_DIR/config
CONTAINERS_CONF=$CONF_DIR/containers.config
UNIT_DIR=/etc/systemd/system
DROPIN_DIR=$UNIT_DIR/smoke-collector.service.d
DROPIN=$DROPIN_DIR/lockfiles.conf
DEFAULT_DOCKER_HOST=unix:///var/run/docker.sock
MAX_LOCKFILES=20

URL=""
TOKEN_FILE=""
C_TOKEN_FILE=""
REPLACE_TOKEN=0
VERSION=""
SKIP_SIGNATURE=0
NO_SERVICE=0
NO_RUN=0
INSECURE_HTTP=0
UNINSTALL=0
OPT_CONTAINERS=0
SCAN_OPT=""
LOCKFILES=""
LOCKFILE_COUNT=0
LOCKFILE_GIVEN=0
ACCEPT_TERMS=0
SHOW_TERMS=0
LANG_OPT=""
DOCKER_HOST_OPT=""
VERIFY_FILE=""
VERIFY_SIG=""
WORK=""
STTY_SAVED=""

say() { printf '%s\n' "smoke-collector install: $*"; }
warn() { printf '%s\n' "smoke-collector install: warning: $*" >&2; }
die() {
	printf '%s\n' "smoke-collector install: error: $*" >&2
	exit 1
}

# shellcheck disable=SC2317,SC2329 # called from the EXIT trap
cleanup() {
	if [ -n "$STTY_SAVED" ]; then
		stty "$STTY_SAVED" </dev/tty 2>/dev/null || true
	fi
	if [ -n "$WORK" ]; then
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
	if [ -f "$0" ]; then
		sed -n '2,/^set -eu/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
	else
		echo "Options: --url URL [--scan os,lockfiles,docker] [--lockfile PATH|none]... [--token-file FILE]"
		echo "         [--containers-token-file FILE] [--replace-token] [--version VERSION] [--skip-signature]"
		echo "         [--no-service]"
		echo "         [--no-run] [--insecure-http] [--accept-terms] [--lang zh-TW|en]"
		echo "         [--containers] [--docker-host unix:///PATH]"
		echo "         | --show-terms [--scan LIST] [--lang zh-TW|en]"
		echo "         | --uninstall [--containers | --scan LIST]"
		echo "         | --verify-signature FILE SIGFILE"
	fi
}

need_value() {
	if [ $# -lt 2 ] || [ -z "$2" ]; then die "$1 needs a value"; fi
}

# check_lockfile PATH: 0 when PATH is a lockfile path install.sh accepts, with the trailing / removed
# in LF_PATH; otherwise 1 with the reason in LF_ERR. The allowed characters contain no blank and no
# glob or shell character, so LOCKFILES can be a space-separated list.
check_lockfile() {
	LF_PATH=$1 LF_ERR=""
	case $LF_PATH in
	/*) ;;
	*) LF_ERR="must be an absolute path"; return 1 ;;
	esac
	while [ "$LF_PATH" != / ] && [ "${LF_PATH%/}" != "$LF_PATH" ]; do LF_PATH=${LF_PATH%/}; done
	case $LF_PATH in
	*[!A-Za-z0-9._/@+-]*)
		LF_ERR="install.sh accepts only letters, digits and . _ - / @ + in lockfile paths (for other characters, edit $OS_CONF yourself)"
		return 1 ;;
	*//* | */./* | */../* | */. | */..) LF_ERR="must be a clean path (no //, . or ..)"; return 1 ;;
	esac
	if [ "${#LF_PATH}" -gt 512 ]; then LF_ERR="is longer than 512 characters"; return 1; fi
	return 0
}

# add_lockfile PATH WHAT: checks PATH (dies with WHAT in the message) and adds it to LOCKFILES once.
add_lockfile() {
	check_lockfile "$1" || die "$2 $1: $LF_ERR"
	case " $LOCKFILES " in *" $LF_PATH "*) return 0 ;; esac
	LOCKFILE_COUNT=$((LOCKFILE_COUNT + 1))
	[ "$LOCKFILE_COUNT" -le "$MAX_LOCKFILES" ] || die "at most $MAX_LOCKFILES lockfile paths"
	LOCKFILES="${LOCKFILES:+$LOCKFILES }$LF_PATH"
}

lockfile_opt() {
	LOCKFILE_GIVEN=1
	if [ "$1" = none ]; then
		LOCKFILES="" LOCKFILE_COUNT=0
	else
		add_lockfile "$1" --lockfile
	fi
}

while [ $# -gt 0 ]; do
	case $1 in
	--url) need_value "$@"; URL=$2; shift 2 ;;
	--url=*) URL=${1#*=}; shift ;;
	--scan) need_value "$@"; SCAN_OPT="${SCAN_OPT:+$SCAN_OPT,}$2"; shift 2 ;;
	--scan=*) SCAN_OPT="${SCAN_OPT:+$SCAN_OPT,}${1#*=}"; [ -n "${1#*=}" ] || SCAN_OPT="$SCAN_OPT,"; shift ;;
	--lockfile) need_value "$@"; lockfile_opt "$2"; shift 2 ;;
	--lockfile=*) lockfile_opt "${1#*=}"; shift ;;
	--token-file) need_value "$@"; TOKEN_FILE=$2; shift 2 ;;
	--token-file=*) TOKEN_FILE=${1#*=}; shift ;;
	--containers-token-file) need_value "$@"; C_TOKEN_FILE=$2; shift 2 ;;
	--containers-token-file=*) C_TOKEN_FILE=${1#*=}; shift ;;
	--replace-token) REPLACE_TOKEN=1; shift ;;
	--version) need_value "$@"; VERSION=$2; shift 2 ;;
	--version=*) VERSION=${1#*=}; shift ;;
	--skip-signature) SKIP_SIGNATURE=1; shift ;;
	--no-service) NO_SERVICE=1; shift ;;
	--no-run) NO_RUN=1; shift ;;
	--insecure-http) INSECURE_HTTP=1; shift ;;
	--uninstall) UNINSTALL=1; shift ;;
	--containers) OPT_CONTAINERS=1; shift ;;
	--accept-terms | --yes) ACCEPT_TERMS=1; shift ;;
	--show-terms) SHOW_TERMS=1; shift ;;
	--lang) need_value "$@"; LANG_OPT=$2; shift 2 ;;
	--lang=*) LANG_OPT=${1#*=}; shift ;;
	--docker-host) need_value "$@"; DOCKER_HOST_OPT=$2; shift 2 ;;
	--docker-host=*) DOCKER_HOST_OPT=${1#*=}; shift ;;
	--verify-signature)
		[ $# -ge 3 ] || die "--verify-signature needs FILE and SIGFILE"
		VERIFY_FILE=$2; VERIFY_SIG=$3; shift 3 ;;
	--token | --token=*)
		die "the token is never given on the command line (it would end up in the shell history and process list); you will be asked for it, or use --token-file" ;;
	-h | --help) usage; exit 0 ;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
done

if [ -n "$DOCKER_HOST_OPT" ]; then
	case $DOCKER_HOST_OPT in
	unix:///?*) ;;
	*) die "--docker-host must look like unix:///run/smoke-docker.sock (only unix sockets)" ;;
	esac
	case ${DOCKER_HOST_OPT#unix://} in
	*[!A-Za-z0-9._/-]* | *..* | *//*) die "--docker-host must be unix:// followed by a clean absolute path (letters, digits, . _ - /)" ;;
	esac
fi

# --- what to scan -------------------------------------------------------------------------------

# --containers is --scan docker.
if [ "$OPT_CONTAINERS" = 1 ]; then SCAN_OPT="${SCAN_OPT:+$SCAN_OPT,}docker"; fi
SCAN_GIVEN=0
if [ -n "$SCAN_OPT" ]; then SCAN_GIVEN=1; fi
SEL_OS=0
SEL_LOCK=0
SEL_DOCKER=0

# parse_scan LIST WHAT: adds the items of LIST to SEL_*.
parse_scan() {
	list=$(printf '%s' "$1" | tr -d ' \t')
	case $list in
	'' | ,* | *, | *,,*) die "$2 needs a comma-separated list of os, lockfiles, docker" ;;
	esac
	old_ifs=$IFS
	IFS=,
	set -f
	for item in $list; do
		case $item in
		os) SEL_OS=1 ;;
		lockfiles) SEL_LOCK=1 ;;
		docker) SEL_DOCKER=1 ;;
		*) IFS=$old_ifs; set +f; die "$2: unknown item $item (known: os, lockfiles, docker)" ;;
		esac
	done
	set +f
	IFS=$old_ifs
}

# set_programs: DO_OS (smoke-collector) and DO_C (smoke-container-collector) from SEL_*, and
# OS_SCAN, smoke-collector's scan= value.
set_programs() {
	DO_OS=0 DO_C=$SEL_DOCKER OS_SCAN=""
	if [ "$SEL_OS" = 1 ]; then OS_SCAN=os; fi
	if [ "$SEL_LOCK" = 1 ]; then OS_SCAN="${OS_SCAN:+$OS_SCAN,}lockfiles"; fi
	if [ -n "$OS_SCAN" ]; then DO_OS=1; fi
}

# scan_list: the chosen items, comma-separated.
scan_list() {
	s=""
	if [ "$SEL_OS" = 1 ]; then s=os; fi
	if [ "$SEL_LOCK" = 1 ]; then s="${s:+$s,}lockfiles"; fi
	if [ "$SEL_DOCKER" = 1 ]; then s="${s:+$s,}docker"; fi
	printf '%s' "$s"
}

has_tty() { (: </dev/tty) 2>/dev/null; }

# conf_value KEY FILE: the first value of KEY in FILE, blanks and quotes removed.
conf_value() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$2" | sed -n 1p | tr -d " \t\r\"'"; }

# ask QUESTION y|n: 0 for yes; the second argument is the answer to an empty line.
ask() {
	if [ "$2" = y ]; then hint='[Y/n]'; else hint='[y/N]'; fi
	printf '%s %s ' "$1" "$hint" >/dev/tty
	IFS= read -r answer </dev/tty || answer=""
	case $answer in
	y | Y | yes | YES | Yes) return 0 ;;
	n | N | no | NO | No) return 1 ;;
	'') [ "$2" = y ] ;;
	*) ask "$1" "$2" ;;
	esac
}

# --- signature (minisign legacy = Ed25519 over the file) -------------------------------------

# file_size FILE
file_size() { wc -c <"$1" | tr -d ' '; }

# hex FILE SKIP COUNT: COUNT bytes of FILE from offset SKIP, as hex.
hex() { dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null | od -An -v -tx1 | tr -d ' \n'; }

check_openssl() {
	command -v openssl >/dev/null 2>&1 ||
		die "openssl is needed to verify the signature (Alpine: apk add openssl; Debian/Ubuntu: apt-get install openssl; RHEL/Rocky/AlmaLinux: dnf install openssl), or pass --skip-signature"
	major=$(openssl version 2>/dev/null | awk '{ split($2, v, "."); print v[1] }')
	case $major in
	'' | *[!0-9]*) die "cannot tell the openssl version; OpenSSL 3 is needed, or pass --skip-signature" ;;
	esac
	[ "$major" -ge 3 ] || die "OpenSSL 3 is needed to verify the signature (found $(openssl version)), or pass --skip-signature"
}

# verify_signature FILE SIGFILE DIR: exits unless SIGFILE is a valid legacy minisign signature of
# FILE by PUBKEY. The trusted comment (lines 3-4) is not checked; only the file signature is.
verify_signature() {
	file=$1 sigfile=$2 dir=$3
	printf '%s' "$PUBKEY" | openssl base64 -d -A >"$dir/pk.bin" 2>/dev/null || true
	[ "$(file_size "$dir/pk.bin")" = 42 ] || die "the embedded public key is not a minisign Ed25519 key"
	[ "$(hex "$dir/pk.bin" 0 2)" = 4564 ] || die "the embedded public key is not a minisign Ed25519 key"
	sed -n 2p "$sigfile" | tr -d '\r\n' | openssl base64 -d -A >"$dir/sig.bin" 2>/dev/null || true
	[ "$(file_size "$dir/sig.bin")" = 74 ] || die "$(basename "$sigfile") is not a minisign signature"
	case $(hex "$dir/sig.bin" 0 2) in
	4564) ;; # "Ed": legacy, a signature over the file itself
	4544) die "$(basename "$sigfile") is a prehashed minisign signature; it must be made with minisign -S -l" ;;
	*) die "$(basename "$sigfile") is not an Ed25519 minisign signature" ;;
	esac
	[ "$(hex "$dir/sig.bin" 2 8)" = "$(hex "$dir/pk.bin" 2 8)" ] ||
		die "$(basename "$sigfile") was made with a different key than the one in this script"
	dd if="$dir/sig.bin" of="$dir/sig.raw" bs=1 skip=10 count=64 2>/dev/null
	# Ed25519 SubjectPublicKeyInfo: 302a300506032b6570032100 followed by the 32-byte key.
	printf '\060\052\060\005\006\003\053\145\160\003\041\000' >"$dir/pk.der"
	dd if="$dir/pk.bin" bs=1 skip=10 count=32 2>/dev/null >>"$dir/pk.der"
	openssl pkeyutl -verify -pubin -inkey "$dir/pk.der" -keyform DER -rawin \
		-in "$file" -sigfile "$dir/sig.raw" >/dev/null 2>&1 ||
		die "SIGNATURE CHECK FAILED for $(basename "$file"); do not install"
}

new_workdir() {
	WORK=$(mktemp -d 2>/dev/null || mktemp -d -t smoke-collector)
	chmod 700 "$WORK"
}

# --- installation terms -------------------------------------------------------------------------

# The version of the terms below. Change it whenever their text changes in substance: hosts that
# accepted an older version are asked again on their next install or upgrade.
TERMS_VERSION=2026-11-15.1

case ${LANG_OPT:-} in
'' | zh-TW | zh_TW | zh | en) ;;
*) die "--lang must be zh-TW or en" ;;
esac
TERMS_LANG=en
case ${LANG_OPT:-$ORIG_LOCALE} in
zh*) TERMS_LANG=zh-TW ;;
esac

terms_uninstall_cmds() {
	c="curl -fsSL ${URL:-https://<Smoke>}/downloads/collector/install.sh | sudo sh -s -- --uninstall"
	if [ "$DO_OS" = 1 ]; then printf '    %s\n' "$c"; fi
	if [ "$DO_C" = 1 ]; then printf '    %s\n' "$c --containers"; fi
}

# terms_docker_group: 0 when the container collector reads Docker through the docker group.
terms_docker_group() {
	case $DOCKER_HOST_OPT in
	'' | "$DEFAULT_DOCKER_HOST") return 0 ;;
	esac
	return 1
}

# terms_section ZH EN: the next numbered section heading.
TERMS_N=0
terms_section() {
	TERMS_N=$((TERMS_N + 1))
	if [ "$TERMS_LANG" = zh-TW ]; then
		case $TERMS_N in
		1) n=一 ;; 2) n=二 ;; 3) n=三 ;; 4) n=四 ;; 5) n=五 ;; 6) n=六 ;; 7) n=七 ;; *) n=八 ;;
		esac
		printf '\n%s、%s\n' "$n" "$1"
	else
		printf '\n%s. %s\n' "$TERMS_N" "$2"
	fi
}

terms_zh() {
	items=""
	if [ "$SEL_OS" = 1 ]; then items="OS 套件"; fi
	if [ "$SEL_LOCK" = 1 ]; then items="${items:+$items、}應用程式 lockfile"; fi
	if [ "$SEL_DOCKER" = 1 ]; then items="${items:+$items、}Docker 容器"; fi
	cat <<EOF
================================================================================
 Smoke 收集程式安裝與使用條款　版本 $TERMS_VERSION
 掃描項目：$items
================================================================================
安裝前請完整閱讀以下條款。輸入 y 表示您已閱讀、理解並同意全部條款；
輸入其他內容會取消安裝，這台主機不會有任何變更。
EOF
	terms_section "安裝後主機上的變更與權限"
	if [ "$DO_OS" = 1 ]; then
		cat <<EOF
  Linux 收集程式（smoke-collector）：
  1. 建立不能登入的系統帳號 smoke-collector。
  2. 安裝程式 /usr/local/bin/smoke-collector，以及設定檔
     /etc/smoke-collector/config（內含資產權杖，只有 root 和該帳號能讀）。
  3. 安裝每天執行一次的 systemd timer；沒有 systemd 時改用 cron。
  4. 程式以一般使用者權限執行，不常駐、不開任何連接埠、不會自動更新，
     也不會安裝、移除或修改系統套件與設定。
EOF
		if [ "$SEL_LOCK" = 1 ]; then
			cat <<EOF
  5. lockfile 路徑在 /home、/root 或 /run/user 底下時，加上 systemd 設定
     /etc/systemd/system/smoke-collector.service.d/lockfiles.conf，只把這些
     路徑以唯讀方式開放給程式。安裝程式只檢查讀取權限，不會變更任何檔案的
     權限。
EOF
		fi
	fi
	if [ "$DO_C" = 1 ]; then
		cat <<EOF
  容器收集程式（smoke-container-collector）：
  1. 建立不能登入的系統帳號 smoke-container。
EOF
		if terms_docker_group; then
			cat <<EOF
  2. 把 smoke-container 加入 docker 群組。【重要】能存取 Docker 就等同擁有
     這台主機的 root 權限：任何能以這個帳號執行程式的人，都能完全控制這台
     主機。若不能接受，請取消安裝，改用只開放唯讀路徑的 Docker API proxy，
     並以 --docker-host 指定它的 socket（見使用手冊）。
EOF
		else
			cat <<EOF
  2. 不加入 docker 群組，改透過 $DOCKER_HOST_OPT 讀取 Docker。請自行讓
     smoke-container 能存取這個 socket；這個 socket 允許的所有操作，這個帳號
     都能執行，請確認它只開放收集程式需要的唯讀路徑。
EOF
		fi
		cat <<EOF
  3. 安裝程式 /usr/local/bin/smoke-container-collector，以及設定檔
     /etc/smoke-collector/containers.config（內含權杖，只有 root 和該帳號能讀）。
  4. 安裝每天執行一次的 systemd timer；沒有 systemd 時改用 cron。
EOF
		if [ "$DO_OS" = 1 ]; then
			echo "  5. 程式不常駐、不開任何連接埠、不會自動更新。"
		else
			echo "  5. 程式不常駐、不開任何連接埠、不會自動更新。Linux 收集程式不受影響。"
		fi
		terms_section "對 Docker 做的事"
		cat <<EOF
  1. 只送出 GET 請求，而且只限四個路徑：Docker 版本、執行中的容器清單、
     映像檔資訊、從容器複製檔案。程式內建限制，其他請求一律不會送出。
  2. 不會在容器內執行指令，不會下載、刪除或建立映像檔，也不會啟動、停止
     或修改容器。
  3. 每個映像檔只從其中一個執行中的容器複製 /etc/os-release 和套件資料庫
     （dpkg 的 status、apk 的 installed）。
EOF
	fi
	terms_section "收集與傳送的資料"
	echo "  每天一次，透過 HTTPS 傳送到安裝時指定的 Smoke 網址，不會送到其他地方。"
	if [ "$SEL_OS" = 1 ]; then
		cat <<EOF
  OS 套件（smoke-collector）：
  1. 作業系統識別（/etc/os-release 的 ID、VERSION_ID、VERSION_CODENAME）
     與核心版本；
  2. 已安裝套件的名稱、版本、架構與來源套件；
  3. 執行中的 systemd 服務名稱，以及每個服務使用到的套件名稱；
  4. 是否需要重新開機。
  為判斷服務使用的套件，程式會讀取服務的行程資訊（/proc）以及程式與函式庫
  的 ELF 標頭，但只傳送套件名稱。OS 套件掃描不會傳送檔案內容、命令列參數、
  環境變數、密碼、金鑰、帳號資料、日誌或網路流量。
EOF
	fi
	if [ "$SEL_LOCK" = 1 ]; then
		cat <<EOF
  應用程式 lockfile（smoke-collector）：
  1. 設定的路徑字串，以及這些路徑下支援檔名的 lockfile 全文（例如
     package-lock.json、yarn.lock、pnpm-lock.yaml、composer.lock、
     poetry.lock、uv.lock、Pipfile.lock、requirements*.txt、go.mod、
     Cargo.lock、gradle.lockfile、packages.lock.json、pubspec.lock）；
  2. 路徑是目錄時只讀這一層的上述檔名。不讀目錄中的其他檔案（例如 .env、
     原始碼、node_modules），也不往下層目錄找；
  3. lockfile 裡 URL 夾帶的帳號密碼（例如私有套件庫的權杖）由 Smoke 去掉，
     原始檔案在 24 小時內刪除；
  4. 路徑字串會保存，用來對應 Smoke 上的資產，只有看得到該專案的成員看得到。
  讀取權限就是 smoke-collector 帳號的權限。
EOF
		if [ -n "$LOCKFILES" ]; then
			echo "  這次設定的路徑："
			for p in $LOCKFILES; do echo "    $p"; done
		fi
	fi
	if [ "$DO_C" = 1 ]; then
		cat <<EOF
  Docker 容器（smoke-container-collector）：
  1. 每個執行中映像檔的名稱與標籤、映像檔 ID、digest、使用它的容器數量；
  2. 映像檔的作業系統識別與已安裝套件清單（名稱、版本、架構、來源套件）；
  3. 映像檔的四個標準出處標籤（org.opencontainers.image 的 source、title、
     version、base.name），讓 Smoke 判斷它是從哪個公開映像檔建的。
  不會傳送其他標籤（labels）、容器名稱、環境變數、掛載、網路設定、日誌或
  其他檔案內容。
EOF
	fi
	echo "  每次也會傳送收集程式的版本、CPU 架構和掃描項目。"
	echo "  Smoke 的伺服器紀錄會包含連線的來源 IP 位址與時間。"
	echo "  實際傳送的內容可以隨時查看："
	if [ "$DO_OS" = 1 ]; then echo "    sudo smoke-collector run --dry-run"; fi
	if [ "$DO_C" = 1 ]; then echo "    sudo -u smoke-container /usr/local/bin/smoke-container-collector run --dry-run"; fi
	terms_section "資料的用途"
	cat <<EOF
  1. 資料存放在您的 Smoke 工作區，用來比對安全公告、產生弱點清單與修補
     建議，並依您與 Smoke 服務提供者之間的服務條款及隱私權政策處理。
EOF
	n=2
	if [ "$SEL_LOCK" = 1 ]; then
		cat <<EOF
  $n. lockfile 只會寫入工作區管理員在 Smoke 連結到這台主機的資產；沒有連結
     的路徑只列在主機頁上，由管理員處理。
EOF
		n=3
	fi
	if [ "$DO_C" = 1 ]; then
		cat <<EOF
  $n. Smoke 可能依映像檔名稱自動建立「容器映像檔」資產，計入方案的資產數量；
     超過方案上限時不會建立，並通知工作區管理員。
EOF
	fi
	terms_section "您的責任"
	cat <<EOF
  1. 您確認自己有權在這台主機上安裝並執行本程式，且安裝符合貴組織的資訊
     安全政策、契約義務與相關法令。
EOF
	n=2
	if [ "$SEL_LOCK" = 1 ]; then echo "  $n. 您確認自己有權讀取上述 lockfile 並傳送到 Smoke。"; n=$((n + 1)); fi
	if [ "$DO_C" = 1 ]; then echo "  $n. 您確認自己有權授與上述 Docker 權限。"; n=$((n + 1)); fi
	cat <<EOF
  $n. 權杖是這台主機上傳資料的憑證，請妥善保管；懷疑外洩時請立即到 Smoke
     撤銷並換發。
  $((n + 1)). 請自行評估安裝對系統的影響；正式環境安裝前，建議先在測試環境確認。
EOF
	terms_section "免責聲明"
	cat <<EOF
  1. 本程式及其產生的結果依「現況」及「現有」提供，不保證沒有錯誤或中斷，
     也不保證適合任何特定用途。
  2. 弱點比對依賴第三方發布的安全公告與套件資訊，結果可能有遺漏、延遲或
     誤判，不能取代您自己的安全評估、修補決策與備份。
EOF
	if [ "$DO_C" = 1 ]; then
		cat <<EOF
  3. 授與 Docker 權限的風險由您自行評估與承擔。在法律允許的最大範圍內，
     Smoke 服務提供者對於因安裝、使用或無法使用本程式，或依其結果所做的任何
     決定，所造成的直接、間接、附帶、衍生或特別損害（包括但不限於系統中斷、
     資料遺失、安全事件、營業或利潤損失），均不負賠償責任。
EOF
	else
		cat <<EOF
  3. 在法律允許的最大範圍內，Smoke 服務提供者對於因安裝、使用或無法使用
     本程式，或依其結果所做的任何決定，所造成的直接、間接、附帶、衍生或
     特別損害（包括但不限於系統中斷、資料遺失、營業或利潤損失），均不負
     賠償責任。
EOF
	fi
	echo "  4. 法律強制規定不得排除的責任，不受本條影響。"
	terms_section "移除"
	if [ "$DO_C" = 1 ]; then
		echo "  隨時可以移除程式、設定檔、排程與帳號（容器收集程式並移出 docker 群組），"
		echo "  再到 Smoke 撤銷權杖："
	else
		echo "  隨時可以移除程式、設定檔、排程與帳號，再到 Smoke 撤銷權杖："
	fi
	terms_uninstall_cmds
	echo "================================================================================"
}

terms_en() {
	items=""
	if [ "$SEL_OS" = 1 ]; then items="OS packages"; fi
	if [ "$SEL_LOCK" = 1 ]; then items="${items:+$items, }application lockfiles"; fi
	if [ "$SEL_DOCKER" = 1 ]; then items="${items:+$items, }Docker containers"; fi
	cat <<EOF
================================================================================
 Smoke collectors: installation terms, version $TERMS_VERSION
 Scanning: $items
================================================================================
Read these terms in full before installing. Typing y means you have read,
understood and accept all of them; anything else cancels the installation and
leaves this host unchanged.
EOF
	terms_section "" "What is installed on this host, and its privileges"
	if [ "$DO_OS" = 1 ]; then
		cat <<EOF
   The Linux collector (smoke-collector):
   a. A system account, smoke-collector, that cannot log in.
   b. The program /usr/local/bin/smoke-collector and the configuration file
      /etc/smoke-collector/config (it holds the asset token; only root and
      that account can read it).
   c. A systemd timer that runs it once a day (a cron entry without systemd).
   d. It runs as an unprivileged user, does not stay running, opens no port,
      does not update itself and never installs, removes or changes system
      packages or settings.
EOF
		if [ "$SEL_LOCK" = 1 ]; then
			cat <<EOF
   e. For lockfile paths under /home, /root or /run/user, the systemd drop-in
      /etc/systemd/system/smoke-collector.service.d/lockfiles.conf makes
      exactly those paths visible to it, read-only. The installer only checks
      read permissions; it never changes the permissions of any file.
EOF
		fi
	fi
	if [ "$DO_C" = 1 ]; then
		cat <<EOF
   The container collector (smoke-container-collector):
   a. A system account, smoke-container, that cannot log in.
EOF
		if terms_docker_group; then
			cat <<EOF
   b. smoke-container is added to the docker group. IMPORTANT: access to
      Docker is equivalent to root on this host; anyone who can run a program
      as this account can take full control of the host. If that is not
      acceptable, cancel and use a Docker API proxy that allows only read-only
      paths, given with --docker-host (see the help pages).
EOF
		else
			cat <<EOF
   b. It is NOT added to the docker group; it reads Docker through
      $DOCKER_HOST_OPT. Give smoke-container access to that socket yourself;
      whatever the socket allows, the account can do, so make sure it allows
      only the read-only paths the collector needs.
EOF
		fi
		cat <<EOF
   c. The program /usr/local/bin/smoke-container-collector and the
      configuration file /etc/smoke-collector/containers.config (it holds the
      token; only root and that account can read it).
   d. A systemd timer that runs it once a day (a cron entry without systemd).
EOF
		if [ "$DO_OS" = 1 ]; then
			echo "   e. It does not stay running, opens no port and does not update itself."
		else
			echo "   e. It does not stay running, opens no port and does not update itself."
			echo "      The Linux collector is not affected."
		fi
		terms_section "" "What it does with Docker"
		cat <<EOF
   a. It sends only GET requests, to four paths only: the Docker version, the
      running containers, image details, and copying files out of a
      container. The program refuses any other request.
   b. It never runs commands in containers, never pulls, deletes or builds
      images, and never starts, stops or changes containers.
   c. For each image it copies /etc/os-release and the package database
      (dpkg status, apk installed) from one running container.
EOF
	fi
	terms_section "" "What is collected and sent"
	echo "   Once a day, over HTTPS, only to the Smoke address given at installation."
	if [ "$SEL_OS" = 1 ]; then
		cat <<EOF
   OS packages (smoke-collector):
   a. the operating system (ID, VERSION_ID, VERSION_CODENAME from
      /etc/os-release) and the kernel version;
   b. the installed packages: name, version, architecture, source package;
   c. the names of running systemd services and the packages each one uses;
   d. whether a reboot is required.
   To tell which packages a service uses, it reads the services' process
   information (/proc) and the ELF headers of programs and libraries, but
   sends only package names. The OS package scan never sends file contents,
   command lines, environment variables, passwords, keys, account data, logs
   or network traffic.
EOF
	fi
	if [ "$SEL_LOCK" = 1 ]; then
		cat <<EOF
   Application lockfiles (smoke-collector):
   a. the configured path strings, and the full contents of the lockfiles
      with a supported name at those paths (such as package-lock.json,
      yarn.lock, pnpm-lock.yaml, composer.lock, poetry.lock, uv.lock,
      Pipfile.lock, requirements*.txt, go.mod, Cargo.lock, gradle.lockfile,
      packages.lock.json, pubspec.lock);
   b. for a directory, only those names directly inside it. No other file in
      it is read (such as .env, source code or node_modules), and
      subdirectories are not searched;
   c. Smoke strips user names and passwords in URLs inside lockfiles (such as
      private registry tokens) and deletes the original files within 24
      hours;
   d. the path strings are kept to match the paths to assets in Smoke; only
      members who can see the project can see them.
   It reads with the permissions of the smoke-collector account.
EOF
		if [ -n "$LOCKFILES" ]; then
			echo "   The paths given now:"
			for p in $LOCKFILES; do echo "     $p"; done
		fi
	fi
	if [ "$DO_C" = 1 ]; then
		cat <<EOF
   Docker containers (smoke-container-collector):
   a. for each running image: its name and tag, image ID, digest and the
      number of containers using it;
   b. the image's operating system and installed packages (name, version,
      architecture, source package);
   c. four standard labels of the image saying where it comes from
      (org.opencontainers.image source, title, version and base.name), so
      Smoke can tell which public image it is built from.
   It never sends other labels, container names, environment variables,
   mounts, network settings, logs or other file contents.
EOF
	fi
	cat <<EOF
   Each report also carries the collector's version, CPU architecture and
   scanned items. Smoke's server logs record the connecting IP address and
   time. See exactly what is sent at any time with:
EOF
	if [ "$DO_OS" = 1 ]; then echo "   sudo smoke-collector run --dry-run"; fi
	if [ "$DO_C" = 1 ]; then echo "   sudo -u smoke-container /usr/local/bin/smoke-container-collector run --dry-run"; fi
	terms_section "" "How the data is used"
	cat <<EOF
   a. It is stored in your Smoke workspace and used to match security
      advisories and produce vulnerability findings and fix advice, under the
      terms of service and privacy policy between you and the Smoke service
      provider.
EOF
	n=b
	if [ "$SEL_LOCK" = 1 ]; then
		cat <<EOF
   $n. Lockfiles are written only to assets that a workspace admin has linked
      to this host in Smoke; paths without a link are only listed on the host
      page for an admin to handle.
EOF
		n=c
	fi
	if [ "$DO_C" = 1 ]; then
		cat <<EOF
   $n. Smoke may create container image assets from image names; they count
      toward your plan's asset limit. Over the limit none are created and the
      workspace admins are notified.
EOF
	fi
	terms_section "" "Your responsibilities"
	cat <<EOF
   a. You confirm that you are authorized to install and run this program on
      this host, and that doing so complies with your organization's security
      policies, your contractual obligations and applicable law.
EOF
	set -- b c d e
	if [ "$SEL_LOCK" = 1 ]; then
		echo "   $1. You confirm that you are authorized to read the lockfiles above and"
		echo "      send them to Smoke."
		shift
	fi
	if [ "$DO_C" = 1 ]; then
		echo "   $1. You confirm that you are authorized to grant the Docker access above."
		shift
	fi
	cat <<EOF
   $1. The tokens are this host's upload credentials: keep them safe, and
      revoke and replace them in Smoke at once if they may have leaked.
   $2. Assess the impact on your systems yourself; try it in a test
      environment before production.
EOF
	terms_section "" "Disclaimer"
	cat <<EOF
   a. The program and its results are provided "as is" and "as available",
      without any warranty that they are error-free, uninterrupted or fit for
      a particular purpose.
   b. Vulnerability matching relies on third-party advisories and package
      data; results may be incomplete, late or wrong, and do not replace your
      own security assessment, patching decisions and backups.
EOF
	if [ "$DO_C" = 1 ]; then
		cat <<EOF
   c. You assess and bear the risk of granting Docker access. To the maximum
      extent permitted by law, the Smoke service provider is not liable for
      any direct, indirect, incidental, consequential or special damages
      (including, without limitation, system outages, data loss, security
      incidents, or loss of business or profit) arising from installing,
      using or being unable to use this program, or from decisions based on
      its results.
EOF
	else
		cat <<EOF
   c. To the maximum extent permitted by law, the Smoke service provider is
      not liable for any direct, indirect, incidental, consequential or
      special damages (including, without limitation, system outages, data
      loss, or loss of business or profit) arising from installing, using or
      being unable to use this program, or from decisions based on its
      results.
EOF
	fi
	echo "   d. Nothing here limits liability that cannot be excluded by law."
	terms_section "" "Removal"
	if [ "$DO_C" = 1 ]; then
		echo "   Remove the programs, their configuration, schedules and accounts (and the"
		echo "   container collector's docker group membership) at any time, then revoke"
		echo "   the tokens in Smoke:"
	else
		echo "   Remove the program, its configuration, schedule and account at any time,"
		echo "   then revoke the token in Smoke:"
	fi
	terms_uninstall_cmds
	echo "================================================================================"
}

terms_text() {
	TERMS_N=0
	if [ "$TERMS_LANG" = zh-TW ]; then terms_zh; else terms_en; fi
}

# terms_covered FILE ITEMS: 0 when FILE records this terms version for every item of ITEMS.
terms_covered() {
	[ -f "$1" ] && grep -qx "terms_version=$TERMS_VERSION" "$1" || return 1
	recorded=$(sed -n 's/^scans=//p' "$1" | sed -n 1p)
	for it in $(printf '%s' "$2" | tr , ' '); do
		case ",$recorded," in
		*",$it,"*) ;;
		*) return 1 ;;
		esac
	done
	return 0
}

# confirm_terms: returns when the terms of this version are accepted for every chosen item
# (already on this host, by --accept-terms, or typed y at the terminal); otherwise exits without
# changing anything.
TERMS_HOW=""
confirm_terms() {
	need=0
	if [ "$DO_OS" = 1 ] && ! terms_covered "$CONF_DIR/terms-accepted" "$OS_SCAN"; then need=1; fi
	if [ "$DO_C" = 1 ] && ! terms_covered "$CONF_DIR/containers.terms-accepted" docker; then need=1; fi
	if [ "$need" = 0 ]; then
		say "installation terms $TERMS_VERSION already accepted on this host for $(scan_list)"
		TERMS_HOW=kept
		return 0
	fi
	if [ "$ACCEPT_TERMS" = 1 ]; then
		say "installation terms $TERMS_VERSION for $(scan_list) accepted with --accept-terms (read them with --show-terms)"
		TERMS_HOW=--accept-terms
		return 0
	fi
	if ! has_tty; then
		die "the installation terms must be accepted first: read them with --show-terms --scan $(scan_list), then run again with --accept-terms (no terminal to ask)"
	fi
	{
		terms_text
		if [ "$TERMS_LANG" = zh-TW ]; then
			printf '是否同意上述條款並繼續安裝？輸入 y 同意 [y/N] '
		else
			printf 'Do you accept these terms and continue? Type y to accept [y/N] '
		fi
	} >/dev/tty
	IFS= read -r answer </dev/tty || answer=""
	case $answer in
	y | Y | yes | YES | Yes) ;;
	*) die "terms not accepted; nothing installed" ;;
	esac
	TERMS_HOW=prompt
}

# record_terms: after the program's configuration is written, keep which terms were accepted for
# which items, when, how and by whom (the sudo caller), so an upgrade does not ask again.
record_terms() {
	[ "$TERMS_HOW" != kept ] || return 0
	tmp="$CONF_DIR/.terms.$$"
	{
		echo "# Installation terms accepted for $PROG, written by install.sh."
		echo "terms_version=$TERMS_VERSION"
		echo "scans=$PROG_SCANS"
		echo "accepted_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "accepted_with=$TERMS_HOW"
		echo "language=$TERMS_LANG"
		echo "sudo_user=${SUDO_USER:-}"
	} >"$tmp"
	chown root:root "$tmp" 2>/dev/null || chown 0:0 "$tmp"
	chmod 0644 "$tmp"
	mv -f "$tmp" "$TERMS_FILE"
}

if [ "$SHOW_TERMS" = 1 ]; then
	URL=$(printf '%s' "$URL" | sed 's#/*$##')
	if [ "$SCAN_GIVEN" = 1 ]; then parse_scan "$SCAN_OPT" --scan; else SEL_OS=1; fi
	set_programs
	terms_text
	exit 0
fi

if [ -n "$VERIFY_FILE" ]; then
	[ "$PUBKEY" != "$PLACEHOLDER" ] || die "this install.sh has no public key (it is the unreleased copy)"
	check_openssl
	new_workdir
	verify_signature "$VERIFY_FILE" "$VERIFY_SIG" "$WORK"
	say "signature OK: $VERIFY_FILE"
	exit 0
fi

# --- helpers ------------------------------------------------------------------------------------

[ "$(id -u)" = 0 ] || die "run as root (for example: curl -fsSL .../install.sh | sudo sh -s -- --url ...)"

have() { command -v "$1" >/dev/null 2>&1; }

has_systemd() { [ -d /run/systemd/system ] && have systemctl; }

user_group() { id -gn "$NAME" 2>/dev/null || echo "$NAME"; }

in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }

# select_prog os|containers: the program the next steps work on (its user, binary, configuration
# file, terms record, units and cron entry).
select_prog() {
	if [ "$1" = containers ]; then
		PROG=smoke-container-collector
		NAME=smoke-container
		BIN=/usr/local/bin/smoke-container-collector
		CONF=$CONTAINERS_CONF
		CRON_D=/etc/cron.d/smoke-container-collector
		CRONTAB=/etc/crontabs/smoke-container
		TERMS_FILE=$CONF_DIR/containers.terms-accepted
		IS_C=1
		PROG_SCANS=docker
	else
		PROG=smoke-collector
		NAME=smoke-collector
		BIN=/usr/local/bin/smoke-collector
		CONF=$OS_CONF
		CRON_D=/etc/cron.d/smoke-collector
		CRONTAB=/etc/crontabs/smoke-collector
		TERMS_FILE=$CONF_DIR/terms-accepted
		IS_C=0
		PROG_SCANS=${OS_SCAN:-os}
	fi
}

# user_can r|x PATH: whether $NAME has read (r) or search (x) permission on PATH, as test -r/-x
# run as that account.
user_can() {
	if have runuser; then
		runuser -u "$NAME" -- test "-$1" "$2"
	else
		# busybox su (Alpine) parses options anywhere on its command line: only the path (which
		# starts with /) follows -c, as $1 of the shell.
		su -s /bin/sh "$NAME" -c "test -$1 \"\$1\"" sh "$2"
	fi
}

# --- uninstall ----------------------------------------------------------------------------------

uninstall() {
	if have systemctl && [ -f "$UNIT_DIR/$PROG.timer" ]; then
		systemctl disable --now "$PROG.timer" >/dev/null 2>&1 || true
	fi
	rm -f "$UNIT_DIR/$PROG.timer" "$UNIT_DIR/$PROG.service"
	if [ "$IS_C" = 0 ]; then
		rm -f "$DROPIN"
		rmdir "$DROPIN_DIR" 2>/dev/null || true
	fi
	if has_systemd; then
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	if [ -f "$CRONTAB" ]; then
		rm -f "$CRONTAB"
		echo "$NAME" >>/etc/crontabs/cron.update 2>/dev/null || true
	fi
	rm -f "$CRON_D" "$BIN"
	# /etc/smoke-collector is shared: each collector removes only its own file while the other
	# one is installed.
	if [ "$IS_C" = 1 ]; then
		rm -f "$CONF" "$TERMS_FILE"
		if [ -f "$OS_CONF" ]; then
			chmod 0750 "$CONF_DIR"
		else
			rmdir "$CONF_DIR" 2>/dev/null || true
		fi
	elif [ -f "$CONTAINERS_CONF" ]; then
		find "$CONF_DIR" -mindepth 1 -maxdepth 1 ! -name 'containers.*' -exec rm -rf {} \;
		chown root:root "$CONF_DIR" 2>/dev/null || chown 0:0 "$CONF_DIR"
		chmod 0751 "$CONF_DIR"
	else
		rm -rf "$CONF_DIR"
	fi
	if id "$NAME" >/dev/null 2>&1; then
		if have userdel; then
			userdel "$NAME" >/dev/null 2>&1 || warn "could not remove the user $NAME"
		elif have deluser; then
			deluser "$NAME" >/dev/null 2>&1 || warn "could not remove the user $NAME"
		fi
	fi
	if have getent && getent group "$NAME" >/dev/null 2>&1; then
		if have groupdel; then groupdel "$NAME" >/dev/null 2>&1 || true; elif have delgroup; then delgroup "$NAME" >/dev/null 2>&1 || true; fi
	fi
	say "removed $BIN, $CONF, the timer or cron entry and the $NAME user"
}

if [ "$UNINSTALL" = 1 ]; then
	# Without --scan: smoke-collector (--containers is --scan docker).
	if [ "$SCAN_GIVEN" = 1 ]; then parse_scan "$SCAN_OPT" --scan; else SEL_OS=1; fi
	set_programs
	if [ "$DO_OS" = 1 ]; then select_prog os; uninstall; fi
	if [ "$DO_C" = 1 ]; then select_prog containers; uninstall; fi
	exit 0
fi

# --- what to scan: the existing choice, the terminal or os --------------------------------------

if [ "$SCAN_GIVEN" = 1 ]; then
	parse_scan "$SCAN_OPT" --scan
elif [ -f "$OS_CONF" ] || [ -f "$CONTAINERS_CONF" ]; then
	if [ -f "$OS_CONF" ]; then
		existing=$(conf_value scan "$OS_CONF")
		(parse_scan "${existing:-os}" "scan= in $OS_CONF") 2>/dev/null || {
			warn "scan=$existing in $OS_CONF is not valid; using os"
			existing=os
		}
		parse_scan "${existing:-os}" "scan= in $OS_CONF"
	fi
	if [ -f "$CONTAINERS_CONF" ]; then SEL_DOCKER=1; fi
	say "keeping what the existing installation scans: $(scan_list) (use --scan to change it)"
elif has_tty; then
	if [ "$TERMS_LANG" = zh-TW ]; then
		q_os="掃描 OS 套件（smoke-collector）？" q_lock="掃描應用程式 lockfile（smoke-collector）？" q_docker="掃描 Docker 容器（smoke-container-collector，需要 docker 群組）？"
	else
		q_os="Scan OS packages (smoke-collector)?" q_lock="Scan application lockfiles (smoke-collector)?" q_docker="Scan Docker containers (smoke-container-collector, needs the docker group)?"
	fi
	if ask "$q_os" y; then SEL_OS=1; fi
	if ask "$q_lock" n; then SEL_LOCK=1; fi
	if ask "$q_docker" n; then SEL_DOCKER=1; fi
	[ -n "$(scan_list)" ] || die "nothing chosen to scan; nothing installed"
else
	SEL_OS=1
fi
set_programs

if [ -n "$DOCKER_HOST_OPT" ] && [ "$DO_C" = 0 ]; then
	die "--docker-host is only for --containers (--scan docker)"
fi
if [ -n "$C_TOKEN_FILE" ] && [ "$DO_C" = 0 ]; then
	die "--containers-token-file is only for --containers (--scan docker)"
fi
if [ "$LOCKFILE_GIVEN" = 1 ] && [ "$DO_OS" = 0 ]; then
	die "--lockfile is for lockfiles in --scan (for example --scan lockfiles --lockfile /srv/app/current)"
fi

# --- lockfile paths -----------------------------------------------------------------------------

# KEEP_LOCKFILES: copy the existing lockfile= lines as they are. LOCKFILES: the checked paths
# (for the systemd drop-in, the readability check and the configuration).
KEEP_LOCKFILES=0
if [ "$DO_OS" = 1 ] && [ "$LOCKFILE_GIVEN" = 0 ] && [ -f "$OS_CONF" ] &&
	grep -Eq '^[[:space:]]*lockfile[[:space:]]*=' "$OS_CONF"; then
	if [ "$SEL_LOCK" = 1 ]; then
		KEEP_LOCKFILES=1
		existing=$(sed -n 's/^[[:space:]]*lockfile[[:space:]]*=[[:space:]]*//p' "$OS_CONF" |
			sed -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/")
		while IFS= read -r v; do
			if check_lockfile "$v"; then
				case " $LOCKFILES " in *" $LF_PATH "*) ;; *) LOCKFILES="${LOCKFILES:+$LOCKFILES }$LF_PATH" ;; esac
			else
				warn "lockfile=$v in $OS_CONF is kept, but not checked here and not given to the systemd drop-in ($LF_ERR)"
			fi
		done <<EOF
$existing
EOF
		say "keeping the lockfile paths of the existing installation (use --lockfile to replace them)"
	elif [ "$SCAN_GIVEN" = 0 ]; then
		KEEP_LOCKFILES=1 # not scanned, but an upgrade does not drop them
	fi
fi
if [ "$SEL_LOCK" = 1 ] && [ "$KEEP_LOCKFILES" = 0 ] && [ -z "$LOCKFILES" ]; then
	if ! has_tty; then
		die "lockfiles is chosen but no lockfile path is set: add --lockfile PATH (an application directory or lockfile, for example --lockfile /srv/app/current)"
	fi
	printf 'Lockfile paths for smoke-collector to read (absolute application directories or lockfiles, separated by spaces): ' >/dev/tty
	IFS= read -r answer </dev/tty || answer=""
	set -f
	for p in $answer; do add_lockfile "$p" "lockfile path"; done
	set +f
	[ -n "$LOCKFILES" ] || die "no lockfile path given; nothing installed"
fi
if [ "$SEL_LOCK" = 0 ] && [ -n "$LOCKFILES" ]; then
	die "--lockfile needs lockfiles in --scan (for example --scan os,lockfiles)"
fi

# --- checks -------------------------------------------------------------------------------------

[ -n "$URL" ] || die "--url is required (the Smoke address, for example --url https://smoke.example.com)"
URL=$(printf '%s' "$URL" | sed 's#/*$##')
case $URL in
*[!A-Za-z0-9.:/_~%-]*) die "--url contains characters that are not allowed (no user name, query or spaces)" ;;
https://?*) ;;
http://localhost | http://localhost[:/]* | http://127.0.0.1 | http://127.0.0.1[:/]*)
	[ "$INSECURE_HTTP" = 1 ] || die "--url must use https:// (http:// only with --insecure-http and localhost)" ;;
*) die "--url must use https://" ;;
esac

if [ -n "$VERSION" ]; then
	VERSION=${VERSION#v}
fi

# An upgrade without --docker-host keeps the socket of the existing configuration.
if [ "$DO_C" = 1 ] && [ -z "$DOCKER_HOST_OPT" ] && [ -f "$CONTAINERS_CONF" ]; then
	DOCKER_HOST_OPT=$(conf_value docker_host "$CONTAINERS_CONF")
	case ${DOCKER_HOST_OPT#unix://} in
	"$DOCKER_HOST_OPT" | *[!A-Za-z0-9._/-]* | *..*) DOCKER_HOST_OPT="" ;;
	esac
	if [ -n "$DOCKER_HOST_OPT" ]; then say "keeping docker_host=$DOCKER_HOST_OPT of the existing installation"; fi
fi
if [ "$DOCKER_HOST_OPT" = "$DEFAULT_DOCKER_HOST" ]; then
	DOCKER_HOST_OPT=""
fi
# USE_DOCKER_GROUP: the default socket through the docker group; otherwise the given socket.
USE_DOCKER_GROUP=0
if [ "$DO_C" = 1 ] && [ -z "$DOCKER_HOST_OPT" ]; then
	USE_DOCKER_GROUP=1
fi

if [ "$DO_C" = 1 ] && [ "$USE_DOCKER_GROUP" = 1 ]; then
	if have getent; then
		getent group docker >/dev/null 2>&1 || die "there is no docker group on this host (is Docker installed?); the container collector reads Docker through it (or use --docker-host with a proxy socket)"
	else
		grep -q '^docker:' /etc/group || die "there is no docker group on this host (is Docker installed?); the container collector reads Docker through it (or use --docker-host with a proxy socket)"
	fi
elif [ "$DO_C" = 1 ]; then
	say "smoke-container will read Docker through $DOCKER_HOST_OPT (not added to the docker group)"
fi

if [ "$SKIP_SIGNATURE" = 0 ]; then
	[ "$PUBKEY" != "$PLACEHOLDER" ] ||
		die "this install.sh has no public key (it is the unreleased copy from the repository); download it from <smoke>/downloads/collector/install.sh, or pass --skip-signature"
	check_openssl
else
	warn "--skip-signature: the download is NOT checked against the release signature"
fi

case $(uname -m) in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture $(uname -m) (supported: x86_64, aarch64)" ;;
esac

if have curl; then
	if [ "$INSECURE_HTTP" = 1 ]; then proto='=http,https'; else proto='=https'; fi
	fetch() { curl -fsSL --proto "$proto" --proto-redir "$proto" --retry 2 -o "$2" "$1"; }
elif have wget; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "curl or wget is needed"
fi

# The token files: --token-file is smoke-collector's, or the container collector's when it is the
# only program of this run; --containers-token-file is the container collector's.
OS_TOKEN_FILE="" CT_TOKEN_FILE=$C_TOKEN_FILE
if [ "$DO_OS" = 1 ]; then
	OS_TOKEN_FILE=$TOKEN_FILE
elif [ -z "$CT_TOKEN_FILE" ]; then
	CT_TOKEN_FILE=$TOKEN_FILE
elif [ -n "$TOKEN_FILE" ]; then
	die "--token-file is smoke-collector's token, which is not installed by this run (--scan docker); use --containers-token-file only"
fi
for f in "$OS_TOKEN_FILE" "$CT_TOKEN_FILE"; do
	if [ -n "$f" ] && { ! [ -f "$f" ] || ! [ -r "$f" ]; }; then die "cannot read the token file $f"; fi
done

# The terms (privileges, data, disclaimer) are accepted after the checks above and before
# anything is downloaded or changed.
confirm_terms

new_workdir
BASE="$URL/downloads/collector"

# --- 1. download --------------------------------------------------------------------------------

PROGS=""
if [ "$DO_OS" = 1 ]; then PROGS=smoke-collector; fi
if [ "$DO_C" = 1 ]; then PROGS="${PROGS:+$PROGS }smoke-container-collector"; fi
if [ -z "$VERSION" ]; then
	fetch "$BASE/LATEST" "$WORK/LATEST" || die "cannot download $BASE/LATEST (has the collector been released on this Smoke?)"
	VERSION=$(sed -n 1p "$WORK/LATEST" | tr -d ' \r\t')
fi
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' ||
	die "invalid version: $VERSION"
say "downloading $PROGS $VERSION ($ARCH)"
for prog in $PROGS; do
	fetch "$BASE/v$VERSION/${prog}_linux_$ARCH" "$WORK/${prog}_linux_$ARCH" || die "cannot download $BASE/v$VERSION/${prog}_linux_$ARCH"
done
for f in SHA256SUMS SHA256SUMS.minisig; do
	fetch "$BASE/v$VERSION/$f" "$WORK/$f" || die "cannot download $BASE/v$VERSION/$f"
done

# --- 2. signature, 3. checksum ------------------------------------------------------------------

if [ "$SKIP_SIGNATURE" = 0 ]; then
	verify_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.minisig" "$WORK"
	say "signature of SHA256SUMS verified"
fi
for prog in $PROGS; do
	FILE="${prog}_linux_$ARCH"
	expected=$(awk -v f="$FILE" '$2 == f || $2 == "*" f { print $1; exit }' "$WORK/SHA256SUMS")
	[ -n "$expected" ] || die "SHA256SUMS has no entry for $FILE"
	if have sha256sum; then
		actual=$(sha256sum "$WORK/$FILE" | awk '{ print $1 }')
	else
		actual=$(openssl dgst -sha256 -r "$WORK/$FILE" | awk '{ print $1 }')
	fi
	[ "$actual" = "$expected" ] || die "SHA-256 mismatch for $FILE; do not install"
	say "SHA-256 of $FILE verified"
	chmod 0755 "$WORK/$FILE"
	"$WORK/$FILE" version >/dev/null 2>&1 || die "the downloaded binary $FILE does not run on this machine"
done

# --- 4. tokens (smoke-collector's first) --------------------------------------------------------

# read_token FILE PROMPT OPTION: sets TOKEN, or KEEP_TOKEN=1 to keep the one in $CONF (not with
# --replace-token).
read_token() {
	TOKEN="" KEEP_TOKEN=0
	if [ -n "$1" ]; then
		TOKEN=$(sed -n 1p "$1" | tr -d '\r')
	elif [ "$REPLACE_TOKEN" = 0 ] && [ -f "$CONF" ] &&
		grep -Eq '^[[:space:]]*(token|token_file)[[:space:]]*=' "$CONF"; then
		KEEP_TOKEN=1
		say "keeping the token of the existing $PROG installation (use --replace-token or $3 to replace it)"
		return 0
	else
		has_tty || die "no terminal to read the $PROG token from; use $3 FILE"
		STTY_SAVED=$(stty -g </dev/tty)
		printf '%s (smk_..., input hidden): ' "$2" >/dev/tty
		stty -echo </dev/tty
		IFS= read -r TOKEN </dev/tty || true
		stty "$STTY_SAVED" </dev/tty
		STTY_SAVED=""
		printf '\n' >/dev/tty
	fi
	# Trim surrounding blanks; reject anything that is not printable ASCII without spaces.
	TOKEN=$(printf '%s' "$TOKEN" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	[ -n "$TOKEN" ] || die "no token given for $PROG"
	case $TOKEN in
	*[!!-~]*) die "the $PROG token contains characters that are not allowed" ;;
	esac
}

OS_TOKEN="" OS_KEEP_TOKEN=0 C_TOKEN="" C_KEEP_TOKEN=0
if [ "$DO_OS" = 1 ]; then
	select_prog os
	read_token "$OS_TOKEN_FILE" "Asset token for smoke-collector (OS packages and lockfiles)" --token-file
	OS_TOKEN=$TOKEN OS_KEEP_TOKEN=$KEEP_TOKEN
fi
if [ "$DO_C" = 1 ]; then
	select_prog containers
	opt=--containers-token-file
	if [ "$DO_OS" = 0 ]; then opt=--token-file; fi
	read_token "$CT_TOKEN_FILE" "Container collector token for smoke-container-collector (Docker)" "$opt"
	C_TOKEN=$TOKEN C_KEEP_TOKEN=$KEEP_TOKEN
fi
TOKEN=""

# --- 5. user, binary, configuration -------------------------------------------------------------

# install_program: the user, binary, configuration and terms record of $PROG, with TOKEN/KEEP_TOKEN.
install_program() {
	if ! id "$NAME" >/dev/null 2>&1; then
		nologin=/bin/false
		for p in /usr/sbin/nologin /sbin/nologin; do
			if [ -x "$p" ]; then nologin=$p; break; fi
		done
		if have useradd; then
			useradd --system --user-group --no-create-home --home-dir /nonexistent --shell "$nologin" "$NAME"
		elif have adduser; then
			addgroup -S "$NAME" 2>/dev/null || true
			adduser -S -D -H -h /nonexistent -s "$nologin" -G "$NAME" "$NAME"
		else
			die "cannot create the $NAME user (no useradd or adduser)"
		fi
		say "created system user $NAME"
	fi
	GROUP=$(user_group)
	if [ "$IS_C" = 1 ] && [ "$USE_DOCKER_GROUP" = 0 ] && in_group "$NAME" docker; then
		# Switching to a proxy socket: the docker group is no longer needed.
		if have gpasswd; then
			gpasswd -d "$NAME" docker >/dev/null
		elif have delgroup; then
			delgroup "$NAME" docker >/dev/null
		else
			warn "could not remove $NAME from the docker group; remove it yourself"
		fi
		in_group "$NAME" docker || say "removed $NAME from the docker group (it reads Docker through $DOCKER_HOST_OPT)"
	fi
	if [ "$IS_C" = 1 ] && [ "$USE_DOCKER_GROUP" = 1 ] && ! in_group "$NAME" docker; then
		if have usermod; then
			usermod -aG docker "$NAME"
		elif have addgroup; then
			addgroup "$NAME" docker
		else
			die "cannot add $NAME to the docker group (no usermod or addgroup)"
		fi
		say "added $NAME to the docker group"
	fi

	mkdir -p "$(dirname "$BIN")"
	cp "$WORK/${PROG}_linux_$ARCH" "$BIN.new"
	chown root:root "$BIN.new" 2>/dev/null || chown 0:0 "$BIN.new"
	chmod 0755 "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	say "installed $BIN ($("$BIN" version))"

	# /etc/smoke-collector is shared by both collectors. With only the OS collector it stays
	# 0750 root:smoke-collector; with containers.config in it, others get search (x) permission so
	# smoke-container can open its own file (each file is 0640 and owned by its group).
	mkdir -p "$CONF_DIR"
	if [ "$IS_C" = 1 ]; then
		if ! [ -f "$OS_CONF" ]; then
			chown root:root "$CONF_DIR" 2>/dev/null || chown 0:0 "$CONF_DIR"
		fi
		chmod 0751 "$CONF_DIR"
	else
		chown "root:$GROUP" "$CONF_DIR"
		if [ -f "$CONTAINERS_CONF" ]; then chmod 0751 "$CONF_DIR"; else chmod 0750 "$CONF_DIR"; fi
	fi
	tmp="$CONF_DIR/.config.$$"
	(
		umask 077
		{
			if [ "$IS_C" = 1 ]; then
				echo "# smoke-container-collector configuration, written by install.sh. Mode 0640 root:$GROUP."
				echo "# Keys: url, token (or token_file), docker_host (default unix:///var/run/docker.sock)."
				echo "# SMOKE_CONTAINER_COLLECTOR_URL / _TOKEN / _DOCKER_HOST override."
			else
				echo "# smoke-collector configuration, written by install.sh. Mode 0640 root:$GROUP."
				echo "# Keys: url, token (or token_file), scan (os, lockfiles), lockfile (repeatable, at most 20)."
				echo "# SMOKE_COLLECTOR_URL / SMOKE_COLLECTOR_TOKEN override url and token."
			fi
			printf 'url=%s\n' "$URL"
			if [ "$KEEP_TOKEN" = 1 ]; then
				grep -E '^[[:space:]]*(token|token_file)[[:space:]]*=' "$CONF"
			else
				printf 'token=%s\n' "$TOKEN"
			fi
			if [ "$IS_C" = 1 ] && [ -n "$DOCKER_HOST_OPT" ]; then
				printf 'docker_host=%s\n' "$DOCKER_HOST_OPT"
			fi
			if [ "$IS_C" = 0 ]; then
				printf 'scan=%s\n' "$OS_SCAN"
				if [ "$KEEP_LOCKFILES" = 1 ]; then
					grep -E '^[[:space:]]*lockfile[[:space:]]*=' "$CONF"
				else
					for p in $LOCKFILES; do printf 'lockfile=%s\n' "$p"; done
				fi
			fi
		} >"$tmp"
	)
	chown "root:$GROUP" "$tmp"
	chmod 0640 "$tmp"
	mv -f "$tmp" "$CONF"
	if [ "$IS_C" = 1 ]; then
		say "wrote $CONF (0640 root:$GROUP)"
	else
		say "wrote $CONF (0640 root:$GROUP; scan=$OS_SCAN)"
	fi
	record_terms
}

# is_lockfile_name NAME: about smoke-collector's list of supported names (the program decides).
is_lockfile_name() {
	case $1 in
	package-lock.json | npm-shrinkwrap.json | pnpm-lock.yaml | yarn.lock | composer.lock | poetry.lock | \
		uv.lock | Pipfile.lock | go.mod | Cargo.lock | gradle.lockfile | packages.lock.json | pubspec.lock) return 0 ;;
	esac
	lc=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
	case $lc in
	*[!a-z0-9_.-]*) return 1 ;;
	requirements.txt | requirements[-_.]?*.txt | ?*[-_.]requirements.txt) return 0 ;;
	esac
	return 1
}

access_warn() {
	warn "smoke-collector cannot read $1 (it reads with the smoke-collector account's permissions; install.sh does not change them). To allow it, for example: setfacl -m u:smoke-collector:$2 $1 (every directory above it also needs u:smoke-collector:x)"
}

# check_lockfile_access: warns about lockfile paths smoke-collector cannot read. Run as the
# account itself, so missing search permission on a parent directory is found too.
check_lockfile_access() {
	[ "$SEL_LOCK" = 1 ] || return 0
	for p in $LOCKFILES; do
		if ! [ -e "$p" ]; then
			warn "lockfile path $p does not exist; it is reported as not_found until it does"
			continue
		fi
		if [ -d "$p" ]; then
			if ! user_can r "$p" || ! user_can x "$p"; then
				access_warn "$p" rX
				continue
			fi
			found=0
			for f in "$p"/*; do
				[ -f "$f" ] || continue
				is_lockfile_name "${f##*/}" || continue
				found=1
				user_can r "$f" || access_warn "$f" r
			done
			if [ "$found" = 0 ]; then warn "lockfile path $p has no supported lockfile; it is reported as no_lockfile"; fi
		else
			if ! is_lockfile_name "${p##*/}"; then
				warn "lockfile path $p: ${p##*/} is not a supported lockfile name; it is reported as no_lockfile"
			fi
			user_can r "$p" || access_warn "$p" r
		fi
	done
}

# --- 6. schedule --------------------------------------------------------------------------------

# dropin_paths: the lockfile paths, and where they lead, under /home, /root or /run/user.
dropin_paths() {
	out=""
	[ "$SEL_LOCK" = 1 ] || return 0
	for p in $LOCKFILES; do
		real=$(readlink -f "$p" 2>/dev/null || true)
		for q in "$p" "$real"; do
			case $q in
			/home | /home/* | /root | /root/* | /run/user | /run/user/*) ;;
			*) continue ;;
			esac
			case $q in
			*[!A-Za-z0-9._/@+-]*)
				warn "$p leads to $q, which cannot be written to the systemd drop-in; smoke-collector will not see it under ProtectHome"
				continue ;;
			esac
			case " $out " in *" $q "*) ;; *) out="${out:+$out }$q" ;; esac
		done
	done
	printf '%s' "$out"
}

# update_dropin: ProtectHome=yes hides /home, /root and /run/user from smoke-collector.service;
# for lockfile paths there, the drop-in mounts only those paths, read-only. Removed when there are
# none. A leading - makes a missing path not fail the service (it is reported as not_found).
update_dropin() {
	paths=$(dropin_paths)
	if [ -z "$paths" ]; then
		if [ -f "$DROPIN" ]; then
			rm -f "$DROPIN"
			rmdir "$DROPIN_DIR" 2>/dev/null || true
			say "removed $DROPIN (no lockfile path under /home, /root or /run/user)"
		fi
		return 0
	fi
	mkdir -p "$DROPIN_DIR"
	{
		echo "# Written by install.sh for the lockfile paths under /home, /root or /run/user, which"
		echo "# ProtectHome=yes hides: only these paths are made visible to smoke-collector, read-only."
		echo "# install.sh rewrites or removes this file; change the paths with install.sh --lockfile."
		echo "[Service]"
		echo "ProtectHome=tmpfs"
		for p in $paths; do echo "BindReadOnlyPaths=-$p"; done
	} >"$DROPIN.new"
	chmod 0644 "$DROPIN.new"
	mv -f "$DROPIN.new" "$DROPIN"
	say "wrote $DROPIN (read-only: $paths)"
}

install_systemd() {
	if [ "$IS_C" = 1 ]; then
		install_container_units
		return
	fi
	cat >"$UNIT_DIR/smoke-collector.service" <<'SERVICE'
[Unit]
Description=Smoke collector: upload the OS package inventory and/or application lockfiles to Smoke
Documentation=https://gitlab.aircraft.tw/smoke/smoke-collector
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=smoke-collector
Group=smoke-collector
ExecStart=/usr/local/bin/smoke-collector run
TimeoutStartSec=15min
NoNewPrivileges=yes
ProtectSystem=strict
# Lockfile paths under /home, /root or /run/user: install.sh adds the drop-in
# smoke-collector.service.d/lockfiles.conf (ProtectHome=tmpfs plus BindReadOnlyPaths= per path).
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
SERVICE
	cat >"$UNIT_DIR/smoke-collector.timer" <<'TIMER'
[Unit]
Description=Daily Smoke collector run

[Timer]
OnCalendar=daily
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
TIMER
	chmod 0644 "$UNIT_DIR/smoke-collector.service" "$UNIT_DIR/smoke-collector.timer"
	update_dropin
	systemctl daemon-reload
	systemctl enable --now smoke-collector.timer >/dev/null 2>&1 || die "systemctl enable --now smoke-collector.timer failed"
	say "installed systemd smoke-collector.timer (daily, randomized by up to 4 h)"
}

install_container_units() {
	cat >"$UNIT_DIR/smoke-container-collector.service" <<'CONTAINER_SERVICE'
[Unit]
Description=Smoke container collector: report running Docker images and their packages to Smoke
Documentation=https://gitlab.aircraft.tw/smoke/smoke-collector
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
User=smoke-container
Group=smoke-container
# The docker group can control Docker, which is equivalent to root (install.sh --containers asks
# before adding it). The program only sends GET requests to four Docker API paths.
SupplementaryGroups=docker
ExecStart=/usr/local/bin/smoke-container-collector run
TimeoutStartSec=15min
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
CONTAINER_SERVICE
	cat >"$UNIT_DIR/smoke-container-collector.timer" <<'CONTAINER_TIMER'
[Unit]
Description=Daily Smoke container collector run

[Timer]
OnCalendar=daily
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
CONTAINER_TIMER
	if [ "$USE_DOCKER_GROUP" = 0 ]; then
		# A proxy socket: no docker group (the comment above SupplementaryGroups goes with it).
		awk '/^# The docker group can control Docker/ { skip = 1 } !skip { print } /^SupplementaryGroups=docker$/ { skip = 0 }' \
			"$UNIT_DIR/smoke-container-collector.service" >"$UNIT_DIR/.smoke-container-collector.service.$$"
		mv -f "$UNIT_DIR/.smoke-container-collector.service.$$" "$UNIT_DIR/smoke-container-collector.service"
	fi
	chmod 0644 "$UNIT_DIR/smoke-container-collector.service" "$UNIT_DIR/smoke-container-collector.timer"
	systemctl daemon-reload
	systemctl enable --now smoke-container-collector.timer >/dev/null 2>&1 || die "systemctl enable --now smoke-container-collector.timer failed"
	say "installed systemd smoke-container-collector.timer (daily, randomized by up to 4 h)"
}


install_cron() {
	# A random time of day, like RandomizedDelaySec, so hosts do not all report at once.
	when=$(awk 'BEGIN { srand(); printf "%d %d", int(rand() * 60), int(rand() * 24) }')
	if have logger; then sink="2>&1 | logger -t $PROG"; else sink='>/dev/null 2>&1'; fi
	if [ -d /etc/cron.d ]; then
		{
			echo "# $PROG daily run, written by install.sh"
			echo "SHELL=/bin/sh"
			echo "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
			echo "$when * * * $NAME $BIN run $sink"
		} >"$CRON_D"
		chmod 0644 "$CRON_D"
		say "installed $CRON_D (daily at $(echo "$when" | awk '{ printf "%02d:%02d", $2, $1 }'))"
	elif [ -d /etc/crontabs ] || have crond; then
		mkdir -p /etc/crontabs
		{
			echo "# $PROG daily run, written by install.sh"
			echo "$when * * * $BIN run $sink"
		} >"$CRONTAB"
		chmod 0600 "$CRONTAB"
		echo "$NAME" >>/etc/crontabs/cron.update 2>/dev/null || true
		if have rc-update; then
			rc-update add crond default >/dev/null 2>&1 || warn "could not add crond to the default runlevel"
			rc-service crond start >/dev/null 2>&1 || warn "could not start crond (rc-service crond start)"
		fi
		say "installed $CRONTAB (daily at $(echo "$when" | awk '{ printf "%02d:%02d", $2, $1 }'))"
	else
		warn "no systemd and no cron found: run '$BIN run' as $NAME once a day yourself"
	fi
}

schedule() {
	if [ "$NO_SERVICE" = 1 ]; then
		say "--no-service: no timer or cron entry installed for $PROG"
		if [ "$IS_C" = 0 ] && has_systemd; then
			# An existing unit still needs the drop-in for the current lockfile paths.
			update_dropin
			systemctl daemon-reload >/dev/null 2>&1 || true
		fi
	elif has_systemd; then
		install_systemd
	else
		install_cron
	fi
}

if [ "$DO_OS" = 1 ]; then
	select_prog os
	TOKEN=$OS_TOKEN KEEP_TOKEN=$OS_KEEP_TOKEN
	install_program
	TOKEN="" OS_TOKEN=""
	check_lockfile_access
	schedule
fi
if [ "$DO_C" = 1 ]; then
	select_prog containers
	TOKEN=$C_TOKEN KEEP_TOKEN=$C_KEEP_TOKEN
	install_program
	TOKEN="" C_TOKEN=""
	schedule
fi

# --- 7. first run -------------------------------------------------------------------------------

if [ "$NO_RUN" = 1 ]; then
	for prog in $PROGS; do say "$prog installed (--no-run: not run now). Try: /usr/local/bin/$prog run --dry-run"; done
	say "done"
	exit 0
fi

# first_run: runs $PROG once as $NAME and sets RC.
first_run() {
	set -- run
	if [ "$INSECURE_HTTP" = 1 ]; then set -- run --insecure-http; fi
	say "running $PROG once as $NAME"
	set +e
	if have runuser; then
		runuser -u "$NAME" -- "$BIN" "$@"
	else
		# busybox su (Alpine); its setpriv lacks --reuid, so it is not used.
		su -s /bin/sh "$NAME" -c "$BIN $*"
	fi
	RC=$?
	set -e
	case $RC in
	0) say "$PROG: the first report was accepted" ;;
	1) warn "$PROG first run: configuration error (check $CONF; $PROG print-config)" ;;
	2)
		if [ "$IS_C" = 1 ]; then
			if [ "$USE_DOCKER_GROUP" = 1 ]; then
				warn "$PROG first run: reading Docker failed (is Docker running? is $NAME in the docker group?)"
			else
				warn "$PROG first run: reading Docker failed (can $NAME open ${DOCKER_HOST_OPT#unix://}?)"
			fi
		else
			warn "$PROG first run: collecting the package list failed"
		fi
		;;
	3) warn "$PROG first run: Smoke rejected a report (see the message above)" ;;
	4) warn "$PROG first run: network or server error; the timer will try again" ;;
	*) warn "$PROG first run failed (exit code $RC)" ;;
	esac
}

# The exit code is the first failing run's (smoke-collector first).
rc=0
if [ "$DO_OS" = 1 ]; then
	select_prog os
	first_run
	if [ "$rc" = 0 ]; then rc=$RC; fi
fi
if [ "$DO_C" = 1 ]; then
	select_prog containers
	first_run
	if [ "$rc" = 0 ]; then rc=$RC; fi
fi
if [ "$rc" = 0 ]; then say "done"; fi
exit "$rc"
