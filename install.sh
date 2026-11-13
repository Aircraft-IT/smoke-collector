#!/bin/sh
# smoke-collector installer (OS detection plan §5.4). POSIX sh; Ubuntu, Debian, Alpine, RHEL, Rocky Linux and AlmaLinux.
#
#   curl -fsSL https://<smoke>/downloads/collector/install.sh | sudo sh -s -- --url https://<smoke>
#
# Downloads the collector from <url>/downloads/collector/, verifies the minisign signature of
# SHA256SUMS with openssl (legacy minisign signatures are plain Ed25519) and the SHA-256 of the
# binary, reads the asset token from the terminal (never from the command line), creates the
# smoke-collector system user, installs /usr/local/bin/smoke-collector and
# /etc/smoke-collector/config, schedules a daily run (systemd timer, or cron without systemd)
# and runs the collector once.
#
# With --containers it installs the container collector instead (spec FR-COL-08):
# /usr/local/bin/smoke-container-collector, run daily as the smoke-container user, which is added
# to the docker group (equivalent to root), configured in /etc/smoke-collector/containers.config
# with its own token. The OS collector is not touched.
#
# Before anything is downloaded or changed, the installation terms (what is installed, what is
# collected and sent, your responsibilities, the disclaimer) are shown and must be accepted by
# typing y. The acceptance is recorded in /etc/smoke-collector/terms-accepted (container
# collector: containers.terms-accepted); a later upgrade asks again only when the terms change.
#
# Options:
#   --url URL            Smoke address (https://). Required unless --uninstall.
#   --token-file FILE    read the asset token from FILE instead of the terminal (non-interactive).
#                        Without it, an existing installation keeps its token.
#   --version VERSION    install VERSION instead of the one in LATEST.
#   --skip-signature     do not verify the signature (not recommended; SHA-256 is still checked).
#   --no-service         do not install the systemd timer or cron entry.
#   --no-run             do not run the collector at the end.
#   --insecure-http      allow an http:// URL for localhost (testing only).
#   --containers         install (or with --uninstall remove) the container collector.
#   --show-terms         print the installation terms (with --containers: the container
#                        collector's) and exit (no root needed).
#   --accept-terms       accept the installation terms without being asked (non-interactive
#                        installs; read them first with --show-terms). --yes is the same.
#   --lang zh-TW|en      language of the terms (default: from LANG, otherwise English).
#   --docker-host unix:///PATH
#                        with --containers: read Docker through this socket (for example a
#                        filtering proxy that allows only the collector's four GET paths) instead
#                        of /var/run/docker.sock. The user is then NOT added to the docker group:
#                        give it access to that socket yourself (for example its group).
#   --uninstall          remove the program, its configuration, the timer or cron entry and the user.
#   --verify-signature FILE SIGFILE
#                        only verify FILE against the minisign signature SIGFILE with the embedded
#                        public key, then exit (no root needed).
set -eu
umask 022
# The caller's locale, before it is replaced: it picks the language of the terms.
ORIG_LOCALE=${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}
LC_ALL=C
export LC_ALL

# minisign public key (the base64 line of smoke-collector.pub), written by scripts/release.sh.
PUBKEY="__SMOKE_COLLECTOR_PUBKEY__"
PLACEHOLDER="__SMOKE_COLLECTOR""_PUBKEY__"

NAME=smoke-collector
BIN=/usr/local/bin/smoke-collector
CONF_DIR=/etc/smoke-collector
CONF=$CONF_DIR/config
UNIT_DIR=/etc/systemd/system
CRON_D=/etc/cron.d/smoke-collector
CRONTAB=/etc/crontabs/smoke-collector

URL=""
TOKEN_FILE=""
VERSION=""
SKIP_SIGNATURE=0
NO_SERVICE=0
NO_RUN=0
INSECURE_HTTP=0
UNINSTALL=0
CONTAINERS=0
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

# shellcheck disable=SC2317 # called from the EXIT trap
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
		echo "Options: --url URL [--token-file FILE] [--version VERSION] [--skip-signature] [--no-service]"
		echo "         [--no-run] [--insecure-http] [--accept-terms] [--lang zh-TW|en]"
		echo "         [--containers [--docker-host unix:///PATH]]"
		echo "         | --show-terms [--containers] [--lang zh-TW|en]"
		echo "         | --uninstall [--containers]"
		echo "         | --verify-signature FILE SIGFILE"
	fi
}

need_value() {
	if [ $# -lt 2 ] || [ -z "$2" ]; then die "$1 needs a value"; fi
}

while [ $# -gt 0 ]; do
	case $1 in
	--url) need_value "$@"; URL=$2; shift 2 ;;
	--url=*) URL=${1#*=}; shift ;;
	--token-file) need_value "$@"; TOKEN_FILE=$2; shift 2 ;;
	--token-file=*) TOKEN_FILE=${1#*=}; shift ;;
	--version) need_value "$@"; VERSION=$2; shift 2 ;;
	--version=*) VERSION=${1#*=}; shift ;;
	--skip-signature) SKIP_SIGNATURE=1; shift ;;
	--no-service) NO_SERVICE=1; shift ;;
	--no-run) NO_RUN=1; shift ;;
	--insecure-http) INSECURE_HTTP=1; shift ;;
	--uninstall) UNINSTALL=1; shift ;;
	--containers) CONTAINERS=1; shift ;;
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

# The program this run installs or removes: the OS collector, or with --containers the container
# collector (its own user, binary, configuration file, units and cron entry).
PROG=smoke-collector
if [ "$CONTAINERS" = 1 ]; then
	PROG=smoke-container-collector
	NAME=smoke-container
	BIN=/usr/local/bin/smoke-container-collector
	CONF=$CONF_DIR/containers.config
	CRON_D=/etc/cron.d/smoke-container-collector
	CRONTAB=/etc/crontabs/smoke-container
fi
TERMS_FILE=$CONF_DIR/terms-accepted
if [ "$CONTAINERS" = 1 ]; then TERMS_FILE=$CONF_DIR/containers.terms-accepted; fi
OS_CONF=$CONF_DIR/config
CONTAINERS_CONF=$CONF_DIR/containers.config
DEFAULT_DOCKER_HOST=unix:///var/run/docker.sock
if [ -n "$DOCKER_HOST_OPT" ]; then
	[ "$CONTAINERS" = 1 ] || die "--docker-host is only for --containers"
	case $DOCKER_HOST_OPT in
	unix:///?*) ;;
	*) die "--docker-host must look like unix:///run/smoke-docker.sock (only unix sockets)" ;;
	esac
	case ${DOCKER_HOST_OPT#unix://} in
	*[!A-Za-z0-9._/-]* | *..* | *//*) die "--docker-host must be unix:// followed by a clean absolute path (letters, digits, . _ - /)" ;;
	esac
fi

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
TERMS_VERSION=2026-11-13

case ${LANG_OPT:-} in
'' | zh-TW | zh_TW | zh | en) ;;
*) die "--lang must be zh-TW or en" ;;
esac
TERMS_LANG=en
case ${LANG_OPT:-$ORIG_LOCALE} in
zh*) TERMS_LANG=zh-TW ;;
esac

terms_uninstall_cmd() {
	c="curl -fsSL ${URL:-https://<Smoke>}/downloads/collector/install.sh | sudo sh -s -- --uninstall"
	if [ "$CONTAINERS" = 1 ]; then c="$c --containers"; fi
	printf '%s' "$c"
}

# terms_docker_group: 1 when the container collector reads Docker through the docker group.
terms_docker_group() {
	case $DOCKER_HOST_OPT in
	'' | "$DEFAULT_DOCKER_HOST") return 0 ;;
	esac
	return 1
}

terms_os_zh() {
	cat <<EOF
================================================================================
 Smoke Linux 收集程式（smoke-collector）安裝與使用條款　版本 $TERMS_VERSION
================================================================================
安裝前請完整閱讀以下條款。輸入 y 表示您已閱讀、理解並同意全部條款；
輸入其他內容會取消安裝，這台主機不會有任何變更。

一、安裝後主機上的變更
  1. 建立不能登入的系統帳號 smoke-collector。
  2. 安裝程式 /usr/local/bin/smoke-collector，以及設定檔
     /etc/smoke-collector/config（內含資產權杖，只有 root 和該帳號能讀）。
  3. 安裝每天執行一次的 systemd timer；沒有 systemd 時改用 cron。
  4. 程式以一般使用者權限執行，不常駐、不開任何連接埠、不會自動更新，
     也不會安裝、移除或修改系統套件與設定。

二、收集與傳送的資料
  每天一次，透過 HTTPS 傳送到安裝時指定的 Smoke 網址，不會送到其他地方：
  1. 作業系統識別（/etc/os-release 的 ID、VERSION_ID、VERSION_CODENAME）
     與核心版本；
  2. 已安裝套件的名稱、版本、架構與來源套件；
  3. 執行中的 systemd 服務名稱，以及每個服務使用到的套件名稱；
  4. 是否需要重新開機；
  5. 收集程式的版本與 CPU 架構。
  Smoke 的伺服器紀錄會包含連線的來源 IP 位址與時間。
  為判斷服務使用的套件，程式會讀取服務的行程資訊（/proc）以及程式與函式庫
  的 ELF 標頭，但只傳送套件名稱。程式不會傳送檔案內容、命令列參數、環境
  變數、密碼、金鑰、帳號資料、日誌或網路流量。
  實際傳送的內容可以隨時用 sudo smoke-collector run --dry-run 查看。

三、資料的用途
  資料存放在您的 Smoke 工作區，用來比對安全公告、產生弱點清單與修補建議，
  並依您與 Smoke 服務提供者之間的服務條款及隱私權政策處理。

四、您的責任
  1. 您確認自己有權在這台主機上安裝並執行本程式，且安裝符合貴組織的資訊
     安全政策、契約義務與相關法令。
  2. 資產權杖是這台主機上傳資料的憑證，請妥善保管；懷疑外洩時請立即到
     Smoke 撤銷並換發。
  3. 請自行評估安裝對系統的影響；正式環境安裝前，建議先在測試環境確認。

五、免責聲明
  1. 本程式及其產生的結果依「現況」及「現有」提供，不保證沒有錯誤或中斷，
     也不保證適合任何特定用途。
  2. 弱點比對依賴第三方發布的安全公告與套件資訊，結果可能有遺漏、延遲或
     誤判，不能取代您自己的安全評估、修補決策與備份。
  3. 在法律允許的最大範圍內，Smoke 服務提供者對於因安裝、使用或無法使用
     本程式，或依其結果所做的任何決定，所造成的直接、間接、附帶、衍生或
     特別損害（包括但不限於系統中斷、資料遺失、營業或利潤損失），均不負
     賠償責任。
  4. 法律強制規定不得排除的責任，不受本條影響。

六、移除
  隨時可以移除程式、設定檔、排程與帳號，再到 Smoke 撤銷權杖：
    $(terms_uninstall_cmd)
================================================================================
EOF
}

terms_containers_zh() {
	cat <<EOF
================================================================================
 Smoke 容器收集程式（smoke-container-collector）安裝與使用條款　版本 $TERMS_VERSION
================================================================================
安裝前請完整閱讀以下條款。輸入 y 表示您已閱讀、理解並同意全部條款；
輸入其他內容會取消安裝，這台主機不會有任何變更。

一、安裝後主機上的變更與權限
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
  5. 程式不常駐、不開任何連接埠、不會自動更新。Linux 收集程式不受影響。

二、對 Docker 做的事
  1. 只送出 GET 請求，而且只限四個路徑：Docker 版本、執行中的容器清單、
     映像檔資訊、從容器複製檔案。程式內建限制，其他請求一律不會送出。
  2. 不會在容器內執行指令，不會下載、刪除或建立映像檔，也不會啟動、停止
     或修改容器。
  3. 每個映像檔只從其中一個執行中的容器複製 /etc/os-release 和套件資料庫
     （dpkg 的 status、apk 的 installed）。

三、收集與傳送的資料
  每天一次，透過 HTTPS 傳送到安裝時指定的 Smoke 網址，不會送到其他地方：
  1. 每個執行中映像檔的名稱與標籤、映像檔 ID、digest、使用它的容器數量；
  2. 映像檔的作業系統識別與已安裝套件清單（名稱、版本、架構、來源套件）；
  3. 收集程式的版本與 CPU 架構。
  Smoke 的伺服器紀錄會包含連線的來源 IP 位址與時間。
  不會傳送容器名稱、環境變數、標籤（labels）、掛載、網路設定、日誌或其他
  檔案內容。實際傳送的內容可以用 sudo -u smoke-container
  /usr/local/bin/smoke-container-collector run --dry-run 查看。

四、資料的用途
  1. 資料存放在您的 Smoke 工作區，用來比對安全公告、產生弱點清單與修補
     建議，並依您與 Smoke 服務提供者之間的服務條款及隱私權政策處理。
  2. Smoke 可能依映像檔名稱自動建立「容器映像檔」資產，計入方案的資產數量；
     超過方案上限時不會建立，並通知工作區管理員。

五、您的責任
  1. 您確認自己有權在這台主機上安裝並執行本程式、授與上述 Docker 權限，
     且安裝符合貴組織的資訊安全政策、契約義務與相關法令。
  2. 權杖是這台主機上傳資料的憑證，請妥善保管；懷疑外洩時請立即到 Smoke
     撤銷並換發。
  3. 請自行評估安裝對系統的影響；正式環境安裝前，建議先在測試環境確認。

六、免責聲明
  1. 本程式及其產生的結果依「現況」及「現有」提供，不保證沒有錯誤或中斷，
     也不保證適合任何特定用途。
  2. 弱點比對依賴第三方發布的安全公告與套件資訊，結果可能有遺漏、延遲或
     誤判，不能取代您自己的安全評估、修補決策與備份。
  3. 授與 Docker 權限的風險由您自行評估與承擔。在法律允許的最大範圍內，
     Smoke 服務提供者對於因安裝、使用或無法使用本程式，或依其結果所做的任何
     決定，所造成的直接、間接、附帶、衍生或特別損害（包括但不限於系統中斷、
     資料遺失、安全事件、營業或利潤損失），均不負賠償責任。
  4. 法律強制規定不得排除的責任，不受本條影響。

七、移除
  隨時可以移除程式、設定檔、排程與帳號（並移出 docker 群組），再到 Smoke
  撤銷權杖：
    $(terms_uninstall_cmd)
================================================================================
EOF
}

terms_os_en() {
	cat <<EOF
================================================================================
 Smoke Linux collector (smoke-collector): installation terms, version $TERMS_VERSION
================================================================================
Read these terms in full before installing. Typing y means you have read,
understood and accept all of them; anything else cancels the installation and
leaves this host unchanged.

1. What is installed on this host
   a. A system account, smoke-collector, that cannot log in.
   b. The program /usr/local/bin/smoke-collector and the configuration file
      /etc/smoke-collector/config (it holds the asset token; only root and
      that account can read it).
   c. A systemd timer that runs it once a day (a cron entry without systemd).
   d. It runs as an unprivileged user, does not stay running, opens no port,
      does not update itself and never installs, removes or changes system
      packages or settings.

2. What is collected and sent
   Once a day, over HTTPS, only to the Smoke address given at installation:
   a. the operating system (ID, VERSION_ID, VERSION_CODENAME from
      /etc/os-release) and the kernel version;
   b. the installed packages: name, version, architecture, source package;
   c. the names of running systemd services and the packages each one uses;
   d. whether a reboot is required;
   e. the collector's version and CPU architecture.
   Smoke's server logs record the connecting IP address and time.
   To tell which packages a service uses, it reads the services' process
   information (/proc) and the ELF headers of programs and libraries, but
   sends only package names. It never sends file contents, command lines,
   environment variables, passwords, keys, account data, logs or network
   traffic. See exactly what is sent at any time with:
   sudo smoke-collector run --dry-run

3. How the data is used
   It is stored in your Smoke workspace and used to match security advisories
   and produce vulnerability findings and fix advice, under the terms of
   service and privacy policy between you and the Smoke service provider.

4. Your responsibilities
   a. You confirm that you are authorized to install and run this program on
      this host, and that doing so complies with your organization's security
      policies, your contractual obligations and applicable law.
   b. The asset token is this host's upload credential: keep it safe, and
      revoke and replace it in Smoke at once if it may have leaked.
   c. Assess the impact on your systems yourself; try it in a test
      environment before production.

5. Disclaimer
   a. The program and its results are provided "as is" and "as available",
      without any warranty that they are error-free, uninterrupted or fit for
      a particular purpose.
   b. Vulnerability matching relies on third-party advisories and package
      data; results may be incomplete, late or wrong, and do not replace your
      own security assessment, patching decisions and backups.
   c. To the maximum extent permitted by law, the Smoke service provider is
      not liable for any direct, indirect, incidental, consequential or
      special damages (including, without limitation, system outages, data
      loss, or loss of business or profit) arising from installing, using or
      being unable to use this program, or from decisions based on its
      results.
   d. Nothing here limits liability that cannot be excluded by law.

6. Removal
   Remove the program, its configuration, schedule and account at any time,
   then revoke the token in Smoke:
     $(terms_uninstall_cmd)
================================================================================
EOF
}

terms_containers_en() {
	cat <<EOF
================================================================================
 Smoke container collector (smoke-container-collector): installation terms,
 version $TERMS_VERSION
================================================================================
Read these terms in full before installing. Typing y means you have read,
understood and accept all of them; anything else cancels the installation and
leaves this host unchanged.

1. What is installed on this host, and its privileges
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
   e. It does not stay running, opens no port and does not update itself.
      The Linux collector is not affected.

2. What it does with Docker
   a. It sends only GET requests, to four paths only: the Docker version, the
      running containers, image details, and copying files out of a
      container. The program refuses any other request.
   b. It never runs commands in containers, never pulls, deletes or builds
      images, and never starts, stops or changes containers.
   c. For each image it copies /etc/os-release and the package database
      (dpkg status, apk installed) from one running container.

3. What is collected and sent
   Once a day, over HTTPS, only to the Smoke address given at installation:
   a. for each running image: its name and tag, image ID, digest and the
      number of containers using it;
   b. the image's operating system and installed packages (name, version,
      architecture, source package);
   c. the collector's version and CPU architecture.
   Smoke's server logs record the connecting IP address and time.
   It never sends container names, environment variables, labels, mounts,
   network settings, logs or other file contents. See exactly what is sent
   with:
   sudo -u smoke-container /usr/local/bin/smoke-container-collector run --dry-run

4. How the data is used
   a. It is stored in your Smoke workspace and used to match security
      advisories and produce vulnerability findings and fix advice, under the
      terms of service and privacy policy between you and the Smoke service
      provider.
   b. Smoke may create container image assets from image names; they count
      toward your plan's asset limit. Over the limit none are created and the
      workspace admins are notified.

5. Your responsibilities
   a. You confirm that you are authorized to install and run this program on
      this host and to grant the Docker access above, and that doing so
      complies with your organization's security policies, your contractual
      obligations and applicable law.
   b. The token is this host's upload credential: keep it safe, and revoke
      and replace it in Smoke at once if it may have leaked.
   c. Assess the impact on your systems yourself; try it in a test
      environment before production.

6. Disclaimer
   a. The program and its results are provided "as is" and "as available",
      without any warranty that they are error-free, uninterrupted or fit for
      a particular purpose.
   b. Vulnerability matching relies on third-party advisories and package
      data; results may be incomplete, late or wrong, and do not replace your
      own security assessment, patching decisions and backups.
   c. You assess and bear the risk of granting Docker access. To the maximum
      extent permitted by law, the Smoke service provider is not liable for
      any direct, indirect, incidental, consequential or special damages
      (including, without limitation, system outages, data loss, security
      incidents, or loss of business or profit) arising from installing,
      using or being unable to use this program, or from decisions based on
      its results.
   d. Nothing here limits liability that cannot be excluded by law.

7. Removal
   Remove the program, its configuration, schedule and account (and its
   docker group membership) at any time, then revoke the token in Smoke:
     $(terms_uninstall_cmd)
================================================================================
EOF
}

terms_text() {
	if [ "$CONTAINERS" = 1 ]; then
		if [ "$TERMS_LANG" = zh-TW ]; then terms_containers_zh; else terms_containers_en; fi
	elif [ "$TERMS_LANG" = zh-TW ]; then
		terms_os_zh
	else
		terms_os_en
	fi
}

# confirm_terms: returns when the terms of this version are accepted (already on this host, by
# --accept-terms, or typed y at the terminal); otherwise exits without changing anything.
TERMS_HOW=""
confirm_terms() {
	if [ -f "$TERMS_FILE" ] && grep -qx "terms_version=$TERMS_VERSION" "$TERMS_FILE"; then
		say "installation terms $TERMS_VERSION already accepted on this host ($TERMS_FILE)"
		TERMS_HOW=kept
		return 0
	fi
	if [ "$ACCEPT_TERMS" = 1 ]; then
		say "installation terms $TERMS_VERSION accepted with --accept-terms (read them with --show-terms)"
		TERMS_HOW=--accept-terms
		return 0
	fi
	if ! (: </dev/tty) 2>/dev/null; then
		die "the installation terms must be accepted first: read them with --show-terms, then run again with --accept-terms (no terminal to ask)"
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

# record_terms: after the configuration is written, keep which terms were accepted, when, how and
# by whom (the sudo caller), so an upgrade does not ask again for the same version.
record_terms() {
	[ "$TERMS_HOW" != kept ] || return 0
	tmp="$CONF_DIR/.terms.$$"
	{
		echo "# Installation terms accepted for $PROG, written by install.sh."
		echo "terms_version=$TERMS_VERSION"
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

# --- uninstall ----------------------------------------------------------------------------------

uninstall() {
	if have systemctl && [ -f "$UNIT_DIR/$PROG.timer" ]; then
		systemctl disable --now "$PROG.timer" >/dev/null 2>&1 || true
	fi
	rm -f "$UNIT_DIR/$PROG.timer" "$UNIT_DIR/$PROG.service"
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
	if [ "$CONTAINERS" = 1 ]; then
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
	uninstall
	exit 0
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

in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }

# An upgrade without --docker-host keeps the socket of the existing configuration.
if [ "$CONTAINERS" = 1 ] && [ -z "$DOCKER_HOST_OPT" ] && [ -f "$CONF" ]; then
	DOCKER_HOST_OPT=$(sed -n 's/^[[:space:]]*docker_host[[:space:]]*=[[:space:]]*//p' "$CONF" | sed -n 1p | tr -d " \t\r\"'")
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
if [ "$CONTAINERS" = 1 ] && [ -z "$DOCKER_HOST_OPT" ]; then
	USE_DOCKER_GROUP=1
fi

if [ "$CONTAINERS" = 1 ] && [ "$USE_DOCKER_GROUP" = 1 ]; then
	if have getent; then
		getent group docker >/dev/null 2>&1 || die "there is no docker group on this host (is Docker installed?); the container collector reads Docker through it (or use --docker-host with a proxy socket)"
	else
		grep -q '^docker:' /etc/group || die "there is no docker group on this host (is Docker installed?); the container collector reads Docker through it (or use --docker-host with a proxy socket)"
	fi
elif [ "$CONTAINERS" = 1 ]; then
	say "$NAME will read Docker through $DOCKER_HOST_OPT (not added to the docker group)"
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

if [ -n "$TOKEN_FILE" ]; then
	if ! [ -f "$TOKEN_FILE" ] || ! [ -r "$TOKEN_FILE" ]; then die "cannot read --token-file $TOKEN_FILE"; fi
fi

# The terms (privileges, data, disclaimer) are accepted after the checks above and before
# anything is downloaded or changed.
confirm_terms

new_workdir
BASE="$URL/downloads/collector"

# --- 1. download --------------------------------------------------------------------------------

if [ -z "$VERSION" ]; then
	fetch "$BASE/LATEST" "$WORK/LATEST" || die "cannot download $BASE/LATEST (has the collector been released on this Smoke?)"
	VERSION=$(sed -n 1p "$WORK/LATEST" | tr -d ' \r\t')
fi
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' ||
	die "invalid version: $VERSION"
FILE="${PROG}_linux_$ARCH"
say "downloading $PROG $VERSION ($ARCH)"
for f in "$FILE" SHA256SUMS SHA256SUMS.minisig; do
	fetch "$BASE/v$VERSION/$f" "$WORK/$f" || die "cannot download $BASE/v$VERSION/$f"
done

# --- 2. signature, 3. checksum ------------------------------------------------------------------

if [ "$SKIP_SIGNATURE" = 0 ]; then
	verify_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.minisig" "$WORK"
	say "signature of SHA256SUMS verified"
fi
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
"$WORK/$FILE" version >/dev/null 2>&1 || die "the downloaded binary does not run on this machine"

# --- 4. token -----------------------------------------------------------------------------------

TOKEN=""
KEEP_TOKEN=0
if [ -n "$TOKEN_FILE" ]; then
	TOKEN=$(sed -n 1p "$TOKEN_FILE" | tr -d '\r')
elif [ -f "$CONF" ] && grep -Eq '^[[:space:]]*(token|token_file)[[:space:]]*=' "$CONF"; then
	KEEP_TOKEN=1
	say "keeping the token of the existing installation (use --token-file to replace it)"
else
	if ! (: </dev/tty) 2>/dev/null; then
		die "no terminal to read the token from; use --token-file FILE"
	fi
	STTY_SAVED=$(stty -g </dev/tty)
	if [ "$CONTAINERS" = 1 ]; then
		printf 'Container collector token (smk_..., input hidden): ' >/dev/tty
	else
		printf 'Asset token (smk_..., input hidden): ' >/dev/tty
	fi
	stty -echo </dev/tty
	IFS= read -r TOKEN </dev/tty || true
	stty "$STTY_SAVED" </dev/tty
	STTY_SAVED=""
	printf '\n' >/dev/tty
fi
if [ "$KEEP_TOKEN" = 0 ]; then
	# Trim surrounding blanks; reject anything that is not printable ASCII without spaces.
	TOKEN=$(printf '%s' "$TOKEN" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	[ -n "$TOKEN" ] || die "no token given"
	case $TOKEN in
	*[!!-~]*) die "the token contains characters that are not allowed" ;;
	esac
fi

# --- 5. user, binary, configuration -------------------------------------------------------------

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
if [ "$CONTAINERS" = 1 ] && [ "$USE_DOCKER_GROUP" = 0 ] && in_group "$NAME" docker; then
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
if [ "$USE_DOCKER_GROUP" = 1 ] && ! in_group "$NAME" docker; then
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
cp "$WORK/$FILE" "$BIN.new"
chown root:root "$BIN.new" 2>/dev/null || chown 0:0 "$BIN.new"
chmod 0755 "$BIN.new"
mv -f "$BIN.new" "$BIN"
say "installed $BIN ($("$BIN" version))"

# /etc/smoke-collector is shared by both collectors. With only the OS collector it stays
# 0750 root:smoke-collector; with containers.config in it, others get search (x) permission so
# smoke-container can open its own file (each file is 0640 and owned by its group).
mkdir -p "$CONF_DIR"
if [ "$CONTAINERS" = 1 ]; then
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
		if [ "$CONTAINERS" = 1 ]; then
			echo "# smoke-container-collector configuration, written by install.sh. Mode 0640 root:$GROUP."
			echo "# Keys: url, token (or token_file), docker_host (default unix:///var/run/docker.sock)."
			echo "# SMOKE_CONTAINER_COLLECTOR_URL / _TOKEN / _DOCKER_HOST override."
		else
			echo "# smoke-collector configuration, written by install.sh. Mode 0640 root:$GROUP."
			echo "# Keys: url, token (or token_file). SMOKE_COLLECTOR_URL / SMOKE_COLLECTOR_TOKEN override."
		fi
		printf 'url=%s\n' "$URL"
		if [ "$KEEP_TOKEN" = 1 ]; then
			grep -E '^[[:space:]]*(token|token_file)[[:space:]]*=' "$CONF"
		else
			printf 'token=%s\n' "$TOKEN"
		fi
		if [ -n "$DOCKER_HOST_OPT" ]; then
			printf 'docker_host=%s\n' "$DOCKER_HOST_OPT"
		fi
	} >"$tmp"
)
chown "root:$GROUP" "$tmp"
chmod 0640 "$tmp"
mv -f "$tmp" "$CONF"
TOKEN=""
say "wrote $CONF (0640 root:$GROUP)"
record_terms

# --- 6. schedule --------------------------------------------------------------------------------

install_systemd() {
	if [ "$CONTAINERS" = 1 ]; then
		install_container_units
		return
	fi
	cat >"$UNIT_DIR/smoke-collector.service" <<'SERVICE'
[Unit]
Description=Smoke collector: upload the OS package inventory to Smoke
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

if [ "$NO_SERVICE" = 1 ]; then
	say "--no-service: no timer or cron entry installed"
elif has_systemd; then
	install_systemd
else
	install_cron
fi

# --- 7. first run -------------------------------------------------------------------------------

if [ "$NO_RUN" = 1 ]; then
	say "done (--no-run: not run now). Try: $BIN run --dry-run"
	exit 0
fi
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
rc=$?
set -e
case $rc in
0) say "done: the first report was accepted" ;;
1) warn "first run: configuration error (check $CONF; $PROG print-config)" ;;
2)
	if [ "$CONTAINERS" = 1 ]; then
		if [ "$USE_DOCKER_GROUP" = 1 ]; then
			warn "first run: reading Docker failed (is Docker running? is $NAME in the docker group?)"
		else
			warn "first run: reading Docker failed (can $NAME open ${DOCKER_HOST_OPT#unix://}?)"
		fi
	else
		warn "first run: collecting the package list failed"
	fi
	;;
3) warn "first run: Smoke rejected the report (see the message above)" ;;
4) warn "first run: network or server error; the timer will try again" ;;
*) warn "first run failed (exit code $rc)" ;;
esac
exit "$rc"
