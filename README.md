# smoke-collector

Host inventory collector for **Smoke**. Once a day it records which OS packages a Linux host
has installed (Ubuntu, Debian, Alpine, RHEL, Rocky Linux, AlmaLinux) and uploads that list to Smoke, which matches it against
distribution security advisories. It is a single static Go binary that runs as an unprivileged
user from a systemd timer (or cron) and exits when it is done. It does not stay running, update
itself or listen on any port.

## Specification

The design is in the smoke-docs repository:
[OS-DETECTION-PLAN.zh-TW.md](https://gitlab.aircraft.tw/smoke/smoke-docs/-/blob/main/plan/OS-DETECTION-PLAN.zh-TW.md)
(§2 for the data and the `#smoke-host 1` format, §5.1 for the collector, §5.2 for the upload API,
§5.4 for installation and releases). Change the plan first, then this repository.

## What it collects

Only what vulnerability matching needs, in the same `#smoke-host 1` text the manual command on
the asset page produces. The output is byte-for-byte identical to that command on the same host,
except for `#service-packages` (see below):

| Data | Source |
| --- | --- |
| `ID`, `VERSION_ID`, `VERSION_CODENAME` | `/etc/os-release` |
| Kernel release | `uname(2)`, same as `uname -r` |
| Installed packages, with source package and version | `dpkg-query -W -f=…`, `apk list --installed` or `rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n'` |
| Running systemd service names (Debian, Ubuntu, RHEL, Rocky Linux, AlmaLinux) | `systemctl list-units --type=service --state=running --no-legend --plain`, first column |
| Which packages each running service uses (same) | `/proc/<pid>/cgroup`, `/proc/<pid>/maps`, `/proc/<pid>/cmdline`, `systemctl show --property=Id,ExecStart <units>`, the ELF headers of the programs and their libraries, `/etc/ld.so.conf`, then `/var/lib/dpkg/info/*.list` or `rpm -qf --qf '%{NAME}\n' <paths>` and `rpm -q --qf '[%{FILENAMES}\t%{=NAME}\n]' <owners>` |
| Whether a reboot is required | Debian, Ubuntu: whether `/var/run/reboot-required` exists. RHEL, Rocky Linux, AlmaLinux: the exit status of `needs-restarting -r` (1 yes, 0 no; no value when it is not installed or fails otherwise) |

rpm is used only when `/etc/os-release` has `ID=rhel`, `rocky` or `almalinux` (Red Hat UBI images
have `ID=rhel`); `ID_LIKE` is not used, so CentOS, Oracle Linux, Amazon Linux and Fedora are not
supported. A Debian or Ubuntu host with rpm installed still uses dpkg.

The only programs it runs are `dpkg-query`, `apk` or `rpm`, `systemctl` (`list-units` and `show`)
and, on rpm hosts, `needs-restarting -r`. It runs them directly (never through a shell), finds them only in `/usr/bin`, `/bin`, `/sbin`
and `/usr/sbin`, and gives each a timeout. It never runs a program it analyses and does not use
`ldd`.

### `#service-packages`

Which binary packages each running service uses, so Smoke can tell which services to restart
after a library upgrade. It follows `#services`, one line per analysed unit:

```text
#service-packages
nginx.service	linked	libc6 libssl3t64 nginx
postgresql@16-main.service	maps	libc6 libssl3t64 postgresql-16
```

The fields are separated by tabs; packages are sorted and have no `:arch`. A unit is matched to
its processes through `/proc/<pid>/cgroup`. The method says how the list was made:

- `maps`: every process of the unit had a readable `/proc/<pid>/maps`. The packages own a mapped
  file (a library replaced by an upgrade but still mapped counts) or a program file. This needs
  root (`sudo smoke-collector run --dry-run`); the manual command uses only this method.
- `linked`: the usual case for the unprivileged collector, which cannot read other users' maps
  and is given no capability for it. The packages own the unit's programs (the ELF file in
  `ExecStart` and absolute ELF paths in its processes' command lines) or a shared library they
  link, recursively (DT_NEEDED resolved through DT_RPATH/DT_RUNPATH, `/etc/ld.so.conf` and the
  standard directories). Libraries loaded at run time (plugins, NSS or PAM modules) are not seen.

A unit that could not be analysed is left out (unknown), so is one with more than 300 packages;
at most 200 lines are written, and the analysis stops after 60 seconds. Because the methods
differ, this section is the one part of the output that can differ from the manual command (run
without root, the command leaves out most units). Alpine has no `#services`, so it has no
`#service-packages` either.

To see exactly what would be sent:

```sh
smoke-collector run --dry-run
```

## Install

On the host asset's page in Smoke, an Admin chooses **Install collector**. Smoke creates an asset
token (shown once) and the install command:

```sh
curl -fsSL https://smoke.example.com/downloads/collector/install.sh | sudo sh -s -- --url https://smoke.example.com
```

`install.sh` (POSIX sh) then:

0. shows the installation terms (what it installs, what it collects and sends, your
   responsibilities, the disclaimer) and continues only when you type `y`; anything else leaves
   the host unchanged. The language follows `--lang zh-TW|en` (the asset page adds `--lang zh-TW`
   in Chinese), otherwise `LANG`. The acceptance (version, time, how, `SUDO_USER`) is written to
   `/etc/smoke-collector/terms-accepted`, and an upgrade asks again only when `TERMS_VERSION` in
   `install.sh` changes. Without a terminal, read them with `--show-terms` and accept with
   `--accept-terms`;
1. downloads `LATEST`, the binary for the host architecture (`amd64` or `arm64`), `SHA256SUMS`
   and `SHA256SUMS.minisig`;
2. verifies the minisign signature of `SHA256SUMS` with `openssl` (OpenSSL 3; Alpine:
   `apk add openssl`), so minisign is not needed on the host;
3. checks the binary's SHA-256;
4. asks for the token on the terminal with echo off. The token is never accepted as a
   command-line argument. For unattended installs use `--token-file FILE`;
5. creates the `smoke-collector` system user, installs `/usr/local/bin/smoke-collector`, and
   writes `/etc/smoke-collector/config` with mode `0640 root:smoke-collector`;
6. installs `smoke-collector.service` and `smoke-collector.timer` (daily, randomized by up to
   4 hours, `Persistent=true`). Without systemd (Alpine with OpenRC, for example) it installs a
   cron entry at a random time of day instead;
7. runs the collector once and shows the result.

| Option | Meaning |
| --- | --- |
| `--url URL` | Smoke address (`https://` only). |
| `--token-file FILE` | Read the token from FILE. Without it, a reinstall or upgrade keeps the existing token. |
| `--version X.Y.Z` | Install that version instead of `LATEST`. |
| `--skip-signature` | Skip the signature check. The SHA-256 is still checked. Not recommended. |
| `--no-service` | Do not install the timer or cron entry. |
| `--no-run` | Do not run the collector at the end. |
| `--show-terms` | Print the installation terms and exit (no root needed; with `--containers`, the container collector's). |
| `--accept-terms` | Accept the installation terms without being asked (unattended installs). `--yes` is the same. |
| `--lang zh-TW\|en` | Language of the terms (default: from `LANG`, otherwise English). |
| `--uninstall` | Remove the binary, the configuration, the timer or cron entry, the terms record and the user. |
| `--verify-signature FILE SIG` | Only verify FILE against SIG with the embedded key (no root needed). |
| `--insecure-http` | Allow `http://localhost` (testing only). |

To upgrade, run the install command again. To uninstall:

```sh
curl -fsSL https://smoke.example.com/downloads/collector/install.sh | sudo sh -s -- --uninstall
```

### Verifying a release by hand

With [minisign](https://jedisct1.github.io/minisign/) and the public key from
`/downloads/collector/smoke-collector.pub`:

```sh
minisign -Vm SHA256SUMS -P <public key>
sha256sum -c --ignore-missing SHA256SUMS
```

## Commands

```text
smoke-collector run [--dry-run] [--config PATH] [--insecure-http]
smoke-collector print-config [--config PATH] [--insecure-http]
smoke-collector version
```

- `run` collects the inventory and uploads it (the timer runs this).
- `run --dry-run` prints the exact report and makes no network connection. It needs no
  configuration and works as any user.
- `print-config` shows the effective settings and where each came from. Only the first 8
  characters of the token are shown.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Uploaded (`created`), or Smoke already had the same list (`unchanged`) |
| 1 | Configuration error |
| 2 | Collecting the inventory failed |
| 3 | Smoke rejected the upload (4xx, not retried): bad token, wrong asset, malformed report, rate limit |
| 4 | Network or server error after 3 retries (exponential backoff, about 5 minutes at most) |

## Configuration

`/etc/smoke-collector/config`, `key=value`, `#` comments:

```ini
url=https://smoke.example.com
token=smk_...
# or, instead of token:
# token_file=/path/to/token
```

`SMOKE_COLLECTOR_URL` and `SMOKE_COLLECTOR_TOKEN` override the file. The URL must be `https://`.
`--insecure-http` allows `http://` only for `localhost`, `127.0.0.1` or `[::1]`, for tests.

## Upload

`POST <url>/api/v1/collector/report` with `Authorization: Bearer <token>`,
`Content-Type: text/plain; charset=utf-8`, `Content-Encoding: gzip`,
`User-Agent: smoke-collector/<version> (linux/<arch>)` and `X-Smoke-Collector-Version`.
Redirects are not followed, so the token cannot be forwarded anywhere else.

## Security notes

- The token is used only in the `Authorization` header. It is never logged and never appears in
  error messages. Text returned by the server is scrubbed of it before it is printed.
- The collector needs no root and no capability. To find service packages it reads `/proc`
  (cgroup, cmdline, and maps where the kernel allows it), the ELF headers of service programs
  and libraries (regular files of at most 256 MB, opened read-only and non-blocking) and the dpkg
  file lists (on rpm hosts it asks `rpm` instead). It executes none of those files.
- The systemd unit runs it as `smoke-collector` with
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, an
  empty capability set, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` (AF_UNIX lets
  `systemctl` reach D-Bus) and `SystemCallFilter=@system-service`. See
  [systemd/smoke-collector.service](systemd/smoke-collector.service).
- Releases are signed with minisign in legacy mode (`-S -l`), which is a plain Ed25519
  signature over `SHA256SUMS`. That lets `install.sh` check it with
  `openssl pkeyutl -verify -rawin`. The key's trusted comment is not checked by `install.sh`;
  `minisign -V` checks it.

## Development

Go 1.27, standard library plus `golang.org/x/sys`.

```sh
make test           # go test -race ./...
make lint           # go vet + golangci-lint
make build-linux    # bin/smoke-collector_linux_{amd64,arm64}, bin/smoke-container-collector_linux_{amd64,arm64}
make test-identity  # Docker: --dry-run vs the plan's shell commands on ubuntu:24.04, debian:12, alpine:3.21, rockylinux:9, almalinux:9, ubi9
make test-signing   # minisign -S -l + install.sh's openssl check, with a throwaway key (needs minisign, OpenSSL 3)
make test-install   # Docker: install.sh end to end against a fake Smoke (test/fakesmoke), cron path,
                    # including --containers against a fake Docker Engine socket
                    # (INSTALL_TEST_IMAGES="nginx:1.27:deb nginx:alpine:apk" to use other images)
make test-container-identity  # Docker: the container collector's #os-release/#packages vs the page
                    # command in the same container (local images only, --pull never;
                    # CONTAINER_IDENTITY_IMAGES to choose)
```

- `testdata/plan-commands/` holds the shell commands from plan §2.1 and §2.2, copied exactly
  (`rpm.sh` is the rpm branch of the asset page's command). `test-identity` runs them next to
  `--dry-run` as root and as an unprivileged user, with and without a pending reboot
  (`/var/run/reboot-required`, or a stand-in `needs-restarting`), and with a stand-in `systemctl`. It then parses every
  output with smoke-backend's `host-text.ts` if that checkout sits next to this one. Containers
  run no services, so there `#service-packages` is empty on both sides; the unit tests cover
  the analysis with a fake `/proc`, dpkg lists, a fake rpm and generated ELF files.
- `install.sh` contains copies of the units in `systemd/`. A Go test keeps them identical.

## Release

The signing key stays on the maintainer's machine. CI only lints, tests and builds.

One-time key generation:

```sh
minisign -G -p ~/.minisign/smoke-collector.pub -s ~/.minisign/smoke-collector.key
```

Each release:

```sh
SMOKE_REGISTRY=registry.example.com scripts/release.sh 0.1.0
```

This builds `smoke-collector` and `smoke-container-collector` for amd64 and arm64 with the
version stamped in, writes `SHA256SUMS`, and signs it with
`minisign -S -l` (minisign asks for the key password). It writes `install.sh` with the public key
in place of the placeholder, adds `LATEST` and `smoke-collector.pub`, builds
`$SMOKE_REGISTRY/smoke/smoke-collector/dist:<version>` from `Dockerfile.dist`, and pushes it.
The repository's own `install.sh` has no key and refuses to run without `--skip-signature`.

The image is busybox with the download tree under `/dist`, laid out like `/downloads/collector/`:

```text
/dist/install.sh
/dist/LATEST
/dist/smoke-collector.pub
/dist/v0.1.0/smoke-collector_linux_amd64
/dist/v0.1.0/smoke-collector_linux_arm64
/dist/v0.1.0/smoke-container-collector_linux_amd64   (from 0.2.0)
/dist/v0.1.0/smoke-container-collector_linux_arm64   (from 0.2.0)
/dist/v0.1.0/SHA256SUMS
/dist/v0.1.0/SHA256SUMS.minisig
```

On the App VM, a one-shot compose service copies it into the volume nginx serves:

```yaml
collector-dist:
  image: ${SMOKE_REGISTRY}/smoke/smoke-collector/dist:${SMOKE_COLLECTOR_TAG}
  volumes: [collector-downloads:/target]
  restart: "no"
```

## Container collector

`smoke-container-collector` reports the images of the running Docker containers and their
packages (spec FR-COL-08 to 12). It is a separate program on purpose: it needs the `docker`
group, and **an account in the docker group can control Docker, which is equivalent to root**.
Keeping it apart leaves `smoke-collector` unprivileged and lets each host decide whether to
install it.

```sh
curl -fsSL https://<smoke>/downloads/collector/install.sh | sudo sh -s -- --url https://<smoke> --containers
```

Its installation terms state the docker group privilege, and you accept them by typing `y`
(unattended: `--accept-terms`, or `--yes`; recorded in
`/etc/smoke-collector/containers.terms-accepted`; to use a filtering proxy socket instead of the
docker group, see `--docker-host` below). It then asks for the token created
with "Install container collector" on the host page (scope `containers:write`; it cannot write
the host's OS inventory). It creates the `smoke-container` user in the `docker` group,
`/usr/local/bin/smoke-container-collector`, `/etc/smoke-collector/containers.config` (0640
root:smoke-container; keys `url`, `token` or `token_file`, `docker_host`) and a daily
`smoke-container-collector.timer` (or cron entry). `--uninstall --containers` removes only the
container collector. With both installed, `/etc/smoke-collector` is mode 0751 so each user can
open its own file and neither can read the other's.

### What it reads and sends

It talks to the Docker Engine API over the unix socket (`docker_host`, default
`unix:///var/run/docker.sock`; `tcp://` is not accepted), API v1.41 (Docker 20.10 or later).
It sends **GET only, and only to these four paths**; any other request is refused inside the
program before it is sent ([internal/docker](internal/docker/docker.go), unit-tested):

| Request | Why |
| --- | --- |
| `GET /version` | the Engine is reachable and new enough |
| `GET /containers/json` | the running containers (ID, image, image ID are used) |
| `GET /images/sha256:<id>/json` | tags and repo digests of each image |
| `GET /containers/<id>/archive?path=<file>` | what `docker cp` reads, for the files below |

For each distinct image it reads, from one of its running containers, only `/etc/os-release`
(or `/usr/lib/os-release`; symbolic links are followed inside the container), and
`/var/lib/dpkg/status` plus `/var/lib/dpkg/status.d/` (distroless images) or
`/lib/apk/db/installed`, at most 16 MB each. `/var/lib/rpm` and `/usr/lib/sysimage/rpm` are only
checked for existence. These become the `#os-release` and `#packages` sections of the same
`#smoke-host 1` text the page command prints (`make test-container-identity` checks this byte
for byte). It never uses `exec`, never pulls, exports or starts anything, and runs no external
program.

| Sent | Read but not sent | Never read |
| --- | --- | --- |
| image reference (registry, repository, tag), image ID, repo digest, number of running containers; distribution and package list inside the image | container names, labels, ports, mounts and commands in the `/containers/json` response (used only to pick a container) | environment variables (container inspect is never called), volumes, logs, image layers, any other file |

Image statuses: `ok` (with the inventory), `untagged` (no name: not read), `unsupported` (rpm
database, or a distribution Smoke does not support), `no_packages` (no package database, or the
files could not be read; a warning says why), `skipped_limit` (more than 50 images: the ones
with the fewest containers are not read).

`POST <url>/api/v1/collector/containers` with `Content-Type:
application/vnd.smoke.container-report+json`, `Content-Encoding: gzip`, `User-Agent:
smoke-container-collector/<version> (linux/<arch>)`, a body like

```json
{"images":[{"reference":"nginx:1.27","imageId":"sha256:…","repoDigest":"sha256:…","containers":2,"status":"ok","inventory":"#smoke-host 1\n…"}]}
```

An empty list is still sent when nothing runs (Smoke then removes the deployment links).
`smoke-container-collector run --dry-run` prints exactly this body; exit codes are the same as
smoke-collector's (2: Docker not reachable).

### Narrowing Docker access further

If you do not want the account to reach the whole Docker API, put a filtering proxy in front of
the socket and point `docker_host` at the proxy's socket. For example with HAProxy (sketch):

```haproxy
frontend docker_ro
    mode http
    bind unix@/run/smoke-docker.sock mode 660 group smoke-container
    http-request deny unless METH_GET
    acl ok path -m reg ^/v1\.41/(version|containers/json|images/sha256:[0-9a-f]{64}/json|containers/[0-9a-f]{64}/archive)$
    http-request deny unless ok
    default_backend docker
backend docker
    mode http
    server engine /var/run/docker.sock
```

Then install with the proxy socket:

```sh
curl -fsSL https://<smoke>/downloads/collector/install.sh | sudo sh -s -- --url https://<smoke> \
  --containers --docker-host unix:///run/smoke-docker.sock
```

With `--docker-host`, `smoke-container` is **not** added to the `docker` group (an earlier
installation's membership is removed), `docker_host` is written to `containers.config`, and the
systemd unit has no `SupplementaryGroups=docker`. Give the account access to the proxy socket
yourself (above: the socket's group is `smoke-container`). Upgrades without `--docker-host` keep
the configured socket. The archive endpoint can still read any file of a running container, so
the proxy narrows what can be changed, not what can be read.

## License

Apache License 2.0. See [LICENSE](LICENSE).
