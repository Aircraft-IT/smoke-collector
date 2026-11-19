# smoke-collector

Host inventory collector for **Smoke**. Once a day it records which OS packages a Linux host
has installed (Ubuntu, Debian, Alpine, RHEL, Rocky Linux, AlmaLinux) and uploads that list to Smoke, which matches it against
distribution security advisories. It can also send the application lockfiles at paths that root
configures on the host (see [Lockfiles](#lockfiles)), and a separate program reports the running
Docker containers (see [Container collector](#container-collector)). It is a single static Go
binary that runs as an unprivileged user from a systemd timer (or cron) and exits when it is done.
It does not stay running, update itself or listen on any port.

## Source and releases

This repository is published at <https://github.com/aircraft-it/smoke-collector> when a version
is released: each release is a tag on `main` and a
[GitHub release](https://github.com/aircraft-it/smoke-collector/releases) with the binaries,
`SHA256SUMS` and its minisign signature. Development happens in Smoke's own repository, so
`main` here moves only at releases. This README describes what the collector reads and sends;
Smoke's design notes (the `#smoke-host 1` format, the upload API, installation and releases) are
not public.

Issues are welcome. Pull requests are not merged directly; a change we take is made in the
development repository and appears here with the next release. Contributions are under the
Apache License 2.0, like the rest of the repository.

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

On the host asset's page in Smoke, an Admin chooses **Install collector**, ticks what to scan
(OS packages, application lockfiles, Docker containers) and, for lockfiles, the paths. Smoke
creates a token for each program that is needed (shown once) and one install command:

```sh
curl -fsSL https://smoke.example.com/downloads/collector/install.sh | sudo sh -s -- --url https://smoke.example.com \
  --lang zh-TW --scan lockfiles,docker --lockfile /srv/billing/current
```

`--scan` takes any non-empty comma-separated subset of:

| Item | Program | What it sends |
| --- | --- | --- |
| `os` | `smoke-collector` | the OS package inventory (`#smoke-host 1`) |
| `lockfiles` | `smoke-collector` | the lockfiles at the `--lockfile` paths ([Lockfiles](#lockfiles)) |
| `docker` | `smoke-container-collector` | the running Docker images and their packages ([Container collector](#container-collector)) |

When `docker` and `os` or `lockfiles` are chosen, one run installs both programs (the download
and the signature check happen once). Without `--scan`, an existing installation keeps what it
scans (the run upgrades what is installed), a new installation asks item by item at the terminal
(OS packages yes, the others no), and a new installation without a terminal scans `os` as 0.2.x
did. `--scan` never uninstalls the other program: `--scan docker` leaves `smoke-collector` alone,
and `--scan os` leaves the container collector alone (remove it with `--uninstall --containers`).
With `os` or `lockfiles` in it, `--scan` replaces `smoke-collector`'s scan list, so
`--scan lockfiles` turns OS package scanning off.

`install.sh` (POSIX sh) then:

0. shows the installation terms for the chosen items only (what it installs, what it collects
   and sends, your responsibilities, the disclaimer) as one text, and continues only when you
   type `y` once; anything else leaves the host unchanged. The language follows
   `--lang zh-TW|en` (the asset page adds `--lang zh-TW` in Chinese), otherwise `LANG`. Each
   program writes its acceptance (version, `scans=`, time, how, `SUDO_USER`) to
   `/etc/smoke-collector/terms-accepted` or `containers.terms-accepted`. A later run asks again
   only when `TERMS_VERSION` in `install.sh` changes (0.3.0: `2026-11-13.2`, which adds the
   lockfile section; 0.4.0: `2026-11-15.1`, which adds the image labels the container collector
   sends; each time every host is asked once more) or an item is chosen that the record does
   not cover. Without a terminal, read them with `--show-terms --scan LIST` and accept with
   `--accept-terms`;
1. downloads `LATEST`, the binaries for the host architecture (`amd64` or `arm64`), `SHA256SUMS`
   and `SHA256SUMS.minisig`;
2. verifies the minisign signature of `SHA256SUMS` with `openssl` (OpenSSL 3; Alpine:
   `apk add openssl`), so minisign is not needed on the host;
3. checks each binary's SHA-256;
4. asks for the tokens on the terminal with echo off, `smoke-collector`'s first, then the
   container collector's; each prompt names its program. A token is never accepted as a
   command-line argument. For unattended installs use `--token-file FILE` (smoke-collector) and
   `--containers-token-file FILE`. A program that is already installed keeps its token and is not
   asked, unless `--replace-token` is given ([Replacing a token](#replacing-a-token));
5. creates the `smoke-collector` system user, installs `/usr/local/bin/smoke-collector`, and
   writes `/etc/smoke-collector/config` with mode `0640 root:smoke-collector`, including `scan=`
   and the `lockfile=` lines. With lockfiles it checks, as `smoke-collector`, that each path can
   be read and prints a `setfacl` example when not (it never changes permissions);
6. installs `smoke-collector.service` and `smoke-collector.timer` (daily, randomized by up to
   4 hours, `Persistent=true`), plus the [lockfile drop-in](#paths-under-home) when needed.
   Without systemd (Alpine with OpenRC, for example) it installs a cron entry at a random time of
   day instead;
7. runs each program once and shows the result.

| Option | Meaning |
| --- | --- |
| `--url URL` | Smoke address (`https://` only). |
| `--scan LIST` | What to scan: `os`, `lockfiles`, `docker` (see above). |
| `--lockfile PATH` | With `lockfiles`: an absolute directory or lockfile path. Repeatable, at most 50; letters, digits and `. _ - / @ +` only (edit the configuration by hand for others). The paths given replace the configured ones; `--lockfile none` clears them. Without it, an upgrade keeps the configured paths. With `lockfiles` and no path at all, `install.sh` asks at the terminal, or stops without one. |
| `--token-file FILE` | Read `smoke-collector`'s token from FILE (with only `docker` chosen: the container collector's). Without it, a reinstall or upgrade keeps the existing token. |
| `--containers-token-file FILE` | Read the container collector's token from FILE. |
| `--replace-token` | (0.3.1+) Replace the token of each program this run installs that already has one: ask for the new token at the terminal (or read it from the token file). Smoke revokes the program's older token on this host after the new one's first successful report. |
| `--containers` | The same as `--scan docker`. |
| `--docker-host unix:///PATH` | With `docker`: see [Narrowing Docker access further](#narrowing-docker-access-further). |
| `--version X.Y.Z` | Install that version instead of `LATEST`. |
| `--skip-signature` | Skip the signature check. The SHA-256 is still checked. Not recommended. |
| `--no-service` | Do not install the timers or cron entries. |
| `--no-run` | Do not run the programs at the end. |
| `--show-terms` | Print the installation terms for `--scan` (default `os`) and exit (no root needed). |
| `--accept-terms` | Accept the installation terms without being asked (unattended installs). `--yes` is the same. |
| `--lang zh-TW\|en` | Language of the terms (default: from `LANG`, otherwise English). |
| `--uninstall` | Remove `smoke-collector`: the binary, the configuration, the timer or cron entry, the lockfile drop-in, the terms record and the user. With `--containers` (or `--scan docker`): the container collector; with `--scan os,docker`: both. |
| `--verify-signature FILE SIG` | Only verify FILE against SIG with the embedded key (no root needed). |
| `--insecure-http` | Allow `http://localhost` (testing only). |

`install.sh` exits 1 when it stops before installing; otherwise with 0 when every first run
succeeded, or the exit code of the first failing first run (`smoke-collector`'s first).

To upgrade, run the install command again (without `--scan` it keeps what the host scans). To
uninstall:

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

### Which source a binary was built from

Every binary records the commit it was built from and the Go version (from 0.4.1 that commit is
the release tag on GitHub):

```sh
go version -m smoke-collector_linux_amd64
# smoke-collector_linux_amd64: go1.27.3
#   build  vcs.revision=<commit of tag v<version>>
#   build  vcs.modified=false
```

`SHA256SUMS` is signed, so a matching checksum ties the file you run to that commit. To check it
yourself, rebuild the release from a clean clone with the same Go version and compare:

```sh
git clone https://github.com/aircraft-it/smoke-collector && cd smoke-collector
git checkout v0.4.1
GOTOOLCHAIN=go1.27.3 scripts/reproduce.sh 0.4.1 /path/to/SHA256SUMS
```

`reproduce.sh` builds with the same commands as the release (`scripts/build.sh`) and reports
`match` for each of the four binaries, or which ones differ.

### Versions before 0.4.1

0.1.0 to 0.4.0 were built before the repository was published. Its history was then rewritten
once to drop tool-generated lines from commit messages; the source of every commit is unchanged,
but the commit ids changed. The binaries of these versions therefore record the old commit
(`vcs.revision`), which is not in the public history, and cannot be rebuilt bit for bit from it.
The tags here hold the same source:

| Version | Commit recorded in the binaries | Tag on GitHub |
| --- | --- | --- |
| 0.1.0 | `9c3ba51ab992756683bccbe31c5a6066d26c1f85` | `e1c6c7ea18ec3ccb8ae4976446b886dc3e3acffb` |
| 0.2.0 | `3b509e90cc5cd27412119b42796054c1357aabba` | `a56d635935c5a0b88099585c9a1b5749ca7c9a18` |
| 0.2.1 | `af50cb8dfe60cc80a4110b53fad4db7693132da3` | `e3fbf396a5d02f903bc93d0814ee2f674acbdd2d` |
| 0.3.0 | `c9ddfc417e4ca62b4b0e3a2330e4ac98ca29ee07` | `6c19bbe49fcebaca1a8d2360223b55aa34783879` |
| 0.3.1 | `9355d6c6b839969c7d1d2db182dce2ef7dc50b60` | `bf3b62ec8c0ae312d794c2d17443d88636ca4c37` |
| 0.4.0 | `7d933b6dbba53212c4a03a4f627157655b36e480` | `bb812f38dd82b291936a7a05886d5c8c71a531c1` |

### Replacing a token

To give a host a new token (the old one leaked, is about to expire, or the host was rebuilt),
choose **Install collector** on the host page again and tick **Replace token**: Smoke creates a
new token for each program and adds `--replace-token` to the command, so `install.sh` asks for
the new token even though one is configured. Without the tick, the command keeps the host's token
and Smoke creates none (`--replace-token` needs 0.3.1; with an older `install.sh`, edit the
configuration by hand as below). After the new token's first successful report, Smoke revokes the
program's older collector tokens of that host (audited as `api_token.revoked`); tokens created
later than the one reporting, and `smoke-collector`'s tokens renamed by hand, are left alone.
By hand: edit `token=` in `/etc/smoke-collector/config` (or `containers.config`) with `sudoedit`.

## Commands

```text
smoke-collector run [--dry-run] [--config PATH] [--insecure-http]
smoke-collector print-config [--config PATH] [--insecure-http]
smoke-collector version
```

- `run` collects what `scan` lists and uploads it (the timer runs this): with `os` the OS
  report (`POST /api/v1/collector/report`), then with `lockfiles` the lockfile report
  (`POST /api/v1/collector/lockfiles`). With only `lockfiles`, no OS inventory is collected or
  sent.
- `run --dry-run` prints what would be sent and makes no network connection: the exact OS report,
  then for each lockfile path its status and every file's name, size and SHA-256 (with the
  path's `lockfile_digest`), followed by the full contents of each file. It needs no `url` or
  token and works as any user; it reads the configuration only for `scan` and the paths (when it
  cannot read the file, it says so and shows the OS report).
- `print-config` shows the effective settings and where each came from, including `scan` and the
  lockfile paths. Only the first 8 characters of the token are shown.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every report was uploaded (`created`, or Smoke already had it: `unchanged`) |
| 1 | Configuration error (nothing is collected or sent) |
| 2 | Collecting the OS inventory failed |
| 3 | Smoke rejected an upload (4xx, not retried): bad token, wrong asset, malformed report, rate limit; for lockfiles also 404 from a Smoke without the lockfile endpoint |
| 4 | Network or server error after 3 retries (exponential backoff, about 5 minutes at most) |

With `scan=os,lockfiles` both parts always run, the OS report first: a failure of one does not
stop the other (the lockfile report is still sent when the OS inventory cannot be collected, and
the other way round). The exit code is that of the first part that failed:

| OS report | Lockfile report | Exit code |
| --- | --- | --- |
| ok | ok | 0 |
| 2, 3 or 4 | ok | the OS report's code |
| ok | 3 or 4 | the lockfile report's code |
| 2, 3 or 4 | 3 or 4 | the OS report's code |

A lockfile path that cannot be read is not a failure: it is sent with its status (below) and a
warning is printed.

## Configuration

`/etc/smoke-collector/config`, `key=value`, `#` comments:

```ini
url=https://smoke.example.com
token=smk_...
# or, instead of token:
# token_file=/path/to/token
scan=os,lockfiles
lockfile=/srv/billing/current
lockfile=/home/app/shop/package-lock.json
```

| Key | Meaning |
| --- | --- |
| `url` | The Smoke address. |
| `token` / `token_file` | The asset token, or a file holding it (one of the two). |
| `scan` | Comma-separated subset of `os`, `lockfiles`, non-empty; not repeatable. Missing means `os` (0.2.x configurations keep working). `docker` is refused: the container collector scans Docker. |
| `lockfile` | Repeatable, at most 200; only the first 50 are read in one run, the others are sent as `over_limit` (path only) so Smoke can show them. An absolute, clean path (a trailing `/` is removed; no `//`, `.` or `..`; at most 512 bytes; no control characters); the same path twice is an error. Required (at least one) when `scan` includes `lockfiles`; ignored with a warning otherwise. |

`SMOKE_COLLECTOR_URL` and `SMOKE_COLLECTOR_TOKEN` override the file (there are no variables for
`scan` or `lockfile`). The URL must be `https://`. `--insecure-http` allows `http://` only for
`localhost`, `127.0.0.1` or `[::1]`, for tests.

## Upload

`POST <url>/api/v1/collector/report` with `Authorization: Bearer <token>`,
`Content-Type: text/plain; charset=utf-8`, `Content-Encoding: gzip`,
`User-Agent: smoke-collector/<version> (linux/<arch>)`, `X-Smoke-Collector-Version` and
`X-Smoke-Collector-Scans` (the `scan` list, for example `os,lockfiles`; also sent with the lockfile
report, so Smoke knows a host that sends only lockfiles is not stale). The lockfile report is
described [below](#lockfiles). Redirects are not followed, so the token cannot be forwarded
anywhere else.

## Lockfiles

With `lockfiles` in `scan`, `smoke-collector` reads the application lockfiles at the `lockfile=`
paths and sends them to Smoke, so Smoke knows which dependency versions are deployed on the host
(plan §4b). The paths are set on the host by root (`install.sh --lockfile`); Smoke cannot ask the
collector to read anything else.

Each path is either

- a **directory**: only the supported file names directly inside it are read. Nothing else in it
  is opened (`.env`, source code, `node_modules`), and subdirectories are not searched; or
- a **file** whose name is supported.

Supported names: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`,
`composer.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`,
`gradle.lockfile`, `packages.lock.json`, `pubspec.lock`, and requirements files matching
`^(?:requirements(?:[-_.][\w.-]+)?|[\w.-]+[-_.]requirements)\.txt$` (case-insensitive; the same
rule as Smoke). Not `package.json` (only version ranges) and not SBOMs.

Symbolic links are followed (a Capistrano `/srv/app/current` works). Files are opened read-only
and non-blocking and must be regular files. Limits: 20 MB per file, at most 20 files per path, and
50 MB for the whole report as sent (JSON, before gzip); a path over a limit is reported as
`too_large` without its files. Invalid UTF-8 bytes are sent as U+FFFD (with a warning); sizes and
SHA-256 are those of what is sent, which is what Smoke hashes.

Each path gets a status:

| Status | Meaning |
| --- | --- |
| `ok` | The files are sent (`files`: name and full content). |
| `not_found` | The path does not exist (or a parent is a file). |
| `unreadable` | Permission denied (on the path, or on one of its lockfiles), or not a regular file or directory. |
| `no_lockfile` | A directory without a supported name, or a file whose name is not supported. |
| `too_large` | Over a size or file-count limit. |
| `over_limit` | After the first 50 `lockfile` lines: not read, only the path is sent, so Smoke can list it on the host page. |

`POST <url>/api/v1/collector/lockfiles` with the same headers as the OS report, except
`Content-Type: application/vnd.smoke.lockfile-report+json` (Smoke checks the token before it
parses the body), and a body like

```json
{"lockfiles":[{"path":"/srv/billing/current","status":"ok","files":[{"name":"package-lock.json","content":"…"}]},{"path":"/home/app/shop","status":"unreadable"}]}
```

Smoke answers per path with a `result` (`created`, `unchanged`, `older_version`,
`source_preferred`, `unmapped`, `archived`, `failed`, `skipped`), which `run` prints. A path is
written only to the asset an Admin linked to this host with that path; unlinked paths are listed
on the host page. Smoke strips credentials in URLs inside lockfiles and deletes the originals
within 24 hours.

### Permissions

The collector reads with the `smoke-collector` account's permissions. `install.sh` checks each
path as that account (including search permission on the parent directories) and, when it cannot
read one, prints a `setfacl` example such as
`setfacl -m u:smoke-collector:rX /srv/app/current`. It never changes permissions itself.

### Paths under /home

The unit has `ProtectHome=yes`, which hides `/home`, `/root` and `/run/user` (`ProtectSystem=strict`
only makes the file system read-only; `/srv`, `/var/www` and `/opt` stay readable). For lockfile
paths under those directories (or symbolic links that lead there), `install.sh` writes
`/etc/systemd/system/smoke-collector.service.d/lockfiles.conf`:

```ini
[Service]
ProtectHome=tmpfs
BindReadOnlyPaths=-/home/app/shop
```

so only those paths are visible to the service, read-only (`-`: a missing path does not stop the
service; it is reported as `not_found`). The drop-in is removed when no such path is configured
and by `--uninstall`. Cron hosts have no sandbox; only the account's permissions apply.

## Security notes

- The token is used only in the `Authorization` header. It is never logged and never appears in
  error messages. Text returned by the server is scrubbed of it before it is printed.
- The collector needs no root and no capability. To find service packages it reads `/proc`
  (cgroup, cmdline, and maps where the kernel allows it), the ELF headers of service programs
  and libraries (regular files of at most 256 MB, opened read-only and non-blocking) and the dpkg
  file lists (on rpm hosts it asks `rpm` instead). It executes none of those files.
- With lockfiles, it opens only the configured paths and the supported names directly inside
  them, and sends only those files. The paths come from the host's configuration, never from
  Smoke.
- The systemd unit runs it as `smoke-collector` with
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome` (relaxed only by the lockfile
  drop-in above), `PrivateTmp`, `PrivateDevices`, an
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
                    # including --containers against a fake Docker Engine socket, --scan and
                    # lockfiles, and the systemd drop-in with a stand-in systemctl
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

Each release, from a clean checkout of the commit to release (the Go version you build with is
recorded in the binaries and in the release notes):

```sh
git tag -a v0.4.1 -m "smoke-collector 0.4.1: <summary>"   # first: Go records it in the binaries
SMOKE_REGISTRY=registry.example.com scripts/release.sh 0.4.1
git push origin main v0.4.1                  # the development repository
scripts/publish-github.sh 0.4.1 --dry-run    # checks, prints the release notes
scripts/publish-github.sh 0.4.1              # GitHub: main, the tag and the release
```

`publish-github.sh` first checks that the files match the signed `SHA256SUMS` and that every
binary records the tag's commit with no local changes; then it pushes that commit to GitHub's
`main` (fast-forward only) with the tag, and creates the GitHub release with the binaries,
`SHA256SUMS`, `SHA256SUMS.minisig`, `install.sh` and `smoke-collector.pub`. It needs `gh` logged in
to an account that can write to the repository (`GITHUB_REPO`, default
`Aircraft-IT/smoke-collector`). Commit messages here are published as they are.

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
/dist/v0.3.0/smoke-collector_linux_amd64
/dist/v0.3.0/smoke-collector_linux_arm64
/dist/v0.3.0/smoke-container-collector_linux_amd64   (from 0.2.0)
/dist/v0.3.0/smoke-container-collector_linux_arm64   (from 0.2.0)
/dist/v0.3.0/SHA256SUMS
/dist/v0.3.0/SHA256SUMS.minisig
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
curl -fsSL https://<smoke>/downloads/collector/install.sh | sudo sh -s -- --url https://<smoke> --scan docker
```

(`--containers` is the same as `--scan docker`; `--scan os,docker` installs both programs in one
run.) Its installation terms state the docker group privilege, and you accept them by typing `y`
(unattended: `--accept-terms`, or `--yes`; recorded in
`/etc/smoke-collector/containers.terms-accepted` with `scans=docker`; to use a filtering proxy
socket instead of the docker group, see `--docker-host` below). It then asks for the container
collector's token created by "Install collector" on the host page (scope `containers:write`; it
cannot write the host's OS inventory; unattended: `--containers-token-file`, or `--token-file`
when only `docker` is chosen). It creates the `smoke-container` user in the `docker` group,
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
| `GET /images/sha256:<id>/json` | tags, repo digests and four standard labels of each image |
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
| image reference (registry, repository, tag), image ID, repo digest, number of running containers; distribution and package list inside the image; the image labels `org.opencontainers.image.source`, `.title`, `.version` and `.base.name` (0.4.0+, printable ASCII up to 256 bytes each) | container names, labels, ports, mounts and commands in the `/containers/json` response (used only to pick a container); every other image label and the rest of the image configuration | environment variables (container inspect is never called), volumes, logs, image layers, any other file |

Image statuses: `ok` (with the inventory), `untagged` (no name: not read), `unsupported` (rpm
database, or a distribution Smoke does not support), `no_packages` (no package database, or the
files could not be read; a warning says why), `skipped_limit` (more than 50 images: the ones
with the fewest containers are not read).

`POST <url>/api/v1/collector/containers` with `Content-Type:
application/vnd.smoke.container-report+json`, `Content-Encoding: gzip`, `User-Agent:
smoke-container-collector/<version> (linux/<arch>)`, a body like

```json
{"images":[{"reference":"gotenberg/gotenberg:8","imageId":"sha256:…","repoDigest":"sha256:…","containers":2,"status":"ok","inventory":"#smoke-host 1\n…","labels":{"org.opencontainers.image.source":"https://github.com/gotenberg/gotenberg","org.opencontainers.image.version":"8.34.0"}}]}
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
