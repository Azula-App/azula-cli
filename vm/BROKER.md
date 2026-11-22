# azula remote compute: broker, grants and client

Companion to `vm/README.md` (frames §1, guest protocol §2, helper §3, bundles §4).
This file covers the Rust side in `src/compute/`. Merge into README when stable.

## 5. Client ↔ broker (iroh ALPN `azula/compute/1`)

One iroh connection per request; the client opens one bi-stream and speaks
§1 frames. Compute connections (both ends) use a 2 s QUIC keep-alive and a
10 s idle timeout, so a peer that vanishes without closing (SIGKILL, a torn-down
sandbox, a sleeping Mac) is noticed within ~10 s.

1. → `{"t":"hello","v":1,"grant":"<grant id>","secret":"<base64url>","client":"azula/<version>"}`
2. ← `{"t":"welcome","v":1,"host":"<hostname>","broker":"azula/<version>","grant":"<id>","expires":<unix>,"ops":["exec","vm"],"vms":["build","ci-*"],"features":["jobs","files"]}`
   or ← `{"t":"error","code":"unauthorized|unsupported_version|bad_request","msg":"…"}` and close.
   Unknown, expired and revoked grants all get the same `unauthorized` reply.
3. → exactly one request:
   - `{"t":"ping"}` → ← `{"t":"pong","broker":"azula/<version>","host":"<hostname>"}`.
   - `{"t":"vm","op":"list|status|start|stop","vm":"<name>","force":false}` → ← `{"t":"vm_status","vms":[VmInfo…]}`.
     `list`/`status` need any grant that covers the VM(s) (list filters to the grant's scope).
     `start`/`stop` need op `vm`. `start` replies once the worker answers a ping (deadline
     180 s). If the helper fails or the worker never answers, the broker stops the VM and
     replies `error` `vm_start_failed`, with the helper's error and the last 40 console lines.
     `stop` replies once the helper reports `stopped`. If the worker reports running jobs (any
     owner), `stop` replies `error` `vm_busy` with the count, unless `"force":true` is sent and
     the grant has op `vm` (then the jobs end as `interrupted`).
   - `{"t":"guest_ping","vm":"<name>"}` → ← the guest's `pong` frame verbatim (for `doctor --vm`).
   - Job and file requests, §2.3–2.8 frames plus `"vm":"<name>"` and `"start":true|false`:
     `exec`, `attach`, `jobs`, `cancel_job`, `put`, `get`. All need op `exec` and the VM in
     scope. If the VM isn't running: with `"start":true` and op `vm` in the grant, start it as
     above; otherwise ← `error` `vm_not_running`. The broker then:
     - **sets `owner`** to the authenticated grant id, overwriting anything the client sent.
       For `jobs`, `cancel_job` and `attach` from a grant with op `admin` and `"all":true`, it sets
       `"owner":"*"` (the CLI exposes this as `jobs --all` and `cancel --all`);
     - **clamps `exec.timeout_s`** so the job ends no later than the grant expires; if the grant
       has under 60 s left, it replies `error` `grant_expiring`;
     - waits for the worker (ping, ≤ 30 s), connects to the VM's `vsock.sock` once, forwards the
       frame without `vm`/`start`/`all`, and splices bytes both ways until either side closes.
       It never parses job output or file data.
   A client's disconnect closes its guest connection; whether that cancels a job is the
   worker's rule (§2.3), not the broker's.

`VmInfo` = `{"name","state":"stopped|starting|running|stopping|failed","worker":"ready|unreachable|unknown","image","cpus","memory_mb","disk_gb","network","jobs_running","disk_free_mb","worker_info":<guest pong or null>,"error":<last start failure or null>}`.

Error codes: `unauthorized`, `forbidden` (grant doesn't allow the op or VM), `bad_request`,
`unknown_vm`, `vm_not_running`, `vm_start_failed`, `vm_busy`, `grant_expiring`,
`worker_unreachable`, `host_busy` (memory budget, see §8), `internal`.

**Live revocation and expiry.** The broker keeps every live connection indexed by grant. It
re-reads `grants.json` whenever its mtime changes (checked every 2 s) and at each grant's
expiry time, and closes the live connections of a revoked or expired grant with QUIC close
reason `revoked` / `expired`. Their jobs keep running (bounded by the clamped timeout) unless
the revocation asked for `--cancel-jobs`, in which case the broker sends `cancel_job` for each
of that grant's running jobs on every running VM.

The broker logs one line per request to stderr: time, grant id, peer endpoint id (short),
request type, VM, job id if any, outcome. Never the secret, never file contents.

## 6. Grants

Store: `~/.azula/compute/grants.json`, mode 0600, written atomically (temp + rename).

```json
{"grants":[{"id":"g_3f9a1c2b7d4e","label":"claude-code","secret_sha256":"<hex>",
  "created":1795300000,"expires":1795904800,"ops":["exec","vm"],"vms":["*"],
  "revoked":null,"last_used":null,"last_peer":null}]}
```

Token: `azc1.` + base64url-no-pad of
`{"v":1,"host":"<endpoint id>","relay":"<relay url>","grant":"<id>","secret":"<base64url 32 bytes>"}`.
The secret comes from the OS CSPRNG and is printed exactly once. Checks compare SHA-256 digests
in constant time.

Host identity: a persisted iroh secret key dedicated to compute (`~/.azula/compute/host.key`,
0600), never the machine or session keys. `compute serve` writes `~/.azula/compute/host.json`
(`{"endpoint_id","relay_url","updated"}`) once online and holds an exclusive lock on
`~/.azula/compute/serve.lock` while running. `compute grant` takes the relay URL from
`host.json`. If it's missing and no serve holds the lock, grant binds the host key briefly to
learn its home relay. It must never bind the host key while serve is running, because the relay
would drop serve's connection.

Ops: `exec` (jobs and files), `vm` (start/stop, auto-start), `admin` (see and cancel every
owner's jobs, force-stop). `vms` entries are names or `*` globs. A grant is the principal: jobs
and uploads belong to the grant that created them, and only that grant (or an admin grant)
can attach to, list or cancel them. Two sandboxes that share a token share a principal; mint
one grant per session to keep them apart and to make `last_used`/`last_peer` and the broker log
attribute work correctly.

## 7. CLI

Host verbs (Apple silicon macOS only; elsewhere they exit 2 with "compute hosting requires
Apple silicon macOS"):

- `azula compute serve [--allow-sleep]` — foreground broker. Banner: endpoint id, relay URL,
  VM dir. A second instance fails at once ("already running, pid N"; `serve.lock`). While any
  VM it started is running, it holds an idle-sleep assertion (`caffeinate -i -w <pid>`) unless
  `--allow-sleep`. Closing the lid still sleeps the Mac. On SIGINT/SIGTERM it stops every VM it
  started (helper `stop`, 30 s grace; running jobs become `interrupted`) before exiting.
- `azula compute grant [--ttl 7d] [--vm NAME|GLOB]… [--ops exec,vm,admin] [--label TEXT] [--json]`
  — prints the token once on stdout, plus a one-line `export AZULA_COMPUTE_TOKEN=…` hint.
  `--vm` accepts `*` globs (`ci-*`); default `*`. Default ops `exec,vm`. One grant per cloud
  session/agent is the recommended pattern: the grant is the principal that owns jobs.
- `azula compute grants [--json]`, `azula compute revoke <grant-id> [--cancel-jobs]`.
- `azula vm create <name> [--image debian-13] [--cpus 4] [--memory 4096] [--disk-gb 32]
  [--network nat|none]`, `azula vm list [--json]`, `azula vm delete <name>` (refuses while the
  VM is running). `create` refuses if the host volume has less free space than the image size
  plus 10 GiB.

Client verbs (any OS). Token from `--token`, else `AZULA_COMPUTE_TOKEN`. VM: `--vm NAME`, else
`AZULA_COMPUTE_VM`, else the grant's VM when its scope is exactly one plain name, else
`default`. A job is named `<vm>/<job id>`; verbs that take one also accept a bare id with `--vm`.

- `azula compute exec [--vm NAME] [--no-start] [--cwd DIR] [--env K=V]… [--stdin]
  [--timeout 15m] [--detach] [--cancel-on-disconnect] [--reconnect 5m] [--label TEXT] [--quiet]
  [--json] -- ARGV…`
  - Generates a fresh `idem` key, prints `azula: job build/j_… started` to stderr (unless
    `--quiet`), streams stdout/stderr to the local stdout/stderr, and exits with the job's code.
  - `--detach` prints the job ref on stdout and exits 0 as soon as the job has started.
  - **Reconnect**: if the connection drops, the client retries with backoff (1 s doubling to
    15 s) for up to `--reconnect` (default 5m, `0` disables). If it never got `started`, it
    resends the same exec, and the `idem` key makes that safe. Otherwise it attaches with the
    offsets it has already written, so output is neither repeated nor lost. It prints
    `azula: connection lost, reattaching to build/j_…` once per outage. A `gap` frame prints
    `azula: N bytes of stdout were dropped by the host's retention limit`.
  - If reconnecting gives up: exit 255 with
    `azula: lost the connection; build/j_… is still running on the host — reattach with: azula compute attach build/j_…`.
  - First SIGINT sends `cancel` and waits for `exit`; a second SIGINT detaches, prints the job
    ref, and exits 130.
  - `--json` writes JSONL events to stdout: `{"type":"started","job","pid","deduped"}`,
    `{"type":"stdout"|"stderr","off","data_b64"}`, `{"type":"gap","stream","from","to"}`,
    `{"type":"reconnecting","attempt"}`, `{"type":"exit","code","signal","reason"}`,
    `{"type":"error","code","msg"}`.
- `azula compute attach <ref> [--json]` — replay from the start and follow to the end; exits
  with the job's code. Same reconnect behavior as exec.
- `azula compute logs <ref> [--follow] [--tail N] [--stdout-only|--stderr-only] [--json]`:
  without `--follow`, print what's retained and exit 0. `--tail N` prints only the last N lines
  (it fetches from max(0, len − 256 KiB) and trims locally).
- `azula compute jobs [--all] [--json]` — this grant's jobs on the VM (`--all`: every owner,
  admin grants only), newest first: ref, state/reason, exit code, age, label, argv.
- `azula compute cancel <ref>`.
- `azula compute push [--vm NAME] [-r] [--mode 0644] [--no-clobber] [--json] LOCAL REMOTE` and
  `azula compute pull [--vm NAME] [-r] [--json] REMOTE LOCAL` — copy between this machine and
  the VM's filesystem. Nothing on the Mac host itself is reachable.
  - REMOTE is a guest path, absolute or relative to the job user's home. A REMOTE (push) or
    LOCAL (pull) that ends in `/` or names an existing directory gets the source's basename
    appended. LOCAL may be `-` for stdin/stdout (not resumable).
  - Single files use §2.7/2.8: streaming SHA-256 at both ends, size and digest checked before
    an atomic rename, mode preserved (push sends the local mode unless `--mode`).
  - Resume: within one invocation, a dropped transfer resumes from the last acknowledged offset
    (same reconnect window as exec). Across invocations, the client keeps
    `~/.azula/compute/transfers.json` (host, vm, local path, size, mtime, remote path → upload id
    / etag). Rerunning the same push or pull resumes, unless the local or remote file changed,
    in which case it restarts from 0. pull keeps `.<name>.azula-<id>.part` next to its
    destination until it completes.
  - `-r` copies a directory tree by streaming tar through exec. push builds the archive locally
    and runs `tar -x -C DIR` in the guest. pull runs `tar -c -C DIR .` in the guest and
    extracts **defensively**: it rejects absolute paths, `..`, links that point outside LOCAL,
    entries under a symlinked parent, and device/FIFO entries. `-r` rides out a dropped
    connection through the job's reattach-with-offsets (the tar stream continues; the pull side
    extracts only after the whole archive arrived and tar exited 0). It fails if either tar fails.
  - Progress and the result (`pushed 1.2 MiB → /home/azula/out/app.tgz sha256 3f9a…`) go to
    stderr; `--json` prints `{"path","size","sha256","resumed_from"}` to stdout.
- `azula compute doctor [--vm NAME] [--json]` — stages, each with its own deadline: `token`
  (parse), `bind` + `relay` (one bind that must reach the relay within 20 s; a relay failure
  reports `bind` passed and `relay` failed), `dial` (20 s), `auth` (hello→welcome, 10 s),
  `broker` (ping), and with `--vm` `guest` (guest_ping, 30 s; reports jobs running and guest
  disk free). Prints ✓/✗ per stage, the relay URL, and for failures a hint (allowlist the
  relay host and `dns.iroh.link`, check `HTTPS_PROXY`, try `AZULA_RELAY_ONLY=1`, is
  `compute serve` running and the Mac awake?, is the grant revoked/expired?, does the token's
  host id match `azula compute grants` on the Mac?).
- `azula vm start|stop|status [NAME] [--force] [--json]` via the broker.

**Testing.** `AZULA_COMPUTE_FAULT=drop-after:<N>` (deliberately not in `--help`) makes a client
abruptly drop its connection once per process, after it has written N bytes of job output (or
transferred N payload bytes for push/pull), then follow its normal reconnect path. It proves
reconnect against a real host.

Client verbs log at `warn` unless `RUST_LOG` is set, so an agent capturing stderr sees only
azula's own messages and the job's stderr.

Client exit codes:
- exec/attach: the job's exit code; `128+N` when the job died of signal N; `124` timeout;
  `127` `spawn_failed`; `126` `cwd_missing`; `130` cancelled (local SIGINT, or `cancel` from
  anyone); `125` any broker error (`unauthorized`, `forbidden`, `vm_not_running`, `busy`,
  `host_busy`, …); `255` transport failure, or a job that ended as `interrupted`,
  `stdin_lost` or `orphaned` (the message says which).
- push/pull: `0` on success; `1` for a file error from either end (`not_found`,
  `not_a_file`, `exists`, `is_a_directory`, `not_a_directory`, `changed` after retries,
  `size_mismatch`, `digest_mismatch`, `io_error`); `125` broker errors; `255` transport
  failure after the reconnect window.
- logs/jobs/cancel/doctor/vm: `0`, `1` (`not_found`, a doctor stage failed), `125`, `255`.
- Error messages go to stderr prefixed `azula:`.

## 8. VM manager (inside `compute serve`)

- Bundles per README §4 under `~/.azula/vm` (`AZULA_VM_DIR` overrides it, for tests; the host key,
  grants and `host.json` live under `~/.azula/compute`, overridable with `AZULA_COMPUTE_DIR`).
- Helper binary: `$AZULA_VM_HELPER`, else `azula-vm` next to the current executable, else on
  `PATH`. Guest binary: `$AZULA_GUEST_BIN`, else `azula-guest.linux-aarch64` next to the current
  executable. At serve start the broker copies the guest binary (atomically) into
  `~/.azula/vm/share/azula-guest` (only the binary: the systemd unit comes from cloud-init).
- Memory budget: a start is refused with `host_busy` if the running VMs' `memory_mb` plus the
  new VM's would exceed the host's RAM minus 4 GiB. `--network none` VMs get no network device
  (helper config `"network":"none"`).
- Sleep: while ≥ 1 VM it started is running, serve keeps a `caffeinate -i -w <serve pid>` child
  (dropped when the last VM stops), unless `--allow-sleep`.
- Start: spawn `azula-vm run --config <vm>/vm.json` with piped stdin/stdout, track state from
  its events, and poll the worker (connect `vsock.sock` + `ping`, every 1 s) until ready. The
  helper's stdin stays open for the VM's lifetime; dropping it stops the VM.
- Images: `debian-13` = `https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-arm64.tar.xz`,
  verified against `SHA512SUMS` from the same directory (HTTPS), extracted with `tar -xJf` to
  `images/debian-13-generic-arm64/disk.raw` (the image id `debian-13` maps to the directory name its
  archive extracts under; `--image` takes the id). Downloaded on first `vm create` if absent.
- Create: `clonefile` (or `cp -c`) the image to `disk.img`, `set_len` to `--disk-gb`, run
  `azula-vm init --efi-vars <vm>/efi.vars` for machine id + MAC, write `seed.iso` with
  `hdiutil makehybrid -iso -joliet -default-volume-name cidata`, and write `vm.json`.
- Seed `meta-data`: `instance-id: <uuid>`, `local-hostname: <name>`. `user-data`:

```yaml
#cloud-config
hostname: <name>
users:
  - name: azula
    gecos: azula job user
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
ssh_pwauth: false
mounts:
  - [azula, /mnt/azula, virtiofs, "ro,nofail", "0", "0"]
write_files:
  - path: /etc/systemd/system/azula-guest.service
    content: |
      [Unit]
      Description=azula guest worker
      After=mnt-azula.mount
      RequiresMountsFor=/mnt/azula
      [Service]
      ExecStart=/mnt/azula/azula-guest --vsock-port 1024 --run-as azula
      Restart=always
      RestartSec=1
      [Install]
      WantedBy=multi-user.target
  - path: /etc/systemd/resolved.conf.d/azula.conf
    content: |
      [Resolve]
      LLMNR=no
      MulticastDNS=no
runcmd:
  - [mkdir, -p, /mnt/azula]
  - [mount, -a]
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, azula-guest.service]
  - [systemctl, disable, --now, ssh.service, ssh.socket]
  - [systemctl, mask, --now, sshd-vsock.socket, sshd-unix-local.socket]
  - [systemctl, restart, systemd-resolved.service]
```

The last three `runcmd` items close every other guest listener (sshd on TCP, vsock and
the unix-local socket, LLMNR, mDNS) so the worker is the only thing the host can reach; masking
in `/etc` overrides the generator's units in `/run`. The worker is enabled before they run.

The worker runs straight from the read-only share, so every boot runs the host's current
`azula-guest`. No copy into the guest is needed.

## 9. Local backend (Linux)

- On Linux `compute serve` requires `--local`: the machine itself is the sandbox, so the broker runs
  jobs on it directly. Use it only where the machine is already an isolated VM (e.g. Android's Linux
  Terminal). Flags: `--local`, `--vm-name NAME` (default `default`), `--run-as USER` (default
  `azula`). `compute grant|grants|revoke` work on Linux too; `vm create|delete|list` stay macOS-only.
- `LocalBackend` (`src/compute/local.rs`) serves exactly one VM, named by `--vm-name`. "Start"
  spawns `azula-guest --unix <dir>/run/worker.sock --run-as USER --state-dir <dir>/state` with
  `<dir>` = `~/.azula/vm/local/<name>`. `run/` is created 0700, owned by the broker user, and is
  the access control for the socket.
- The worker must run as root to switch users. A non-root broker starts it with `sudo -n sh -c
  'umask 0; exec "$0" "$@"' <guest> …` (umask 0 so the root-created socket is connectable; `sudo
  -n` failing is a `vm_start_failed`); a root broker execs it directly.
- Start is idempotent and polls `ping` every 500 ms for up to 30 s; on failure the worker's stderr
  tail is in the error. Stop sends SIGTERM, waits 10 s, then SIGKILL (the broker's `vm_busy` check
  applies first). `vm status` reports image `local`, network `host`, CPUs and RAM of this machine.
- Guest binary: `$AZULA_GUEST_BIN`, else `azula-guest` or `azula-guest.linux-aarch64` next to the
  executable, else `azula-guest` on `PATH`. The run-as user is never created automatically; start
  fails telling the operator to run `sudo useradd -m -s /bin/bash azula`.
- A grant with `vms:["*"]` maps to `default`, so `--vm-name default` lets `compute exec` omit `--vm`.
- **Attach mode** (`--worker-socket PATH`, absolute): for a broker running as a child of an Android
  app that boots a Debian VM through AVF and bridges the guest's `azula-guest` (vsock port 1024) to
  a Unix socket. The backend spawns nothing: `start` polls `ping` every 1 s for up to 180 s (the VM
  may still be booting; timeout is `vm_start_failed`), `state` is `running` iff the socket answers a
  ping, `stop` fails with code `unsupported` (the app owns the VM) and `shutdown` is a no-op.
  `vm status` reports image `avf`, network `proxy`, and CPUs/RAM from the optional `--vm-cpus N` /
  `--vm-memory-mb M` (default 0; only valid with `--worker-socket`). `--run-as` is ignored and the
  run-as user is never looked up (Android has no `/etc/passwd`). Without `--worker-socket` the spawn
  mode above is unchanged.
