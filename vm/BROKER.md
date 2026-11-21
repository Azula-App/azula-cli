# azula remote compute: broker, grants and client

Companion to `vm/README.md` (frames §1, guest protocol §2, helper §3, bundles §4).
This file covers the Rust side in `src/compute/`. Merge into README when stable.

## 5. Client ↔ broker (iroh ALPN `azula/compute/1`)

One iroh connection per request; the client opens one bi-stream and speaks
§1 frames.

1. → `{"t":"hello","v":1,"grant":"<grant id>","secret":"<base64url>","client":"azula/<version>"}`
2. ← `{"t":"welcome","v":1,"host":"<hostname>","broker":"azula/<version>","grant":"<id>","expires":<unix>,"ops":["exec","vm"],"vms":["*"]}`
   or ← `{"t":"error","code":"unauthorized|unsupported_version|bad_request","msg":"…"}` and close.
   Unknown, expired and revoked grants all get the same `unauthorized` reply.
3. → exactly one request:
   - `{"t":"ping"}` → ← `{"t":"pong","broker":"azula/<version>","host":"<hostname>"}`.
   - `{"t":"vm","op":"list|status|start|stop","vm":"<name>"}` → ← `{"t":"vm_status","vms":[VmInfo…]}`.
     `list`/`status` need any grant that covers the VM(s) (list filters to the grant's scope).
     `start`/`stop` need op `vm`. `start` replies once the worker answers a ping (deadline
     180 s; on failure ← `error` `vm_start_failed` with the last 40 console lines in `msg`).
     `stop` replies once the helper reports `stopped`.
   - `{"t":"exec","vm":"<name>","start":true, …§2 exec fields}` needs op `exec` and the VM in
     scope. If the VM isn't running: with `"start":true` and op `vm` in the grant, start it as
     above; otherwise ← `error` `vm_not_running`. Then the broker connects to the VM's
     `vsock.sock` (retrying ≤ 30 s while the worker comes up), forwards the exec frame with the
     broker-only fields (`vm`, `start`) removed, and splices bytes in both directions until either
     side closes. It never parses job output. The client's disconnect closes the guest connection,
     which the worker treats as cancel.
   - `{"t":"guest_ping","vm":"<name>"}` → ← the guest's `pong` frame verbatim (for `doctor --vm`).

`VmInfo` = `{"name","state":"stopped|starting|running|stopping","worker":"ready|unreachable|unknown","image","cpus","memory_mb","disk_gb","worker_info":<guest pong or null>}`.

Error codes: `unauthorized`, `forbidden` (grant doesn't allow op or VM), `bad_request`,
`unknown_vm`, `vm_not_running`, `vm_start_failed`, `worker_unreachable`, `internal`.

The broker logs one line per request to stderr: time, grant id, peer endpoint id (short),
request type, VM, outcome. Never the secret.

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

## 7. CLI

Host verbs (Apple silicon macOS only; elsewhere they exit 2 with "compute hosting requires
Apple silicon macOS"):

- `azula compute serve` — foreground broker. Banner: endpoint id, relay URL, VM dir. On
  SIGINT/SIGTERM it stops every VM it started (helper `stop`, 30 s grace) before exiting.
- `azula compute grant [--ttl 7d] [--vm NAME]… [--ops exec,vm] [--label TEXT] [--json]` —
  prints the token and a one-line `export AZULA_COMPUTE_TOKEN=…` hint on stdout.
- `azula compute grants [--json]`, `azula compute revoke <grant-id>`.
- `azula vm create <name> [--image debian-13] [--cpus 4] [--memory 4096] [--disk-gb 32]`,
  `azula vm list [--json]`, `azula vm delete <name>` (refuses while `vsock.sock` is live).

Client verbs (any OS). Token from `--token`, else `AZULA_COMPUTE_TOKEN`:

- `azula compute exec [--vm NAME] [--no-start] [--cwd DIR] [--env K=V]… [--stdin]
  [--timeout 15m] [--json] -- ARGV…` — `--vm` defaults to the grant's only VM when it names
  exactly one, else `default`. Streams stdout/stderr to the local stdout/stderr. `--stdin`
  forwards local stdin then EOF. SIGINT sends `cancel` once, and a second SIGINT disconnects.
  `--json` writes JSONL events to stdout: `{"type":"started","pid"}`,
  `{"type":"stdout"|"stderr","data_b64"}`, `{"type":"exit","code","signal","reason"}`,
  `{"type":"error","code","msg"}`.
- `azula compute doctor [--vm NAME] [--json]` — stages, each with its own deadline:
  `token` (parse), `bind` + `relay` (one bind that must reach the relay within 20 s; a relay failure reports `bind` passed and `relay` failed), `dial` (20 s), `auth` (hello→welcome,
  10 s), `broker` (ping), and with `--vm` `guest` (guest_ping, 30 s). Prints ✓/✗ per stage, the
  relay URL, and for failures a hint (allowlist the relay host, check `HTTPS_PROXY`, try
  `AZULA_RELAY_ONLY=1`, is `compute serve` running?, is the grant revoked/expired?).
- `azula vm start|stop|status [NAME] [--json]` via the broker.

Client exit codes: the job's exit code; `128+N` when the job died of signal N; `124` timeout;
`127` `spawn_failed`; `126` `cwd_missing`; `130` cancelled by local SIGINT; `125` any broker
error (`unauthorized`, `forbidden`, `vm_not_running`, …); `255` transport failure (couldn't
reach the host, or the connection dropped before `exit`). Error messages go to stderr prefixed
`azula:`.

## 8. VM manager (inside `compute serve`)

- Bundles per README §4 under `~/.azula/vm` (`AZULA_VM_DIR` overrides it, for tests; the host key,
  grants and `host.json` live under `~/.azula/compute`, overridable with `AZULA_COMPUTE_DIR`).
- Helper binary: `$AZULA_VM_HELPER`, else `azula-vm` next to the current executable, else on
  `PATH`. Guest binary: `$AZULA_GUEST_BIN`, else `azula-guest.linux-aarch64` next to the current
  executable. At serve start the broker copies the guest binary (atomically) into
  `~/.azula/vm/share/azula-guest` (only the binary: the systemd unit comes from cloud-init).
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
