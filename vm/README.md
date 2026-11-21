# azula remote compute: VM pieces

`azula compute` lets a remote azula client (typically a Claude Code or Codex
cloud sandbox) run commands inside a disposable VM on a Mac, over iroh. Three
processes cooperate:

```
cloud sandbox                     Mac host                                   Linux VM
-------------                     --------                                   --------
azula compute exec  --iroh-->  azula compute serve  --unix-->  azula-vm  --vsock-->  azula-guest
(client, any OS)               (broker, macOS only)            (Swift helper,        (worker, static
                                                                one per running VM)   aarch64-linux-musl)
```

- `vm/helper/` — `azula-vm`, a small Swift executable that owns
  Virtualization.framework. One `azula-vm run` process per running VM. It
  exposes the guest's vsock port as a Unix socket. It never runs host commands.
- `vm/guest/` — `azula-guest`, the worker that runs *inside* the VM, listens on
  vsock, and executes jobs. Pure Rust (no C deps), cross-compiled with
  `rust-lld`.
- `src/compute/` (in the main crate) — the broker, grants, VM bundles, and the
  cross-platform client.

This file is the contract between them. Keep it in sync with the code.

## 1. Frame format (shared by every hop)

Every byte stream (client↔broker iroh bi-stream, broker↔helper Unix socket,
helper↔guest vsock) carries the same frames:

```
u32 BE  header_len   1 ..= 65_536
u32 BE  payload_len  0 ..= 1_048_576
[header_len bytes]   UTF-8 JSON object; must contain a string field "t"
[payload_len bytes]  raw bytes (only data frames use it; otherwise 0)
```

A reader rejects out-of-range lengths, non-UTF-8, non-object JSON, or a
missing `"t"` as a protocol error and closes the stream. Unknown fields are
ignored. Unknown `"t"` values are a protocol error for requests and ignored
for events.

**Test vector** (both implementations must have a unit test for it): header
`{"t":"stdout"}` with payload `hi` encodes to

```
00 00 00 0e 00 00 00 02 7b 22 74 22 3a 22 73 74 64 6f 75 74 22 7d 68 69
```

## 2. Guest worker protocol (`azula-guest`, vsock port 1024)

One request per connection. The first frame selects it.

### ping
- → `{"t":"ping"}`
- ← `{"t":"pong","worker":"azula-guest/<version>","proto":1,"hostname":"…","kernel":"<uname -r>","arch":"aarch64","user":"<run-as user>"}`, then close.

### exec
- → `{"t":"exec","argv":["cargo","test"],"cwd":"/home/azula/src","env":{"K":"V"},"stdin":false,"timeout_s":900}`
  - `argv` required and non-empty, run directly (no shell). `cwd` optional, defaults
    to the run-as user's home. `env` optional, applied on top of a clean base
    environment (`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
    `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG=C.UTF-8`). `stdin` optional,
    default false (child stdin is `/dev/null`). `timeout_s` optional, default
    900, clamped to 1..=86_400.
- ← `{"t":"started","pid":1234}` once spawned.
- ← `{"t":"stdout"}` / `{"t":"stderr"}` with payload chunks (≤ 64 KiB each), in order per stream.
- → `{"t":"stdin"}` + payload (only when `"stdin":true`), → `{"t":"stdin_eof"}` closes child stdin.
- → `{"t":"cancel"}` — SIGTERM to the job's process group, SIGKILL after 5 s.
  The connection closing (EOF or error from the far side) is treated as cancel.
- ← `{"t":"exit","code":0,"signal":null,"reason":"exited"}` after the child is
  reaped **and** both output pipes are drained. `reason` is `exited`,
  `timeout`, or `cancelled`. `code` is null when killed by a signal. Then close.
- ← `{"t":"error","code":"<code>","msg":"…"}` then close, for failures before or
  instead of `started`: `bad_request`, `spawn_failed` (msg = OS error; the
  client maps it to exit 127), `cwd_missing`.

Jobs run as the `--run-as` user (default `azula`) with its uid/gid/groups and
`HOME`, in their own process group. If the worker isn't root or the user is
missing, jobs run as the worker's own user.

## 3. Helper protocol (`azula-vm`)

Swift package at `vm/helper/`, product `azula-vm`, macOS 13+, Apple silicon.
It must be signed with `vm/helper/azula-vm.entitlements`
(`com.apple.security.virtualization`); `vm/helper/build.sh [OUT_DIR]` builds a
release binary and ad-hoc signs it.

### `azula-vm check`
Prints one JSON object: `{"supported":true,"macos":"27.2.1","max_cpus":12,"min_memory_mb":…,"max_memory_mb":…}`. Exit 0.

### `azula-vm init --efi-vars PATH`
Creates a new EFI variable store at PATH (error if it exists) and prints
`{"machine_id":"<base64 VZGenericMachineIdentifier.dataRepresentation>","mac":"<random locally administered MAC>"}`.

### `azula-vm run --config PATH`
Config JSON (all paths absolute):

```json
{
  "cpus": 4,
  "memory_mb": 4096,
  "machine_id": "<base64>",
  "mac": "96:0f:…",
  "efi_vars": "/…/efi.vars",
  "disks": [
    {"path": "/…/disk.img", "read_only": false},
    {"path": "/…/seed.iso", "read_only": true}
  ],
  "shares": [{"tag": "azula", "path": "/…/share", "read_only": true}],
  "console_log": "/…/console.log",
  "vsock": {"socket": "/…/vsock.sock", "port": 1024}
}
```

Linux guest via `VZEFIBootLoader`, `VZGenericPlatformConfiguration`, virtio
block disks, NAT networking, virtio entropy + memory balloon, a virtio console
appended to `console_log`, virtiofs shares, and one virtio socket device.

- **stdout**: JSON lines. `{"event":"started"}` once the VM is running;
  `{"event":"stopped","reason":"guest_shutdown|requested|error","error":"…"}`
  as the last line, then exit (0 unless `reason` is `error`).
- **stdin**: JSON lines. `{"op":"stop","grace_s":30}` asks the guest to power
  off (`requestStop`) and force-stops after the grace period; `{"op":"kill"}`
  force-stops. **stdin EOF or SIGTERM/SIGINT behaves as `stop` with 30 s
  grace**, so the VM never outlives the broker that started it.
- **vsock bridge**: listens on `vsock.socket` (stale file removed first, mode
  0600). Each accepted connection is joined to a fresh guest connection on
  `vsock.port`; bytes are pumped both ways, half-closes are propagated, and if
  the guest refuses (worker not up yet) the Unix connection is closed at once
  so the broker can retry.

## 4. VM bundles on the host

```
~/.azula/vm/
  images/<image>/disk.raw        pristine downloaded image (never booted)
  share/                         read-only virtiofs share "azula": azula-guest, azula-guest.service
  vms/<name>/vm.json             helper config (section 3) + image, created_at
  vms/<name>/disk.img            APFS clone of the image disk, grown sparse
  vms/<name>/efi.vars
  vms/<name>/seed.iso            cloud-init NoCloud seed (label "cidata"), unique instance-id
  vms/<name>/console.log
  vms/<name>/vsock.sock          present while running
```

The seed's cloud-init `runcmd` mounts the `azula` share and installs and starts
`azula-guest` from it on first boot, so a VM always gets the worker that ships
with the host's azula.
