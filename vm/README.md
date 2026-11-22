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

One request per connection; the first frame selects it. Only the broker can
reach the worker (vsock, through the helper's 0600 Unix socket), so the worker
trusts the `owner` field the broker puts on every job and file request: it is
the grant id of the client the broker authenticated. A client can't set it.

### 2.1 Jobs model

A job outlives the connection that started it. Its output goes to disk first
and to whoever is attached second, so a slow, absent or reconnecting client
never blocks it and never loses output that is still retained.

- **Id** `j_` + 16 random hex. Clients name a job `<vm>/<id>` (e.g.
  `build/j_3f9a1c2b7d4e8a60`); the worker only sees the id.
- **Record** `/var/lib/azula/jobs/<id>/`: `job.json` (owner, label, idem key,
  argv, cwd, env *keys* (never values), created/started times, timeout,
  flags), `stdout/` and `stderr/` segment directories, and `exit.json` once it
  ends. Written with fsync before `started` is sent.
- **States**: `running`, then `exited` with a `reason` (`exited`, `timeout`,
  `cancelled`, `stdin_lost`, `orphaned`), or `interrupted` (the worker or the VM
  stopped while it ran: found at worker start with no `exit.json`).
- **Output**: each stream is an append-only byte sequence with absolute
  offsets, stored in 8 MiB segment files named by their start offset. The last
  32 segments (256 MiB) per stream are kept; older ones are deleted and the
  stream's `earliest` offset advances. If the guest disk is full, output that
  can't be written is dropped, the record gets `"output_truncated":true`, and
  the pipes keep draining so the job never stalls.
- **Limits**: at most 64 running jobs per VM and 16 per owner; beyond that,
  `error` `busy`.
- **Retention**: a finished job's record and output are kept 24 h after it
  ends, at most 200 finished jobs per VM, and at most 2 GiB of output per VM;
  the oldest finished jobs are pruned first. Running jobs are never pruned.
- **Worker restart**: every job without `exit.json` is marked `interrupted`
  (its processes died with the worker's cgroup). Part files older than 24 h are
  removed.

### 2.2 ping
- → `{"t":"ping"}`
- ← `{"t":"pong","worker":"azula-guest/<version>","proto":1,"hostname":"…","kernel":"<uname -r>","arch":"aarch64","user":"<run-as user>","jobs_running":0,"disk_free_mb":12345}`, then close.

### 2.3 exec
- → `{"t":"exec","owner":"g_…","idem":"<client uuid>","label":"…","argv":["cargo","test"],"cwd":"/home/azula/src","env":{"K":"V"},"stdin":false,"timeout_s":900,"attach":true,"cancel_on_disconnect":false}`
  - `argv` required and non-empty, run directly (no shell). `cwd` optional, defaults
    to the run-as user's home. `env` optional, applied on top of a clean base
    environment (`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
    `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG=C.UTF-8`). `stdin` optional,
    default false (child stdin is `/dev/null`). `timeout_s` optional, default
    900, clamped to 1..=86_400 (the broker may lower it further). `label`
    optional free text for listings.
  - **`idem`** (required): if this owner already has a job with this key (any
    state, still retained), no new job starts. The worker answers with that
    job (`"deduped":true`) and continues as an attach from offset 0, or closes
    if `attach` is false. The same key with a different argv/cwd/env/stdin is
    `error` `idem_conflict`. This makes "send exec, lose the connection before
    `started`, send it again" safe.
- ← `{"t":"started","job":"j_…","pid":1234,"deduped":false}`.
- `"attach":false`: the worker closes after `started`; the job runs on. `"stdin":true`
  requires `"attach":true` (`bad_request` otherwise), since the input would be lost at once.
- `"attach":true`: ← `{"t":"stdout","off":N}` / `{"t":"stderr","off":N}` + payload
  (≤ 64 KiB), contiguous and in order per stream, then
  ← `{"t":"exit","job":"j_…","code":0,"signal":null,"reason":"exited","stdout_len":N,"stderr_len":M}`
  after the child is reaped **and** both pipes hit EOF and are on disk; then
  close. `code` is null when killed by a signal. The `_len` fields let a client
  confirm it holds every byte.
- → `{"t":"stdin"}` + payload and → `{"t":"stdin_eof"}` (only with `"stdin":true`);
  → `{"t":"cancel"}` cancels the job (SIGTERM to its process group, SIGKILL after 5 s).
- **The connection closing does not cancel the job**, except:
  - `"stdin":true` and `stdin_eof` not yet received: the job's input is
    incomplete, so it is cancelled with reason `stdin_lost`;
  - `"cancel_on_disconnect":true`: if no connection is attached to the job
    for 60 s, it is cancelled with reason `orphaned`.
- ← `{"t":"error","code":"<code>","msg":"…"}` then close, instead of `started`:
  `bad_request`, `spawn_failed` (client exit 127), `cwd_missing` (126), `busy`,
  `idem_conflict`.

### 2.4 attach
- → `{"t":"attach","owner":"g_…","job":"j_…","stdout_off":0,"stderr_off":0,"follow":true}`
- ← `{"t":"attached","job":"j_…","state":"running","label":"…","argv":[…]}`,
  or `error` `not_found` (unknown id **or another owner's job**, indistinguishably).
- For a stream whose requested offset is below what's retained:
  ← `{"t":"gap","stream":"stdout","from":N,"to":E}`, then data from `E`.
- Replayed and live data frames are contiguous per stream: no duplicates, no holes.
- `"follow":true`: continues live while the job runs, then ← `exit`.
  `"follow":false`: after replaying what's on disk, ← `exit` if it has ended,
  else ← `{"t":"end","state":"running","stdout_len":N,"stderr_len":M}`. Then close.
- → `{"t":"cancel"}` on an attach connection cancels the job.
- An `interrupted` job ends with an `exit` frame whose reason is `interrupted`.
- Several connections may attach to one job at once; each gets the full stream.

### 2.5 jobs
- → `{"t":"jobs","owner":"g_…"}`. `"owner":"*"` matches every owner here and in `attach`
  and `cancel_job`; the broker sends it only for an admin grant.
- ← `{"t":"job_list","jobs":[{"job","label","argv","state","reason","created","ended","code","signal","stdout_len","stderr_len","stdout_earliest","stderr_earliest","output_truncated"}]}`, newest first. Then close.

### 2.6 cancel_job
- → `{"t":"cancel_job","owner":"g_…","job":"j_…"}`
- ← `{"t":"cancel_ok","job":"j_…","state":"running|exited|interrupted"}` (a job
  that already ended is left as it is) or `error` `not_found`.

Jobs run as the `--run-as` user (default `azula`) with its uid/gid/groups and
`HOME`, in their own process group. If the worker isn't root or the user is
missing, jobs run as the worker's own user.

### 2.7 put (file into the guest, resumable)
- → `{"t":"put","owner":"g_…","path":"out/app.tgz","upload":"<client uuid>","mode":420,"overwrite":true,"mkdirs":true}`
  - `path` required: absolute, or relative to the run-as user's home; UTF-8
    only. `mode` optional (default 0o644; only the 0o777 bits are applied).
    `overwrite` default true. `mkdirs` default true (missing parents are
    created, owned by the run-as user, mode 0o755).
  - `upload` required: the client's id for this transfer. Resuming needs the
    same owner, upload id and path.
- ← `{"t":"put_ready","offset":N}`: N bytes of this upload are already on disk
  (0 for a new one). The worker re-hashes those N bytes to continue the digest.
- → `{"t":"data"}` + payload chunks (≤ 1 MiB each) starting at byte N, in order.
- → `{"t":"eof","size":S,"sha256":"<hex>"}` over the whole file.
- ← `{"t":"put_ok","path":"/home/azula/out/app.tgz","size":S,"sha256":"<hex>"}`, then close.
- ← `{"t":"error","code":"<code>","msg":"…"}`, then close: `bad_request`,
  `exists` (target exists and `overwrite` is false), `is_a_directory`,
  `not_a_directory` (a parent is a file), `upload_conflict` (id in use for
  another path or owner), `size_mismatch`, `digest_mismatch`, `io_error`
  (message includes the OS error, e.g. ENOSPC).

The bytes go to `.<name>.azula-<upload>.part` in the target's directory
(`O_CREAT|O_NOFOLLOW`, mode 0600). Only when `eof` matches both size and
digest does the worker `fchmod`, `fchown` to the run-as user (a no-op when the worker already
runs as that user), `fsync` and
`rename` over the target, so the target is always either the old file or the
complete new one. If the connection drops before `eof`, the part file stays
for resumption (24 h); a size or digest mismatch deletes it so the client
restarts from 0. Concurrent puts to one path each complete atomically; the
last rename wins.

### 2.8 get (file out of the guest, resumable)
- → `{"t":"get","owner":"g_…","path":"out/app.tgz","offset":0,"etag":null}`
- ← `{"t":"get_meta","path":"/home/azula/out/app.tgz","size":S,"mode":420,"etag":"<dev>:<ino>:<size>:<mtime_ns>"}`.
  If the request carried an `etag` that no longer matches,
  ← `error` `changed` instead (the client restarts from 0 without one).
- ← `{"t":"data"}` + payload chunks (≤ 1 MiB) from `offset`.
- ← `{"t":"get_end","size":S,"sha256":"<hex>"}`: the digest of the whole file,
  including bytes before `offset`. Then close.
- ← `error`: `bad_request`, `not_found`, `not_a_file` (directories, devices,
  sockets, FIFOs; the hint suggests `-r`), `io_error`.

Symlinks are followed inside the guest; the final target must be a regular
file. The client writes to a part file next to its destination and renames it
into place only if `get_end` matches.

File operations run as the worker. In a Mac VM or an AVF VM the worker is root
and creates files owned by the run-as user; there that is not a privilege
boundary (the job user has passwordless sudo), so put/get/attach/jobs are
authorized exactly like exec. In the Linux local backend (BROKER.md section 9)
the worker itself runs as the unprivileged job user, so put and get are
confined to what that user may read and write, and the `fchown` is skipped.
Nothing in this protocol can name a path on the host.

## 3. Helper protocol (`azula-vm`)

Swift package at `vm/helper/`, product `azula-vm`, macOS 13+, Apple silicon.
It must be signed with `vm/helper/azula-vm.entitlements`
(`com.apple.security.virtualization`); `vm/helper/build.sh [OUT_DIR]` (default `vm/helper/.build/dist`) builds a
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
  "network": "nat",
  "console_log": "/…/console.log",
  "vsock": {"socket": "/…/vsock.sock", "port": 1024}
}
```

`network` is `"nat"` (default when absent) or `"none"` (no network device at all).

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
  images/<dir>/disk.raw          pristine downloaded image (never booted); <dir> for debian-13 is debian-13-generic-arm64
  share/                         read-only virtiofs share "azula": azula-guest (the unit comes from cloud-init)
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
