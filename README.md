# azula

The command-line companion for the **azula** p2p app: everything your phone
can be on the other end of, driven from a shell, a script, an MCP client, or
CI — over direct, end-to-end [iroh](https://iroh.computer) connections, no
account and no server in the middle.

- **Talk to your phone from any tool.** `azula mcp` is an MCP server (stdio,
  or Streamable HTTP with `--http`) exposing messaging, file transfer, and
  live agent-drawn UI ([A2UI](../azula-docs/openspec/specs/a2ui/design.md));
  the same verbs exist directly as CLI commands (`azula message`, `azula ui`,
  `azula watch --json`) so a plain script can do everything an LLM can.
- **Many sessions, one pairing.** Pair a machine once; every azula process
  mints its own certified session key and becomes its own conversation on the
  phone — run as many concurrent MCP sessions, terminals, and scripts as you
  like. Ephemeral environments (CI, containers) pair per session with a
  printed URL/QR instead of holding any standing credential.
- **Terminals, including "come look at this" ones.** `azula terminal` hosts
  persistent remote shells; `azula run --handoff on-error -- <cmd>` wraps a
  command so a failure holds the session open — scrollback included — for
  your phone (or `azula terminal attach`) to pick up right where it died.
- **An always-on relay.** `azula relay` on a server stores-and-forwards agent
  chat and A2UI state while your phone is offline, and live-forwards when it
  isn't.

Built on the official Rust MCP SDK,
[`rmcp`](https://github.com/modelcontextprotocol/rust-sdk). This is a
standalone Cargo crate — not part of the Amper/Kotlin build in the rest of
the repository.

## Install

Prebuilt binaries, an npm wrapper, and a Homebrew tap all publish from the
same GitHub Release, cut automatically the first time a `v*` tag is pushed
(see `.github/workflows/release.yml` and `dist/README.md`). Until that first
tag exists, none of these channels are live yet — build from source (below)
in the meantime.

### Homebrew (macOS, Linux)

```sh
brew install azula-app/azula/azula
```

### cargo (any platform with a Rust toolchain)

```sh
cargo install azula
```

Builds and installs the `azula` binary from the crates.io source package.

### npx (no install — works anywhere Node runs, including the Claude Code
web container)

```sh
npx -y azula-cli --version
```

`azula-cli` is a meta package: it fetches the right prebuilt binary for your
platform as an npm optional dependency (`@azula-app/cli-darwin-arm64`,
`-darwin-x64`, `-linux-x64`, or `-linux-arm64`) and execs it. There's nothing
to install ahead of time — `npx -y azula-cli@<version> …` pins an exact
release if you don't want to float on latest.

### `mcp.json` — azula as an MCP server

`npx -y azula-cli mcp` works on a machine that has never touched azula
before, which makes it the most portable way to wire azula into an MCP
client config:

```jsonc
{
  "mcpServers": {
    "azula": {
      "command": "npx",
      "args": ["-y", "azula-cli", "mcp"]
    }
  }
}
```

If you installed via Homebrew or `cargo install` instead, use
`"command": "azula", "args": ["mcp"]`.

### Claude Code web container: relay-only (no-UDP) networking

The Claude Code web container's egress is proxied HTTPS only — no raw UDP —
so iroh's direct QUIC hole-punching path can't connect. Pairing and
messaging still work, but only over iroh's **relay-over-HTTPS fallback**,
which means the container's outbound proxy allowlist must permit the n0
relay hosts iroh dials by default:

| Region  | Hostname                     |
| ------- | ----------------------------- |
| NA East | `use1-1.relay.n0.iroh.link`   |
| NA West | `usw1-1.relay.n0.iroh.link`   |
| EU      | `euc1-1.relay.n0.iroh.link`   |
| AP      | `aps1-1.relay.n0.iroh.link`   |

Reached over HTTPS (443). Source:
[`iroh/src/defaults.rs`](https://github.com/n0-computer/iroh/blob/main/iroh/src/defaults.rs)'s
`prod` module — verified against `iroh 1.0.0`, the version pinned in
`Cargo.lock` as of this writing. n0 can add or retire relay nodes between
iroh releases, so re-check that file (or `cargo tree -p iroh` for the
locked version, then the matching tag on GitHub) if the pinned iroh version
changes and pairing from a proxied environment stops working.

If the container's proxy blocks those hosts, azula cannot reach the phone at
all in that environment — there is no user-controlled-relay fallback in this
release (see `openspec/changes/cli-multi-session-relay/design.md`, decision
D8). This constraint is specific to relay-only egress; `azula relay` (the
always-on relay role) and normal dev-machine usage with UDP egress are
unaffected.

## Build

```sh
cd azula-cli
cargo build
```

(Requires a recent stable Rust toolchain. The first build fetches crates from
crates.io, so network access is needed. `cargo build` at the workspace root
builds both the `azula` binary and the `azula-demos` binary below; add `-p
azula` to build just the production CLI.)

## Command overview

`azula` is a noun-verb CLI: one shared session core underneath every verb
(the same core the MCP tools use), so a script can do anything an LLM
talking to `azula mcp` can.

| Command | Does |
| --- | --- |
| `azula mcp [--http BIND] [--session NAME] [--device URL]... [--name NAME] [--max-turns N]` | MCP server for an LLM client — stdio by default, Streamable HTTP with `--http` |
| `azula message send [--device D] [--session S] TEXT` | Send a chat-style message (queues via the relay/local mailbox if the device is unreachable) |
| `azula message recv [--device D] [--session S] [--wait SECS]` | Drain, or long-poll for, inbound messages |
| `azula watch [--device D] [--session S] [--json]` | Follow a device's inbox continuously: messages, A2UI events, files, connect/disconnect |
| `azula ui render [--device D] [--session S] [--surface ID] [--data-model JSON] FILE\|-` | Render an A2UI surface from a components JSON file or stdin |
| `azula ui update [--device D] [--session S] --surface ID POINTER VALUE` | Update a rendered surface's data model at an RFC 6901 pointer |
| `azula ui delete [--device D] [--session S] --surface ID` | Remove a rendered surface |
| `azula ui catalog` | Print the A2UI component/prop vocabulary |
| `azula file send [--device D] [--session S] PATH [--caption TEXT]` | Send a local file as an inline attachment (always requires a live connection) |
| `azula run [--handoff on-error\|always\|never] [--hold MINUTES] -- CMD…` | Run a command in a PTY; on failure, hand off to a live shell in the same session |
| `azula terminal [new\|list\|attach\|kill]` | Host, manage, or attach to persistent named terminal sessions |
| `azula relay [--allow-legacy]` | Serve the identity's always-on relay role (alias: `azula mailbox`) |
| `azula status [--json]` | Machine identity, known devices, and local sessions — reads disk state, binds nothing |
| `azula devices [--json]` | List the merged device registry |
| `azula pair <URL> [--name N] [--global]` | Save a device's ticket to the registry |
| `azula qr <CODE>` | Print a QR code for any ticket/URL/token |
| `azula invite [--expires W] [--sign] [--single-use] [--label L] [--bridge]` | Mint a signed invite; `azula invite revoke <id-prefix>` deletes one |
| `azula invites` | List invites this node has issued |
| `azula link [--name N] [--relay]` | Enroll this CLI as a sibling device of an existing multi-device identity |

Every command supports `--help`; most one-shot verbs (`message`, `ui`,
`file`, `watch`) also support `--json` for machine-readable output.

## Multiple sessions: pair once, every process gets its own conversation

Older versions of this CLI bound one persistent identity key per long-running
command (`bridge.key` for the MCP bridge, `serve.key` for `azula serve`), so
two `azula mcp` processes on one machine would collide — only one could hold
the phone's connection at a time.

That's gone. Every azula process — an `azula mcp` server, an `azula run`
handoff, a `azula terminal new` host, a one-shot `azula message send` — binds
its **own** ephemeral (or named) session keypair and presents a short-lived
certificate signed by this machine's stable identity (`~/.azula/machine.key`,
adopted in place from an existing `~/.azula/bridge.key` if you're upgrading —
your phone's existing pairing keeps working, no re-pairing needed). Concrete
effects:

- **Pair the machine once.** Any invite you redeem on the phone (from the
  startup banner, `azula invite --bridge`, or a `azula run`/`azula terminal`
  connect block) pairs the *machine*. Every session that machine's processes
  create afterward is auto-admitted with no further prompt — the phone
  recognizes the session's certificate as chaining back to a machine it
  already trusts.
- **Every process is its own conversation.** Two Claude Code windows each
  running `azula mcp` show up as two separate conversations on the phone —
  that's the point, not a bug. Pass `--session NAME` (or set `AZULA_SESSION`)
  to reuse the same conversation across invocations instead — one-shot verbs
  (`message`, `ui`, `file`, `watch`) default to a shared session named `cli`
  automatically, so casual use from any terminal lands in one "CLI"
  conversation without you having to think about it. `azula mcp`, `azula
  run`, and `azula terminal` default to a **fresh** session per invocation.
- **Headless environments scan per session.** A container or CI runner with
  no `~/.azula/machine.key` (a fresh Claude Code web container, a stateless
  CI image) self-certifies instead of writing a standing credential: each
  such process prints its own pairing URL + QR and waits, and the user
  approves it individually from the phone. No secret is left on disk when
  the process exits.

## Scripting azula directly — the "blackjack pattern"

Everything the MCP tools can do, a shell script can do too, by shelling out
to the same one-shot verbs and following `azula watch --json`:

```sh
# Learn the A2UI vocabulary once
azula ui catalog

# Render a surface from stdin — no MCP client needed
echo '[
  {"id":"root","component":"Column","children":["title","face","roll"]},
  {"id":"title","component":"Text","text":"AZULA · DICE","variant":"caption"},
  {"id":"face","component":"Text","text":{"path":"/you"},"variant":"h1"},
  {"id":"rollL","component":"Text","text":"ROLL"},
  {"id":"roll","component":"Button","child":"rollL","variant":"primary",
   "action":{"event":{"name":"roll"}}}
]' | azula ui render --device phone --data-model '{"you":"?"}' -
# → {"status":"rendered","device":"phone","surface":"ui-<t>-<n>"}  (with --json)

# React to taps as they arrive
azula watch --device phone --json | while read -r line; do
  case "$line" in
    *'"type":"ui_event"'*'"name":"roll"'*)
      azula ui update --device phone --surface "$SURFACE" /you '"⚄"'
      ;;
  esac
done
```

`azula ui render`/`update`/`delete` apply the same client-side validation the
`render_ui` MCP tool does (a `"id":"root"` component is required; nothing is
sent for an invalid payload), and `azula ui catalog`/`azula ui render --help`
print the exact same component/prop reference the MCP tool description
carries — one string in the crate (`catalog.rs`), three consumers.

## `azula run` — hand a failing command to the phone

```sh
azula run --handoff on-error -- make test
```

Runs `make test` in a captured PTY, mirroring its output to your real
terminal (or CI log) unmodified. On a nonzero exit, it keeps that output as
scrollback, spawns a live shell in the *same* working directory, and prints a
connect block (an invite URL + QR — scannable straight from a CI log viewed
on a phone). Whoever attaches — the phone, or `azula terminal attach
<invite-url>` from another shell — sees the failed command's output followed
by a live prompt, "continue where execution left off." `azula run` itself
stays alive until that session ends (or a `--hold` timeout, default 60
minutes, expires), then exits with `make test`'s **original** exit code — so
CI still reports the failure even though someone poked around afterward.
`--handoff on-error` is the default (shown above); `--handoff always` hands
off regardless of exit code; `--handoff never` is a pure PTY passthrough —
`azula run` just exits with the command's own code, no connect block ever
printed.

## `azula terminal` — persistent, named shell sessions

```sh
azula terminal                              # host one interactive shell inline
azula terminal new --cmd "claude" --name work   # spawn a detached, named session
azula terminal list [--json]                # see what's running
azula terminal attach work                  # continue it from any shell
azula terminal kill work                    # tear it down
```

`azula terminal new` re-execs itself as a detached background process (stdout/
stderr redirected to log files under `$TMPDIR/azula/sessions/<name>/`) hosting
one persistent PTY under its own named session identity — spin up as many of
these as you want, each its own phone conversation. `azula terminal attach
<name|url>` is a raw-mode passthrough client with no terminal emulator
involved: it works against a name from `azula terminal list`, or any invite
URL/ticket (including one from an `azula run` connect block), so a session
started in CI or on another machine can be continued from a laptop shell as
well as from the phone. Detach with Ctrl-\\.

## `azula relay` — the always-on sibling (alias: `azula mailbox`)

```sh
azula link --relay     # enroll this device once (--mailbox is a kept alias)
azula relay            # then run it, e.g. under systemd/launchd
```

An ordinary sibling device of your azula identity that commits to always
being reachable: it stores and forwards peer chat, bootstraps a brand-new
device's full history, **and** — since sessions can't always reach the phone
directly — relays agent chat (a session's messages, delivered to the phone
on its next sync) and bounded A2UI surface snapshots (latest state per
surface, replayed to the phone when it reconnects). A session's delivery
order is: direct to the phone first, this relay second (only if you've
paired a machine with a phone that has one enrolled), the local per-device
mailbox last. Interactive terminal traffic and file transfers are never
relayed — those always need a direct connection.

## Pairing & the device registry

```sh
azula pair <URL> [--name NAME] [--global]
azula devices [--json]
azula qr <CODE>
azula invite [--expires 1h|24h|7d|never] [--sign] [--single-use] [--label L] [--bridge]
azula invite revoke <id-prefix>
azula invites
azula link [--name NAME] [--relay]
```

`<URL>`/`<CODE>` accept any of: `https://azula.app/s/<token>`,
`https://azula.app/connect/<token>`, `azula://connect?code=<token>`, an
invite link (`https://azula.app/i/<payload>`, `azula://i?c=<payload>`, or a
bare `azi…` payload), or a bare token. `--global` writes to
`~/.azula/devices.json` instead of the project-local `.azula/devices.json`
(used automatically inside a git tree; project entries win on name
collision). `azula invite --bridge` mints against this machine's stable
identity — the one every `azula mcp`/`azula run`/`azula terminal` session's
certificate chains to — rather than the default `serve` identity, so a
plain `azula invite` (no `--bridge`) will **not** pair with any of them.
`azula link [--relay]` enrolls this CLI as a sibling device of an existing
multi-device identity (print a QR/string for the root-holding device to
scan, then wait for it to grant a certificate) — pass `--relay` to request
the always-on relay role.

```
$ azula devices
NAME                 FINGERPRINT  SOURCE
------------------------------------------------
laptop               testtoke…    project
myphone              abc12345…    global
```

| Registry file | Path | When used |
| --- | --- | --- |
| project | `<git-root>/.azula/devices.json` | Inside a git tree; commit for team use |
| global | `~/.azula/devices.json` | Always consulted; `azula pair --global` |
| relay hints | `relay-hints.json` next to each `devices.json` above | Which relay ticket to try for a device (learned automatically at pairing time) |
| runtime | `$TMPDIR/azula/bridge.json` | A running `azula mcp` process's `{bind, pid, devices}` |
| sessions | `~/.azula/sessions/<name>.key` (named), `$TMPDIR/azula/sessions/` (ephemeral) | Session key material — see "Multiple sessions" above |

## Deprecated aliases

Kept working for one release cycle, each printing a stderr deprecation
notice before delegating to its replacement:

| Deprecated | Use instead |
| --- | --- |
| `azula serve-mcp [--bind ADDR]...` | `azula mcp --http [ADDR]` |
| `azula mailbox` | `azula relay` |
| `azula link --mailbox` | `azula link --relay` (same flag now — `--mailbox` is a clap alias, no notice printed) |
| bare `azula` / `azula serve [--mcp-stdio CMD \| --mcp-url URL] [--mcp-tool T] [--term-only]` | Not deprecated (no notice on the bare invocation), but superseded for day-to-day use by `azula mcp`, `azula run`, and `azula terminal`. This is the original LLM-relay-plus-terminal demo server — it still works exactly as before, binding a `serve.key` identity and serving both `azula/llm/0` and `azula/term/0` on one endpoint. |

## `azula-demos` — standalone demo binaries

The `demo-ui` and `blackjack` commands live in a separate `azula-demos` crate
(`demos/`) in this workspace, not in the `azula` binary — they're standalone
manual-testing tools, not part of the production server. Build and run them
with `-p azula-demos`:

```sh
cargo run -p azula-demos -- demo-ui phone
cargo run -p azula-demos -- blackjack
```

### `demo-ui` — push a sample A2UI surface

A quick manual tester for the A2UI render → event → update loop, with no MCP
client required. It dials a device (by registered name or ticket/URL) on the LLM
channel, renders a dice surface in the app's azula conversation, and — unless
`--once` — listens for the user's taps and re-rolls in response.

```sh
cargo run -p azula-demos -- demo-ui phone          # render + react to ROLL taps until Ctrl-C
cargo run -p azula-demos -- demo-ui phone --once   # render once and exit
cargo run -p azula-demos -- demo-ui "https://azula.app/s/<token>"   # dial a ticket directly
```

Tapping **ROLL** in the app prints the event and pushes an `updateDataModel`
back, so the dice faces and result update live — exercising the same path the
LLM uses via `render_ui` / `get_messages` / `update_ui`.

### `blackjack` — standalone Blackjack dealer

Binds its own iroh endpoint (separate persisted identity, `~/.azula/blackjack.key`),
prints a connect code, and deals a game of Blackjack — rendered as an A2UI
surface — to each app that connects. No MCP client involved; unlike `demo-ui`
it *accepts* inbound connections the way `serve` does.

```sh
cargo run -p azula-demos -- blackjack
```

## ALPNs

| ALPN bytes         | Protocol | Served by |
| ------------------ | -------- | --------- |
| `b"azula/llm/0"`   | LLM relay / MCP bridge / agent chat + A2UI snapshots | `azula serve`, `azula mcp`, `azula run`/`azula terminal` (their session endpoints), `azula relay` |
| `b"azula/term/0"`  | remote shell (persistent-session capable) | `azula serve`, `azula run`/`azula terminal`'s session endpoints |
| `b"azula/chat/0"`  | identity peer chat, store-and-forward | `azula relay` only |
| `b"azula/sync/0"`  | identity log sync/bootstrap | `azula relay` (accept-side only in this crate; the phone app dials it) |
| `b"azula/link/0"`  | device-linking enrollment (rootless on a relay) | `azula link`, `azula relay` |

## Wire protocol

Newline-delimited JSON. Each line is one `Frame` object, internally tagged on a
`"type"` field. This matches kotlinx.serialization's default
`classDiscriminator = "type"` for a sealed `Frame` class whose variants carry
`@SerialName` annotations. Framing: write `serde_json::to_string(&frame)` plus a
trailing `'\n'`; read with a buffered `read_line`. The full frame set lives in
`src/proto.rs`; the ones most relevant to using this CLI day-to-day:

| `type`     | Direction        | Fields                       | Meaning                                |
| ---------- | ---------------- | ---------------------------- | -------------------------------------- |
| `hello`    | peer → peer      | `name`, `invite?`, `cert?`   | first frame on a new connection; names the dialer, optionally carries an invite to redeem and/or a session/device certificate |
| `chat`     | client → server  | `text`, `id?`                | LLM prompt / peer chat / agent chat; `id` is a random hex string used for retry dedup |
| `input`    | client → server  | `text`                       | terminal keystrokes / command          |
| `resize`   | client → server  | `cols`, `rows`                | terminal viewport size                 |
| `token`    | server → client  | `delta`, `done` (default false) | LLM token stream                    |
| `thinking` | server → client  | `on`                         | thinking indicator                     |
| `term`     | server → client  | `line`                       | shell output chunk                     |
| `term_attach` | client → server | `session?`                 | opt into (or resume) a persistent terminal session instead of the legacy dies-with-stream behavior |
| `term_session` | server → client | `session`, `resumed`      | acknowledges `term_attach`; `resumed:true` means scrollback replay follows |
| `term_exit` | server → client  | `session`, `code?`           | the persistent session's shell exited  |
| `profile`  | peer → peer      | `name`, `description?`, `avatar?`, `mime?` | names/describes the conversation (a terminal's hostname+cwd, or `set_name`'s output) |
| `a2ui`     | server → client  | `message` (A2UI message JSON) | create/update/delete a UI surface     |
| `a2ui_action` | client → server | `action` (A2UI action JSON) | user interaction with a surface        |
| `a2ui_snapshot` | session → relay | `conversation`, `surface`, `components?`, `data_model?`, `lamport` | a coalesced full-surface A2UI snapshot, for the relay to hold and replay when the phone reconnects |
| `relay_hint` | phone → session | `ticket`                   | the identity's relay connect ticket, sent once at machine-pairing time |
| `file_begin` / `file_chunk` / `file_end` | both | (see `proto.rs`)  | chunked file transfer                  |

`sync_hello`/`sync_vector`/`sync_entries`/`sync_ack` (identity log sync) and
`link_hello`/`link_grant`/`link_reject` (device enrollment) are internal to
`azula relay`/`azula link` and not something a script driving the CLI needs
to speak directly — see `azula-docs`' `account-sync` and `device-linking`
capability pages for those wire formats.

### LLM relay flow

The client opens the bi stream and writes first. For each `chat` prompt the
server pushes the text into the shared MCP session (one `call_tool` with the
configured tool and `{ <message-arg>: <text> }` arguments), extracts the text
content blocks of the result, and emits:

1. `{"type":"thinking","on":true}`
2. one or more `{"type":"token","delta":"…"}` frames (the result is chunked
   word-by-word for a streaming effect; tool-level errors are surfaced as a
   `token` with an error note)
3. `{"type":"token","delta":"","done":true}`
4. `{"type":"thinking","on":false}`

This is `azula serve`'s canned-fallback LLM relay specifically; `azula
mcp`/`message send`/etc. speak the same `chat`/`token`/`thinking` frames but
as an ordinary MCP-tool-backed chat, not a shared upstream MCP session.

### Remote shell flow

The client opens the bi stream and writes first. If its first frame is
`term_attach`, the session is persistent (see `azula terminal` above) —
otherwise it's the legacy behavior: on connect the server sends an initial
`term` banner line, PTY output is forwarded as `term` frames, and incoming
`input` frames are written verbatim to the PTY stdin (the client is
responsible for any trailing newline); the shell dies the instant the stream
closes, no trace left behind.

## Crate layout

This is a Cargo workspace: the root `azula` package (a library + the `azula`
binary) and a `demos/` member (the `azula-demos` binary), so the demo tools
build independently from the production server and don't bloat its binary.

```
azula-cli/
├── Cargo.toml    # workspace root + the `azula` package (lib + bin)
├── README.md
├── .gitignore
├── src/
│   ├── lib.rs         # pub mod declarations — the `azula` library other crates depend on
│   ├── main.rs        # process entry point: stderr-only logging, hands off to cli::run()
│   ├── proto.rs       # Frame enum + read_frame / write_frame helpers
│   ├── cli/           # the noun-verb CLI surface (clap) — one thin module per noun
│   │   ├── mod.rs         # top-level Cli/Command, dispatch, shared --device/--session args
│   │   ├── mcp_cmd.rs      # `mcp [--http]` + the deprecated `serve-mcp` alias
│   │   ├── message.rs      # `message send|recv`
│   │   ├── ui.rs           # `ui render|update|delete|catalog`
│   │   ├── file.rs         # `file send`
│   │   ├── watch_cmd.rs    # `watch` — the JSONL inbox follower
│   │   ├── status_cmd.rs   # `status`
│   │   ├── run_cmd.rs      # `run` — the PTY wrapper + failure handoff
│   │   ├── terminal_cmd.rs # `terminal [new|list|attach|kill]`
│   │   ├── relay_cmd.rs    # `relay`
│   │   └── legacy.rs       # pair/devices/qr/invite/invites/link, and the deprecated serve/mailbox
│   ├── core/           # SessionCore — the shared connection layer the CLI and MCP tools both call
│   │   ├── mod.rs         # SessionCore, establish(), send/render/delivery-chain logic
│   │   ├── device.rs       # DeviceConn/DeviceMap, dial + accept + reconnect plumbing
│   │   ├── state.rs        # runtime state file ($TMPDIR/azula/bridge.json)
│   │   ├── status.rs       # `azula status`'s disk-only report
│   │   ├── watch.rs        # `azula watch --json`'s event model
│   │   └── relay_a2ui.rs   # the relay's bounded A2UI snapshot side store
│   ├── bridge/         # the AzulaBridge MCP tool surface — thin wrappers over SessionCore
│   │   ├── mod.rs         # setup_bridge / run / run_stdio entrypoints
│   │   ├── tools.rs        # the 13 #[tool] MCP methods
│   │   └── tests.rs        # in-process iroh integration tests
│   ├── term.rs        # PTY bridge (azula/term/0): legacy + persistent-session paths
│   ├── mcp.rs          # LLM relay handler: rmcp MCP client + result streaming + canned fallback
│   ├── mailbox_role.rs # `azula relay`/`azula mailbox`: chat/LLM/sync/link ALPN serving
│   ├── mailbox.rs      # per-device offline frame queue (send_message/say fallback), flushed on reconnect
│   ├── eventlog.rs     # the identity log entry codec (incl. agent_in/agent_out kinds)
│   ├── sync.rs         # the azula/sync/0 protocol session
│   ├── accept_gate.rs  # invite- and cert-aware accept-side admission gates
│   ├── identity.rs     # persisted secret keys per identity name; machine.key adoption
│   ├── session.rs      # per-process session key resolution (named vs. ephemeral)
│   ├── certs.rs        # azd/azr/azl codecs; FLAG_SESSION mint/verify
│   ├── linked_identity.rs # this device's own granted cert + identity bundle, once `azula link`ed
│   ├── catalog.rs      # the single A2UI catalog string (CLI + MCP tool description share it)
│   ├── endpoint.rs     # shared bind_server_endpoint / bind_endpoint_with_secret / print_banner helpers
│   ├── link.rs         # parse_ticket: URL / bare-token → token string
│   ├── qr.rs           # pairing_url / render_qr / print_pairing helpers
│   ├── invite.rs       # signed invite mint/verify/revoke
│   ├── filexfer.rs     # file-transfer chunking/mime-guessing shared by send_file
│   └── registry.rs     # device registry + relay-hints: load / add / remove / project_path / global_path
└── demos/        # azula-demos: standalone manual-testing binaries, depends on `azula` as a library
    ├── Cargo.toml
    └── src/
        ├── main.rs      # clap CLI (demo-ui / blackjack)
        ├── demo.rs      # demo-ui: dial a device and push a sample A2UI dice surface
        └── blackjack.rs # blackjack: standalone blackjack dealer served over iroh
```
