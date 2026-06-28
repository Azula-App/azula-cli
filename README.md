# azula

Server-side companion for the **azula** p2p app. It runs on a server, binds an
[iroh](https://iroh.computer) endpoint, prints a shareable ticket, and serves
two ALPN protocols to connecting azula app clients:

- **`azula/llm/0`** — an LLM relay that acts as an **MCP (Model Context
  Protocol) client**. At startup the server opens one shared MCP session to an
  upstream MCP server (a spawned stdio child process, or a remote Streamable
  HTTP / SSE endpoint). Each `chat` message from an azula app client is pushed
  into that session by calling a tool, and the tool's text result is streamed
  back. If no MCP server is configured (or the connect fails), the relay streams
  a short canned notice instead of erroring.
- **`azula/term/0`** — a remote shell ("SSH"-like) bridge that runs your shell
  inside a PTY and streams it over the connection.

The MCP client is built on the official Rust MCP SDK,
[`rmcp`](https://github.com/modelcontextprotocol/rust-sdk).

This is a standalone Cargo crate. It is **not** part of the Amper/Kotlin build
in the rest of the repository.

## Build

```sh
cd azula-cli
cargo build
```

(Requires a recent stable Rust toolchain. The first build fetches crates from
crates.io, so network access is needed.)

## Run

```sh
cargo run                 # equivalent to `cargo run -- serve`
cargo run -- serve
```

On startup the server prints a banner and a **pairing URL + QR code**:

```
  Paste this code into the azula app to connect:

    <a long ticket string>

  Short node id: <node id>

  Pair by scanning:

  https://azula.app/s/<ticket>

  ██▀▀▀██ …
  …QR…
  Scan with your phone's camera, or open the URL.
```

Point your phone camera at the QR — iOS and Android will offer to open the
azula app and dial in automatically. The server runs until you press **Ctrl-C**.

### Flags / environment

| Flag                | Env var                 | Default     | Meaning                                                                 |
| ------------------- | ----------------------- | ----------- | ----------------------------------------------------------------------- |
| `--mcp-stdio`       | `AZULA_MCP_STDIO`       | _(unset)_   | Full command line for an MCP server to spawn over stdio                 |
| `--mcp-url`         | `AZULA_MCP_URL`         | _(unset)_   | URL of a remote MCP server (Streamable HTTP / SSE)                      |
| `--mcp-tool`        | `AZULA_MCP_TOOL`        | _(first)_   | Tool to call to push a message; defaults to the first tool listed       |
| `--mcp-message-arg` | `AZULA_MCP_MESSAGE_ARG` | `message`   | JSON argument name carrying the message text                            |
| —                   | `RUST_LOG`              | `info`      | Log filter (`tracing-subscriber`)                                       |

`--mcp-stdio` and `--mcp-url` are **mutually exclusive** — set at most one. If
**neither** is set, the LLM relay does not error: it streams back a short
word-by-word notice (`azula: no MCP server configured …`) so the end-to-end
iroh path stays testable. A warning is logged at startup.

The MCP session is established **eagerly at startup**. If the connect fails, a
warning is logged and the relay falls back to the canned notice rather than
crashing.

#### Examples

Spawn a local MCP server over stdio (Node's reference "everything" server):

```sh
cargo run -- serve --mcp-stdio "npx -y @modelcontextprotocol/server-everything"
```

Connect to a remote MCP server over Streamable HTTP / SSE:

```sh
cargo run -- serve --mcp-url https://example.com/mcp
```

Pick a specific tool and message argument:

```sh
cargo run -- serve \
  --mcp-stdio "npx -y @modelcontextprotocol/server-everything" \
  --mcp-tool echo --mcp-message-arg message
```

## `azula qr` — print a QR code for any ticket

Display a pairing URL and scannable QR code for any ticket, URL, or bare token:

```sh
azula qr <CODE>
```

`<CODE>` accepts the same forms as `azula pair`:
- `https://azula.app/s/<token>`
- `https://azula.app/connect/<token>`
- `azula://connect?code=<token>`
- a bare token string

Handy for regenerating a QR when the terminal has scrolled past the startup
banner, or for sharing a pairing link in a reproducible way.

```sh
azula qr "https://azula.app/s/abc123"
# or
azula qr abc123
```

## `azula pair` — register a device

Save an azula app's ticket to the local device registry so `serve-mcp` can
connect to it automatically.

```sh
azula pair <URL> [--name <NAME>] [--global]
```

`<URL>` accepts any of:
- `https://azula.app/s/<token>`
- `https://azula.app/connect/<token>`
- `azula://connect?code=<token>`
- a bare token string

`--name` sets the display name (defaults to the first 8 characters of the
token). `--global` writes to `~/.azula/devices.json` instead of the
project-local `.azula/devices.json` (the project file is used when inside a git
tree).

```sh
azula pair "https://azula.app/s/abc123" --name myphone
azula pair "azula://connect?code=abc123" --name myphone --global
```

## `azula devices` — list registered devices

Print the known device registry (merged from global and project files).

```sh
azula devices
```

Output example:

```
NAME                 FINGERPRINT  SOURCE
------------------------------------------------
laptop               testtoke…    project
myphone              abc12345…    global
```

Source is `project` (`.azula/devices.json` at git root) or `global`
(`~/.azula/devices.json`). Project entries win on name collision.

## `serve-mcp` — multi-device MCP↔iroh bridge

The inverse of `serve`'s LLM channel: an **MCP server over Streamable HTTP**
that an external LLM client connects to, bridging that LLM to one or more
running Azula app devices over iroh.

```sh
azula serve-mcp [--bind 127.0.0.1:8765] [--device <URL>]...
```

On startup the bridge loads the device registry (global + project) and:

1. **Dials** every known registered device in the background (non-fatal on
   failure — `list_devices` will show them as offline).
2. **Accepts** incoming connections from devices that scanned the bridge's own
   QR code (printed at startup, also available via the `start_pairing` MCP
   tool). Each scanned-in device is registered automatically under a name
   derived from its remote node-id (e.g. `scan-f1aef7d5`), and behaves
   identically to a registered dialled device for all tools.

`--device` is repeatable and accepts the same URL / token forms as `azula pair`.

The MCP endpoint is at `http://<bind>/mcp`. Add it to any MCP-capable LLM
client.

### MCP tools

| Tool             | Description                                                                          |
| ---------------- | ------------------------------------------------------------------------------------ |
| `connect`        | Pair a new device by URL/token; dials immediately                                    |
| `list_devices`   | Show all known devices and live connection status                                    |
| `send_message`   | Send text to a device (lazy-reconnects if needed)                                    |
| `get_messages`   | Drain the inbox of one device or all devices (chat text + `ui-event:` lines)         |
| `render_ui`      | Render an A2UI declarative surface on a device                                        |
| `update_ui`      | Update a surface's data model at a JSON-pointer path (react to a `ui-event`)          |
| `delete_ui`      | Remove a surface from a device                                                        |
| `disconnect`     | Drop a live connection; optionally remove from registry                              |
| `start_pairing`  | Return the bridge's pairing URL + a Unicode QR the user can scan to connect         |

The `start_pairing` tool returns a text block containing the URL on the first
line, the QR code inside a fenced code block, and a one-line hint. The accept
loop is already running at startup, so scanning the QR and dialling in works
immediately without any additional setup.

### A2UI — drive native UIs from the LLM

The bridge can render [A2UI](https://github.com/a2ui-project/a2ui) v0.9.1
declarative surfaces (basic catalog) in the app's azula conversation, and report
the user's interactions back. The full loop is **`render_ui` → the user taps →
`get_messages` returns a `ui-event:` line → `update_ui`**.

`render_ui` takes a flat `components` array (exactly one component must have
`"id":"root"`), an optional initial `data_model` (backing `{"path":"/ptr"}`
bindings), and an optional `surface_id` (auto-generated as `ui-<n>` otherwise). It
sends `createSurface` → `updateComponents` → `updateDataModel` and returns the
surface id.

```jsonc
// render_ui — a dice surface
{
  "device": "phone",
  "components": [
    { "id": "root",  "component": "Column", "children": ["title", "faces", "roll"] },
    { "id": "title", "component": "Text",   "text": "AZULA · DICE", "variant": "caption" },
    { "id": "faces", "component": "Text",   "text": { "path": "/you" }, "variant": "h1" },
    { "id": "rollL", "component": "Text",   "text": "ROLL" },
    { "id": "roll",  "component": "Button", "child": "rollL", "variant": "primary",
      "action": { "event": { "name": "roll" } } }
  ],
  "data_model": { "you": "?" }
}
// → "rendered surface 'ui-1' on 'phone'"
```

When the user taps the button, `get_messages` yields:

```
ui-event: {"name":"roll","surfaceId":"ui-1","sourceComponentId":"roll","context":{}}
```

React by mutating the data model:

```jsonc
// update_ui
{ "device": "phone", "surface_id": "ui-1", "path": "/you", "value": "⚄" }
```

### Flags / environment

| Flag        | Env var            | Default           | Meaning                                    |
| ----------- | ------------------ | ----------------- | ------------------------------------------ |
| `--bind`    | `AZULA_MCP_BIND`   | `127.0.0.1:8765`  | Address to serve MCP-over-HTTP on          |
| `--device`  | —                  | _(none)_          | Extra device URL (repeatable)              |

### Registry files

| Scope   | Path                           | When used                              |
| ------- | ------------------------------ | -------------------------------------- |
| project | `<git-root>/.azula/devices.json` | Inside a git tree; commit for team use |
| global  | `~/.azula/devices.json`        | Always consulted; `azula pair --global`|
| runtime | `$TMPDIR/azula/bridge.json`    | Live state: pid, bind, connection status |

### Example session

```sh
# Pair two devices
azula pair "https://azula.app/s/abc123" --name laptop
azula pair "azula://connect?code=xyz789" --name phone

# Start the bridge
azula serve-mcp --bind 127.0.0.1:8765 &

# Point your LLM client's MCP server at http://127.0.0.1:8765/mcp
# Then use the MCP tools:
#   list_devices            → shows laptop (connected) + phone (connected)
#   send_message device=laptop text="hello"
#   get_messages            → drains all inboxes
#   disconnect device=phone forget=true
```

## ALPNs

| ALPN bytes        | Protocol     |
| ----------------- | ------------ |
| `b"azula/llm/0"`  | LLM relay    |
| `b"azula/term/0"` | remote shell |

## Wire protocol

Newline-delimited JSON. Each line is one `Frame` object, internally tagged on a
`"type"` field. This matches kotlinx.serialization's default
`classDiscriminator = "type"` for a sealed `Frame` class whose variants carry
`@SerialName` annotations. Framing: write `serde_json::to_string(&frame)` plus a
trailing `'\n'`; read with a buffered `read_line`.

| `type`     | Direction        | Fields                       | Meaning                                |
| ---------- | ---------------- | ---------------------------- | -------------------------------------- |
| `chat`     | client → server  | `text`                       | LLM prompt / peer chat                 |
| `input`    | client → server  | `text`                       | terminal keystrokes / command          |
| `token`    | server → client  | `delta`, `done` (default false) | LLM token stream                    |
| `thinking` | server → client  | `on`                         | thinking indicator                     |
| `term`     | server → client  | `line`                       | shell output chunk                     |
| `widget`   | (passthrough)    | `widget` (arbitrary JSON)    | server may ignore                      |

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

### Remote shell flow

The client opens the bi stream and writes first. On connect the server sends an
initial `term` banner line. Thereafter PTY output is forwarded as `term`
frames, and incoming `input` frames are written verbatim to the PTY stdin (the
client is responsible for any trailing newline).

## Crate layout

```
azula-cli/
├── Cargo.toml
├── README.md
├── .gitignore
└── src/
    ├── main.rs      # clap CLI (serve / serve-mcp / pair / devices / qr), serve loop
    ├── proto.rs     # Frame enum + read_frame / write_frame helpers
    ├── term.rs      # PTY bridge handler (azula/term/0)
    ├── mcp.rs       # LLM relay handler: rmcp MCP client + result streaming + canned fallback
    ├── bridge.rs    # serve-mcp: multi-device AzulaBridge MCP server + accept-side handler
    ├── link.rs      # parse_ticket: URL / bare-token → token string
    ├── qr.rs        # pairing_url / render_qr / print_pairing helpers
    └── registry.rs  # Device registry: load / add / project_path / global_path
```
