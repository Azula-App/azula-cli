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

On startup the server prints a banner like:

```
  Paste this code into the azula app to connect:

    <a long ticket string>

  Short node id: <node id>
```

Copy the ticket string and paste it into the azula app to connect. The server
runs until you press **Ctrl-C**.

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

## `serve-mcp` — the MCP↔iroh bridge

The inverse of `serve`'s LLM channel, and the runtime behind
`https://azula.app/mcp/<token>`: an **MCP server over Streamable HTTP** that an
external LLM client connects to, bridged to a running Azula app over iroh.

```sh
azula serve-mcp --app-ticket <APP_TICKET> [--bind 127.0.0.1:8765]
```

It dials the app on `azula/llm/0` using `--app-ticket` (the app's session code)
and serves an MCP endpoint at `http://<bind>/mcp` exposing two tools to the LLM:

- `get_messages` — read (and drain) what the user typed in the app's azula
  conversation.
- `send_message { text }` — reply; appears as the streamed azula-assistant
  message in the app.

If the app is unreachable the HTTP server still starts and the tools report
"not connected". v1 is **one session per process** (one `--app-ticket`);
multi-tenant routing by token is future work (see `../site/URLS.md`). Point
`mcp.azula.app` (or a Worker proxy of `/mcp/<token>`) at the `--bind` address.

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
    ├── main.rs   # clap CLI, endpoint bind, ticket print, eager MCP connect, Router, Ctrl-C
    ├── proto.rs  # Frame enum + read_frame / write_frame helpers
    ├── term.rs   # PTY bridge handler (azula/term/0)
    └── mcp.rs    # LLM relay handler: rmcp MCP client + result streaming + canned fallback
```
