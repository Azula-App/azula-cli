# Bridge store-and-forward (offline notifications)

When a device is offline at the time a `send_message` or `say` call arrives,
the bridge queues the frames on disk and delivers them when the device reconnects.

## How it works

1. `send_message` / `say` call `ensure_device`. If the device is not reachable,
   instead of returning an error the bridge enqueues the frames in a per-device
   JSONL mailbox file and returns a `queued for delivery` success result.

2. When a device reconnects — either by dialing in (`connect_device`) or by
   scanning the QR and calling in (`accept_incoming`) — `flush_mailbox` is
   called before the send stream is handed off. All queued frames are written
   to the stream in order, then the mailbox file is deleted.

3. A background task runs every 25 seconds. It checks every disconnected device
   that has pending mail and attempts to reconnect it. If the reconnect succeeds
   the flush happens automatically as part of step 2.

## Mailbox location

In order of preference:

| Priority | Path |
|----------|------|
| 1 | `$AZULA_MAILBOX_DIR` (env var — useful for tests) |
| 2 | `~/.azula/mailbox/` (next to the global registry) |
| 3 | `$TMPDIR/azula/mailbox/` (fallback) |

Each device gets its own file: `<sanitized-name>.jsonl`. Non-alphanumeric
characters in the device name are replaced with `_`.

## Cap

The mailbox is capped at 1 000 frames per device. When a new batch would
exceed the cap the oldest frames are dropped and only the newest 1 000 are kept.

## Testing

```
cargo test mailbox        # unit tests in mailbox.rs
cargo test offline_queue  # integration test in bridge.rs
```
