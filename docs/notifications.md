# Bridge store-and-forward (offline notifications)

When a device is offline at the time a `send_message` or `say` call arrives,
the bridge queues the frames on disk and delivers them when the device reconnects.

## How it works

1. `send_message` / `say` call `ensure_device`. If the device is not reachable,
   instead of returning an error the bridge enqueues the frames in a per-device
   JSONL mailbox file and returns a `queued for delivery` success result.

2. When a device reconnects — either by dialing in (`accept_incoming`) or by
   being dialed (`Dialer`, in `core/device.rs`) — `flush_mailbox` is called
   before the send stream is handed off. All queued frames are written to the
   stream in order, then the mailbox file is deleted.

3. A long-lived session (`azula mcp`, `azula watch`) runs a presence loop
   (`core/presence.rs`) that keeps trying to reconnect *every* known device that
   is not connected — not only those with mail pending. Each device has its own
   backoff, starting at 5 s and doubling to a 60 s ceiling (25 s for a device
   with mail queued, the old redelivery cadence), reset whenever the device is
   seen connected; a device you explicitly `disconnect` is left alone until the
   next send. If a reconnect succeeds the flush happens automatically as part of
   step 2, exactly as for the startup dial.

   The same loop is why a phone that went offline stays reachable: a connection
   whose stream ends is marked disconnected (and reported as a `disconnected`
   event from `get_events`), and the loop dials it again.

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
