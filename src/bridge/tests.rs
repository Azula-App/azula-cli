//! Integration and unit tests for the bridge: the frame-reader → inbox path,
//! bridge-to-bridge `say` relaying (with the turn cap), the offline mailbox
//! queue/flush path, and reconnect-by-node-id matching (both the pure helper
//! and the full accept-side flow).

use std::collections::HashMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use rmcp::handler::server::wrapper::Parameters;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;

use crate::filexfer;
use crate::mailbox;
use crate::mcp::LLM_ALPN;
use crate::proto::{read_frame, write_frame, Frame};
use crate::registry::Device;

use super::device::{dial_device, match_known_device, read_frames_into, BridgeAcceptHandler, DeviceConn, DeviceMap, Inbox};
use super::tools::{AzulaBridge, ConnectArgs, GetMessagesArgs, SayArgs, SendFileArgs, SendMessageArgs};

/// The reader surfaces user chat text verbatim and turns an A2UI action
/// (sent by the app when a user taps a surface) into a `ui-event:` line the
/// LLM can parse from `get_messages`.
#[tokio::test]
async fn reader_surfaces_chat_and_ui_events() {
    let (mut writer, reader) = tokio::io::duplex(8192);
    let inbox: Inbox = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
    let inbox_reader = inbox.clone();
    let handle = tokio::spawn(async move {
        read_frames_into(BufReader::new(reader), inbox_reader).await;
    });

    let chat = serde_json::to_string(&Frame::Chat { text: "hello".into() }).unwrap();
    let action = serde_json::json!({
        "name": "roll", "surfaceId": "dice-1", "sourceComponentId": "rollBtn", "context": {}
    });
    let act = serde_json::to_string(&Frame::A2uiAction { action }).unwrap();
    writer.write_all(format!("{chat}\n{act}\n").as_bytes()).await.unwrap();
    writer.shutdown().await.unwrap(); // EOF → reader_loop returns
    handle.await.unwrap();

    let got: Vec<String> = inbox.lock().unwrap().drain(..).collect();
    assert_eq!(got.len(), 2, "expected 2 inbox lines, got {got:?}");
    assert_eq!(got[0], "hello");
    assert!(got[1].starts_with("ui-event: "), "not a ui-event line: {}", got[1]);
    assert!(got[1].contains(r#""name":"roll""#), "missing action name: {}", got[1]);
    assert!(got[1].contains(r#""surfaceId":"dice-1""#), "missing surfaceId: {}", got[1]);
}

/// An inbound `file_begin`/`file_chunk`×N/`file_end` sequence is reassembled
/// to disk and surfaced in the inbox as a `[received file: ...]` line naming
/// the saved (absolute) path — the same reader path `get_messages`/
/// `wait_for_reply` expose.
#[tokio::test]
async fn reader_reassembles_incoming_file() {
    let recv_dir = std::env::temp_dir()
        .join(format!("azula-bridge-test-{}", std::process::id()))
        .join("reader_reassembles_incoming_file");
    let _ = std::fs::remove_dir_all(&recv_dir);
    std::env::set_var("AZULA_RECEIVED_DIR", &recv_dir);

    let (mut writer, reader) = tokio::io::duplex(8192);
    let inbox: Inbox = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
    let inbox_reader = inbox.clone();
    let handle = tokio::spawn(async move {
        read_frames_into(BufReader::new(reader), inbox_reader).await;
    });

    let bytes = b"hello file bytes".to_vec(); // 16 bytes
    let frames = filexfer::build_file_frames(
        "xfer-1".into(),
        "note.txt".into(),
        "text/plain".into(),
        Some("a caption".into()),
        &bytes,
    )
    .unwrap();

    let mut wire = String::new();
    for f in &frames {
        wire.push_str(&serde_json::to_string(f).unwrap());
        wire.push('\n');
    }
    writer.write_all(wire.as_bytes()).await.unwrap();
    writer.shutdown().await.unwrap();
    handle.await.unwrap();

    let got: Vec<String> = inbox.lock().unwrap().drain(..).collect();
    assert_eq!(got.len(), 1, "expected one inbox line, got {got:?}");
    assert!(
        got[0].starts_with("[received file: note.txt (text/plain, 16 bytes) -> "),
        "unexpected line: {}",
        got[0]
    );
    assert!(got[0].contains("caption: a caption"), "missing caption: {}", got[0]);

    // Extract the saved path (between "-> " and the closing "]") and verify
    // the bytes on disk match what was sent.
    let after_arrow = got[0].split("-> ").nth(1).expect("line should contain a path");
    let path_str = after_arrow.split(']').next().expect("path should be bracket-terminated");
    let saved = std::fs::read(path_str).unwrap_or_else(|e| panic!("reading saved file {path_str}: {e}"));
    assert_eq!(saved, bytes);

    std::env::remove_var("AZULA_RECEIVED_DIR");
    let _ = std::fs::remove_dir_all(&recv_dir);
}

/// A `FileBegin` declaring a size over the 64 MiB cap is rejected up front:
/// the transfer is dropped (subsequent chunks/end for that id are skipped)
/// and a `[rejected file: ...]` line is surfaced instead of a saved file.
#[tokio::test]
async fn reader_rejects_oversize_incoming_file() {
    let (mut writer, reader) = tokio::io::duplex(8192);
    let inbox: Inbox = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
    let inbox_reader = inbox.clone();
    let handle = tokio::spawn(async move {
        read_frames_into(BufReader::new(reader), inbox_reader).await;
    });

    let begin = Frame::FileBegin {
        id: "big-1".into(),
        name: "huge.bin".into(),
        mime: "application/octet-stream".into(),
        size: filexfer::MAX_FILE_BYTES + 1,
        encoding: "base64".into(),
        caption: None,
    };
    let chunk = Frame::FileChunk { id: "big-1".into(), seq: 0, data: "aWdub3JlZA==".into() };
    let end = Frame::FileEnd { id: "big-1".into() };

    let mut wire = String::new();
    for f in [&begin, &chunk, &end] {
        wire.push_str(&serde_json::to_string(f).unwrap());
        wire.push('\n');
    }
    writer.write_all(wire.as_bytes()).await.unwrap();
    writer.shutdown().await.unwrap();
    handle.await.unwrap();

    let got: Vec<String> = inbox.lock().unwrap().drain(..).collect();
    assert_eq!(got.len(), 1, "expected only the rejection line, got {got:?}");
    assert!(got[0].starts_with("[rejected file: huge.bin"), "unexpected line: {}", got[0]);
    assert!(!got[0].contains("received file"), "should not report a saved file: {}", got[0]);
}

/// End-to-end over a real iroh connection: Alice's `send_file` tool reads a
/// local file and streams it to Bob; Bob's accept-side reader reassembles it
/// and surfaces a `[received file: ...]` line naming a path with matching
/// bytes on disk. Exercises the exact wire path an LLM client drives.
#[tokio::test]
async fn send_file_tool_delivers_over_iroh() {
    let recv_dir = std::env::temp_dir()
        .join(format!("azula-bridge-test-{}", std::process::id()))
        .join("send_file_tool_delivers_over_iroh");
    let _ = std::fs::remove_dir_all(&recv_dir);
    std::env::set_var("AZULA_RECEIVED_DIR", &recv_dir);

    let alice_raw_ep = Endpoint::bind(presets::Minimal).await.unwrap();
    let bob_raw_ep = Endpoint::bind(presets::Minimal).await.unwrap();

    let alice_devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));
    let bob_devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));
    let bind_placeholder = "127.0.0.1:0".to_string();

    let alice_accept = BridgeAcceptHandler::new(alice_devices.clone(), bind_placeholder.clone(), "Alice".to_string());
    let alice_router = Router::builder(alice_raw_ep).accept(LLM_ALPN, alice_accept).spawn();
    let bob_accept = BridgeAcceptHandler::new(bob_devices.clone(), bind_placeholder.clone(), "Bob".to_string());
    let bob_router = Router::builder(bob_raw_ep).accept(LLM_ALPN, bob_accept).spawn();

    let alice_ep = Arc::new(alice_router.endpoint().clone());
    let bob_ep = Arc::new(bob_router.endpoint().clone());
    let bob_ticket = EndpointTicket::new(bob_ep.addr()).to_string();

    let alice = AzulaBridge::new(alice_ep.clone(), alice_devices.clone(), bind_placeholder.clone(), "alice-ticket".to_string(), "alice".to_string(), 20);

    // Write a small "image" to send.
    let src_path = std::env::temp_dir()
        .join(format!("azula-bridge-test-{}", std::process::id()))
        .join("send_file_tool_delivers_over_iroh-src.png");
    std::fs::create_dir_all(src_path.parent().unwrap()).unwrap();
    let payload = b"not really a png but bytes are bytes".to_vec();
    std::fs::write(&src_path, &payload).unwrap();

    // Alice connects to Bob, then sends the file.
    let connect_result = alice
        .connect(Parameters(ConnectArgs { url: bob_ticket.clone(), name: Some("bob".to_string()) }))
        .await
        .unwrap();
    assert!(!connect_result.is_error.unwrap_or(false), "connect should succeed: {connect_result:?}");

    let send_result = alice
        .send_file(Parameters(SendFileArgs {
            device: "bob".to_string(),
            path: src_path.to_str().unwrap().to_string(),
            caption: Some("a test image".to_string()),
        }))
        .await
        .unwrap();
    assert!(!send_result.is_error.unwrap_or(false), "send_file should succeed: {send_result:?}");
    let send_text = send_result.content.iter().filter_map(|c| c.as_text().map(|t| t.text.as_str())).collect::<Vec<_>>().join("\n");
    assert!(send_text.contains("image/png"), "should infer image/png from .png extension: {send_text}");

    // Wait for Bob's reader to reassemble the file into his inbox.
    let mut bob_inbox_text = String::new();
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let guard = bob_devices.lock().await;
        if let Some(conn) = guard.get("alice") {
            let msgs: Vec<String> = conn.inbox.lock().unwrap().iter().cloned().collect();
            if !msgs.is_empty() {
                bob_inbox_text = msgs.join("\n");
                break;
            }
        }
    }

    assert!(
        bob_inbox_text.starts_with("[received file:"),
        "expected a received-file line, got: {bob_inbox_text:?}"
    );
    assert!(bob_inbox_text.contains("image/png"), "{bob_inbox_text}");
    assert!(bob_inbox_text.contains(&format!("{} bytes", payload.len())), "{bob_inbox_text}");
    assert!(bob_inbox_text.contains("caption: a test image"), "{bob_inbox_text}");

    let after_arrow = bob_inbox_text.split("-> ").nth(1).expect("line should contain a path");
    let path_str = after_arrow.split(']').next().expect("path should be bracket-terminated");
    let saved = std::fs::read(path_str).unwrap_or_else(|e| panic!("reading saved file {path_str}: {e}"));
    assert_eq!(saved, payload);

    alice_router.shutdown().await.unwrap();
    bob_router.shutdown().await.unwrap();
    std::env::remove_var("AZULA_RECEIVED_DIR");
    let _ = std::fs::remove_dir_all(&recv_dir);
    let _ = std::fs::remove_file(&src_path);
}

/// Two bridges connect to each other over iroh. Alice dials Bob, says "ping",
/// Bob says "pong" back. The turn limit is enforced at 3 turns.
#[tokio::test]
async fn bridge_to_bridge_relay() {
    // Bind two separate iroh endpoints.  We use Minimal (no relay) so the
    // test works offline; we skip `online()` since that waits for a relay.
    let alice_raw_ep = Endpoint::bind(presets::Minimal).await.unwrap();
    let bob_raw_ep = Endpoint::bind(presets::Minimal).await.unwrap();

    let alice_devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));
    let bob_devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));

    let bind_placeholder = "127.0.0.1:0".to_string();

    // Build iroh routers with accept handlers.
    let alice_accept = BridgeAcceptHandler::new(alice_devices.clone(), bind_placeholder.clone(), "Alice".to_string());
    let alice_router = Router::builder(alice_raw_ep)
        .accept(LLM_ALPN, alice_accept)
        .spawn();

    let bob_accept = BridgeAcceptHandler::new(bob_devices.clone(), bind_placeholder.clone(), "Bob".to_string());
    let bob_router = Router::builder(bob_raw_ep)
        .accept(LLM_ALPN, bob_accept)
        .spawn();

    let alice_ep = Arc::new(alice_router.endpoint().clone());
    let bob_ep = Arc::new(bob_router.endpoint().clone());

    let alice_ticket = EndpointTicket::new(alice_ep.addr()).to_string();
    let bob_ticket = EndpointTicket::new(bob_ep.addr()).to_string();

    // Create the AzulaBridge handles.
    let alice = AzulaBridge::new(
        alice_ep.clone(),
        alice_devices.clone(),
        bind_placeholder.clone(),
        alice_ticket.clone(),
        "alice".to_string(),
        3,
    );
    let bob = AzulaBridge::new(
        bob_ep.clone(),
        bob_devices.clone(),
        bind_placeholder.clone(),
        bob_ticket.clone(),
        "bob".to_string(),
        3,
    );

    // Alice connects to Bob.
    let connect_result = alice
        .connect(Parameters(ConnectArgs {
            url: bob_ticket.clone(),
            name: Some("bob".to_string()),
        }))
        .await
        .unwrap();
    assert!(
        !connect_result.is_error.unwrap_or(false),
        "connect should succeed: {:?}",
        connect_result
    );

    // Wait for Bob's accept handler to register "alice".
    let mut registered = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let guard = bob_devices.lock().await;
        if guard.contains_key("alice") {
            registered = true;
            break;
        }
    }
    assert!(registered, "bob should have 'alice' in his device map after hello");

    // Alice says "ping" to Bob.
    let say_result = alice
        .say(Parameters(SayArgs {
            device: "bob".to_string(),
            text: "ping".to_string(),
            done: None,
        }))
        .await
        .unwrap();
    assert!(
        !say_result.is_error.unwrap_or(false),
        "alice say ping should succeed: {:?}",
        say_result
    );

    // Give Bob's reader a moment to drain the frame into his inbox.
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let guard = bob_devices.lock().await;
        if let Some(conn) = guard.get("alice") {
            if !conn.inbox.lock().unwrap().is_empty() {
                break;
            }
        }
    }

    // Drain Bob's inbox via get_messages and assert it contains "ping".
    let bob_msgs = bob
        .get_messages(Parameters(GetMessagesArgs { device: Some("alice".to_string()) }))
        .await
        .unwrap();
    assert!(
        !bob_msgs.is_error.unwrap_or(false),
        "get_messages should succeed: {:?}",
        bob_msgs
    );
    let bob_text = bob_msgs.content.iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(bob_text.contains("ping"), "bob inbox should contain 'ping', got: {bob_text}");

    // Bob needs to connect back to Alice to reply.
    let bob_connect = bob
        .connect(Parameters(ConnectArgs {
            url: alice_ticket.clone(),
            name: Some("alice".to_string()),
        }))
        .await
        .unwrap();
    assert!(
        !bob_connect.is_error.unwrap_or(false),
        "bob connect to alice should succeed: {:?}",
        bob_connect
    );

    // Wait for Alice's accept handler to see bob.
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let guard = alice_devices.lock().await;
        if guard.contains_key("bob") {
            break;
        }
    }

    // Bob says "pong" to Alice.
    let pong_result = bob
        .say(Parameters(SayArgs {
            device: "alice".to_string(),
            text: "pong".to_string(),
            done: None,
        }))
        .await
        .unwrap();
    assert!(
        !pong_result.is_error.unwrap_or(false),
        "bob say pong should succeed: {:?}",
        pong_result
    );

    // Wait for Alice's inbox to receive "pong".
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let guard = alice_devices.lock().await;
        if let Some(conn) = guard.get("bob") {
            if !conn.inbox.lock().unwrap().is_empty() {
                break;
            }
        }
    }

    // Drain Alice's inbox and assert it contains "pong".
    let alice_msgs = alice
        .get_messages(Parameters(GetMessagesArgs { device: Some("bob".to_string()) }))
        .await
        .unwrap();
    assert!(
        !alice_msgs.is_error.unwrap_or(false),
        "get_messages should succeed: {:?}",
        alice_msgs
    );
    let alice_text = alice_msgs.content.iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(alice_text.contains("pong"), "alice inbox should contain 'pong', got: {alice_text}");

    // Drive Alice past max_turns=3: she's used 1 turn (ping). Say 2 more to hit the limit.
    // Turn 2
    let t2 = alice
        .say(Parameters(SayArgs {
            device: "bob".to_string(),
            text: "turn2".to_string(),
            done: None,
        }))
        .await
        .unwrap();
    assert!(!t2.is_error.unwrap_or(false), "turn 2 should succeed: {:?}", t2);

    // Turn 3
    let t3 = alice
        .say(Parameters(SayArgs {
            device: "bob".to_string(),
            text: "turn3".to_string(),
            done: None,
        }))
        .await
        .unwrap();
    assert!(!t3.is_error.unwrap_or(false), "turn 3 should succeed: {:?}", t3);

    // Turn 4 — over the limit (max=3).
    let t4 = alice
        .say(Parameters(SayArgs {
            device: "bob".to_string(),
            text: "turn4".to_string(),
            done: None,
        }))
        .await
        .unwrap();
    assert!(
        t4.is_error.unwrap_or(false),
        "turn 4 should fail (over limit): {:?}",
        t4
    );
    assert!(
        alice_devices.lock().await
            .get("bob")
            .map(|c| c.closed.load(Relaxed))
            .unwrap_or(false),
        "bob conn should be closed after turn limit"
    );

    // Subsequent say should immediately return closed error.
    let t5 = alice
        .say(Parameters(SayArgs {
            device: "bob".to_string(),
            text: "turn5".to_string(),
            done: None,
        }))
        .await
        .unwrap();
    assert!(
        t5.is_error.unwrap_or(false),
        "turn 5 should fail (conversation closed): {:?}",
        t5
    );

    // Cleanup.
    alice_router.shutdown().await.unwrap();
    bob_router.shutdown().await.unwrap();
}

/// Tests that messages for an offline device are queued and then flushed
/// when the device reconnects. Uses in-memory duplex for the flush path.
#[tokio::test]
async fn offline_queue_then_flush() {
    // Set a unique mailbox dir for this test so it doesn't interfere with others.
    let mbox_dir = std::env::temp_dir()
        .join(format!("azula-bridge-test-{}", std::process::id()))
        .join("offline_queue");
    std::env::set_var("AZULA_MAILBOX_DIR", &mbox_dir);

    let ep = Endpoint::bind(presets::Minimal).await.unwrap();
    let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));
    let bind_placeholder = "127.0.0.1:0".to_string();
    let ep_arc = Arc::new(ep.clone());

    // Register "phone" as disconnected with a placeholder ticket.
    {
        let mut guard = devices.lock().await;
        guard.insert("phone".to_string(), DeviceConn::new("placeholder_ticket".to_string()));
    }

    let alice = AzulaBridge::new(
        ep_arc.clone(),
        devices.clone(),
        bind_placeholder.clone(),
        "alice-ticket".to_string(),
        "alice".to_string(),
        20,
    );

    // send_message to offline "phone" should queue, not error.
    let result = alice
        .send_message(Parameters(SendMessageArgs {
            device: "phone".to_string(),
            text: "hi while you were away".to_string(),
        }))
        .await
        .unwrap();

    assert!(
        !result.is_error.unwrap_or(false),
        "send_message to offline device should return success (queued): {:?}",
        result
    );
    let result_text = result.content.iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect::<Vec<_>>()
        .join("");
    assert!(
        result_text.contains("queued"),
        "result should mention 'queued', got: {result_text}"
    );

    // has_pending should be true.
    assert!(
        mailbox::has_pending("phone"),
        "mailbox should have pending frames for 'phone'"
    );

    // Now test the flush: create an in-memory duplex and flush to it.
    let (mut send_stream, recv_stream) = tokio::io::duplex(65536);

    // Collect received frames.
    let handle = tokio::spawn(async move {
        let mut reader = BufReader::new(recv_stream);
        let mut frames = vec![];
        while let Ok(Some(f)) = read_frame(&mut reader).await {
            frames.push(f);
        }
        frames
    });

    // Use flush_mailbox via a wrapper — but flush_mailbox is private.
    // Instead call enqueue/load/clear directly to simulate the flush.
    let queued = mailbox::load("phone");
    for f in &queued {
        write_frame(&mut send_stream, f).await.unwrap();
    }
    mailbox::clear("phone");
    drop(send_stream); // EOF so reader task ends.

    let received = handle.await.unwrap();

    // Should receive thinking(true), token("hi while you were away"), token_done, thinking(false).
    assert_eq!(received.len(), 4, "expected 4 frames, got: {received:?}");
    assert!(matches!(&received[0], Frame::Thinking { on: true }));
    assert!(
        matches!(&received[1], Frame::Token { delta, .. } if delta == "hi while you were away"),
        "second frame should be token with text, got: {:?}", received[1]
    );
    assert!(matches!(&received[2], Frame::Token { done: true, .. }));
    assert!(matches!(&received[3], Frame::Thinking { on: false }));

    // After flush and clear, has_pending should be false.
    assert!(
        !mailbox::has_pending("phone"),
        "mailbox should be empty after flush"
    );

    // Clean up env var.
    std::env::remove_var("AZULA_MAILBOX_DIR");
}

// -----------------------------------------------------------------------
// Unit test: match_known_device pure helper
// -----------------------------------------------------------------------

/// Verifies that `match_known_device` finds a device whose ticket encodes
/// the given remote node id and returns its name, and returns None when
/// no ticket matches.
#[tokio::test]
async fn match_known_device_by_node_id() {
    // Build two iroh endpoints to get real, distinct node ids.
    let ep_phone = Endpoint::bind(presets::Minimal).await.unwrap();
    let ep_other = Endpoint::bind(presets::Minimal).await.unwrap();

    let phone_id = ep_phone.id();
    let other_id = ep_other.id();
    let stranger_ep = Endpoint::bind(presets::Minimal).await.unwrap();
    let stranger_id = stranger_ep.id();

    // Build tickets from the endpoints.
    let phone_ticket = EndpointTicket::new(ep_phone.addr()).to_string();
    let other_ticket = EndpointTicket::new(ep_other.addr()).to_string();

    // Device map: "phone" with phone's ticket, "other" with other's ticket.
    let mut map: HashMap<String, DeviceConn> = HashMap::new();
    map.insert("phone".to_string(), DeviceConn::new(phone_ticket.clone()));
    map.insert("other".to_string(), DeviceConn::new(other_ticket.clone()));

    // Empty registry (no on-disk devices in this test).
    let reg: Vec<Device> = vec![];

    // phone_id → "phone"
    assert_eq!(
        match_known_device(&phone_id, &map, &reg),
        Some("phone".to_string()),
        "phone's node id should match 'phone'"
    );

    // other_id → "other"
    assert_eq!(
        match_known_device(&other_id, &map, &reg),
        Some("other".to_string()),
        "other's node id should match 'other'"
    );

    // stranger_id → None (not in map or registry)
    assert_eq!(
        match_known_device(&stranger_id, &map, &reg),
        None,
        "unknown node id should return None"
    );

    // Now test registry path: device only in registry, not in map.
    let map_empty: HashMap<String, DeviceConn> = HashMap::new();
    let reg_with_phone = vec![Device {
        name: "phone-reg".to_string(),
        ticket: phone_ticket.clone(),
        added_at: None,
    }];
    assert_eq!(
        match_known_device(&phone_id, &map_empty, &reg_with_phone),
        Some("phone-reg".to_string()),
        "should find device registered only in registry"
    );

    // Map wins over registry on name collision for same ticket.
    let reg_conflict = vec![Device {
        name: "phone-reg".to_string(),
        ticket: phone_ticket.clone(),
        added_at: None,
    }];
    assert_eq!(
        match_known_device(&phone_id, &map, &reg_conflict),
        Some("phone".to_string()),
        "in-memory map should win over registry for same node id"
    );

    ep_phone.close().await;
    ep_other.close().await;
    stranger_ep.close().await;
}

// -----------------------------------------------------------------------
// Integration test: reconnecting device is matched by node id, mail flushed
// -----------------------------------------------------------------------

/// A registered device "phone" reconnects by dialling the bridge.
/// `accept_incoming` should recognise it by node id (not assign scan-<id>)
/// and flush the offline mailbox.
#[tokio::test]
async fn reconnect_by_node_id_flushes_mailbox() {
    // Unique mailbox dir for this test.
    let mbox_dir = std::env::temp_dir()
        .join(format!("azula-bridge-test-{}-reconnect", std::process::id()));
    std::env::set_var("AZULA_MAILBOX_DIR", &mbox_dir);
    // Clean slate.
    let _ = std::fs::remove_dir_all(&mbox_dir);

    // Two endpoints: bridge and phone.
    let bridge_raw_ep = Endpoint::bind(presets::Minimal).await.unwrap();
    let phone_ep = Endpoint::bind(presets::Minimal).await.unwrap();

    // Build the bridge's device map with "phone" pre-registered using
    // the phone endpoint's real ticket, but disconnected.
    let phone_ticket = EndpointTicket::new(phone_ep.addr()).to_string();
    let bridge_devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));
    {
        let mut guard = bridge_devices.lock().await;
        guard.insert("phone".to_string(), DeviceConn::new(phone_ticket.clone()));
    }

    let bind_placeholder = "127.0.0.1:0".to_string();

    // Enqueue a message for "phone" in the mailbox.
    mailbox::enqueue("phone", &[
        Frame::thinking(true),
        Frame::token("hi reconnected phone".to_string()),
        Frame::token_done(),
        Frame::thinking(false),
    ]);
    assert!(
        mailbox::has_pending("phone"),
        "mailbox should have pending frames before reconnect"
    );

    // Stand up a bridge accept handler.
    let bridge_accept = BridgeAcceptHandler::new(bridge_devices.clone(), bind_placeholder.clone(), "Claude".to_string());
    let bridge_router = Router::builder(bridge_raw_ep)
        .accept(LLM_ALPN, bridge_accept)
        .spawn();
    let bridge_ep = Arc::new(bridge_router.endpoint().clone());

    // The phone dials the bridge.
    let bridge_ticket = EndpointTicket::new(bridge_ep.addr()).to_string();
    let (mut phone_send, phone_recv) = dial_device(&phone_ep, &bridge_ticket).await
        .expect("phone should be able to dial bridge");

    // Phone sends a non-hello first frame (simulates an azula app client).
    let first_frame = Frame::thinking(false);
    write_frame(&mut phone_send, &first_frame).await
        .expect("phone should send first frame");

    // Collect frames received by the phone (the flushed mailbox).
    let recv_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(phone_recv);
        let mut frames = vec![];
        // Read up to 5 frames (hello announcement + 4 flushed) with a
        // timeout so the test doesn't hang.
        for _ in 0..5 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                read_frame(&mut reader),
            ).await {
                Ok(Ok(Some(f))) => frames.push(f),
                _ => break,
            }
        }
        frames
    });

    // Wait for the bridge's accept handler to finish registering the device.
    let mut registered_as_phone = false;
    for _ in 0..80 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let guard = bridge_devices.lock().await;
        if let Some(conn) = guard.get("phone") {
            if conn.connected {
                registered_as_phone = true;
                break;
            }
        }
    }
    assert!(
        registered_as_phone,
        "bridge should register the inbound connection under 'phone' (node-id match)"
    );

    // Confirm no scan- entry was created.
    {
        let guard = bridge_devices.lock().await;
        let scan_keys: Vec<&String> = guard.keys().filter(|k| k.starts_with("scan-")).collect();
        assert!(
            scan_keys.is_empty(),
            "no scan- entry should exist, but found: {scan_keys:?}"
        );
    }

    // Mailbox should be cleared after flush.
    assert!(
        !mailbox::has_pending("phone"),
        "mailbox should be empty after reconnect flush"
    );

    // The phone should have received the bridge's name announcement
    // followed by the queued frames.
    let received = recv_handle.await.unwrap();
    assert_eq!(
        received.len(), 5,
        "phone should receive hello + 4 flushed frames, got: {received:?}"
    );
    assert!(
        matches!(&received[0], Frame::Hello { name } if name == "Claude"),
        "first frame should announce the bridge's own name, got: {:?}", received[0]
    );
    assert!(matches!(&received[1], Frame::Thinking { on: true }));
    assert!(
        matches!(&received[2], Frame::Token { delta, .. } if delta == "hi reconnected phone"),
        "third frame should be token with text, got: {:?}", received[2]
    );
    assert!(matches!(&received[3], Frame::Token { done: true, .. }));
    assert!(matches!(&received[4], Frame::Thinking { on: false }));

    // Cleanup.
    bridge_router.shutdown().await.unwrap();
    phone_ep.close().await;
    std::env::remove_var("AZULA_MAILBOX_DIR");
}
