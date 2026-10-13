//! Presence maintenance: while a long-lived session runs, keep trying to reach
//! every known device that isn't connected.
//!
//! The phone shows a conversation as online only while a live stream is wired
//! to it, and a bridge session — one admitted by its certificate rather than
//! dialed from a saved ticket — is never redialed by the app. So coming back
//! online after a gateway restart, a dropped link, or the app having been
//! asleep at startup depends entirely on *this* side dialing the phone again.
//!
//! This replaces the old 25 s loop that retried only devices with queued mail.
//! That was redelivery, not presence: a device with nothing queued was dialed
//! once at startup and never again.
//!
//! Each device carries its own backoff: an attempt is made as soon as the loop
//! sees it down, then after `initial_backoff`, doubling to `max_backoff`
//! (devices with mail queued are capped lower, at the old 25 s cadence). The
//! schedule resets whenever a tick observes the device connected, so a link
//! that holds starts over at the short delay while one that is refused over and
//! over (a phone still awaiting approval closes the stream each time) backs
//! off instead of hammering it. A phone that comes back is therefore reached
//! within about `max_backoff` plus a dial.
//!
//! Dials respect the per-device lock in [`super::device::DeviceConn::dial_lock`]
//! (a busy device is skipped, never queued behind) and run as spawned tasks so
//! one device that hangs in a handshake doesn't hold up another. The returned
//! [`PresenceGuard`] aborts the loop and every dial it started when dropped, so
//! it ends with the session and a one-shot verb's exit never waits on it.

use std::collections::HashMap;
use std::time::Duration;

use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;

use super::device::Dialer;
use crate::mailbox;

/// Timings for [`spawn`]. Configurable so tests can run the loop in
/// milliseconds; production uses [`Default`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct PresenceTimings {
    /// How often the loop looks at the device map. Also the granularity of
    /// every other delay here.
    pub(crate) tick: Duration,
    /// Delay after the first attempt at a device that is down.
    pub(crate) initial_backoff: Duration,
    /// Ceiling the per-device delay doubles up to.
    pub(crate) max_backoff: Duration,
    /// Lower ceiling for a device with mail queued — the old redelivery loop's
    /// 25 s cadence, kept so queued mail is never retried *less* often than
    /// before.
    pub(crate) redelivery_backoff: Duration,
    /// Give up on a single dial after this long (the loop would otherwise sit
    /// on a device whose handshake never completes).
    pub(crate) dial_timeout: Duration,
}

impl Default for PresenceTimings {
    fn default() -> Self {
        PresenceTimings {
            tick: Duration::from_secs(5),
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(60),
            redelivery_backoff: Duration::from_secs(25),
            dial_timeout: Duration::from_secs(30),
        }
    }
}

/// Stops the presence loop (and any dial it has in flight) when dropped.
pub(crate) struct PresenceGuard(AbortHandle);

impl Drop for PresenceGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Start the loop. It first acts one `tick` from now — the startup dial in
/// `establish` has just run, and a one-shot verb is usually gone before then.
pub(crate) fn spawn(dialer: Dialer, timings: PresenceTimings) -> PresenceGuard {
    PresenceGuard(tokio::spawn(run(dialer, timings)).abort_handle())
}

/// One device's retry schedule.
struct Backoff {
    /// Not before this instant.
    next_at: Instant,
    /// Delay to apply after the *next* attempt.
    delay: Duration,
}

async fn run(dialer: Dialer, timings: PresenceTimings) {
    let mut schedule: HashMap<String, Backoff> = HashMap::new();
    // Owned by this task, so aborting the loop aborts every dial it spawned.
    let mut dials: JoinSet<()> = JoinSet::new();

    loop {
        tokio::time::sleep(timings.tick).await;
        while dials.try_join_next().is_some() {}

        let snapshot: Vec<(String, bool, bool)> = {
            let guard = dialer.devices.lock().await;
            guard.iter().map(|(name, conn)| (name.clone(), conn.connected, conn.held)).collect()
        };
        // Forget schedules for devices that were forgotten.
        schedule.retain(|name, _| snapshot.iter().any(|(n, ..)| n == name));

        let now = Instant::now();
        for (name, connected, held) in snapshot {
            if connected || held {
                // Seen up (or deliberately down): start over when it next drops.
                schedule.remove(&name);
                continue;
            }
            let entry = schedule.entry(name.clone()).or_insert(Backoff { next_at: now, delay: timings.initial_backoff });
            if now < entry.next_at {
                continue;
            }
            let ceiling = if mailbox::has_pending(&name) {
                timings.max_backoff.min(timings.redelivery_backoff)
            } else {
                timings.max_backoff
            };
            entry.next_at = now + entry.delay;
            entry.delay = (entry.delay * 2).min(ceiling);

            let dialer = dialer.clone();
            let dial_timeout = timings.dial_timeout;
            dials.spawn(async move {
                let _ = tokio::time::timeout(dial_timeout, dialer.redial_idle(&name)).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::core::test_support::{core_knowing, eventually, fast_timings, isolate, unisolate, PhoneStub};
    use crate::core::watch::{InboxEntry, WatchEvent};
    use crate::proto::Frame;
    use crate::registry;

    const WITHIN: Duration = Duration::from_secs(10);

    fn connected(device: &str) -> WatchEvent {
        WatchEvent::Connected { device: device.into() }
    }

    fn disconnected(device: &str) -> WatchEvent {
        WatchEvent::Disconnected { device: device.into() }
    }

    async fn is_connected(core: &crate::core::SessionCore, device: &str) -> bool {
        core.devices.lock().await.get(device).is_some_and(|c| c.connected)
    }

    /// The production schedule: a down device is retried every few seconds,
    /// backing off to a minute — so a phone that returns is reached in about a
    /// minute at most.
    #[test]
    fn default_timings_bound_reconnect_to_about_a_minute() {
        let t = PresenceTimings::default();
        assert_eq!(t.initial_backoff, Duration::from_secs(5));
        assert_eq!(t.max_backoff, Duration::from_secs(60));
        assert!(t.tick <= t.initial_backoff, "the loop must look at least as often as the shortest delay");
        assert!(t.redelivery_backoff <= t.max_backoff, "queued mail is never retried less often than before");
    }

    /// A phone that is asleep when the session starts (the startup dial fails)
    /// is reached as soon as it is listening — by the loop alone, with no send
    /// to trigger a lazy redial — and gets exactly what the startup dial sends:
    /// `Hello` with the session cert, the `thinking(false)` handshake, then the
    /// queued mailbox.
    #[tokio::test]
    async fn a_device_unreachable_at_startup_is_reconnected_once_it_is_reachable() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("unreachable_then_reachable");

        mailbox::enqueue("phone", &[Frame::thinking(true), Frame::token("queued while away"), Frame::token_done(), Frame::thinking(false)]);

        let mut stub = PhoneStub::bind().await;
        let core = core_knowing("phone", &stub.ticket).await.with_presence(fast_timings());

        // Several attempts fail while the phone isn't answering.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!is_connected(&core, "phone").await);
        assert_eq!(stub.accepted(), 0);
        assert!(mailbox::has_pending("phone"), "a failed dial must not touch the mailbox");

        stub.listen(false);
        let mut link = stub.next_link(WITHIN).await.expect("the loop should dial the phone once it listens");

        match link.next_frame().await {
            Some(Frame::Hello { name, invite, cert }) => {
                assert_eq!(name, "session");
                assert_eq!(cert.as_deref(), Some("azd-test-cert"), "the redial must present the session cert");
                assert_eq!(invite, None);
            }
            other => panic!("first frame should be Hello, got {other:?}"),
        }
        assert!(matches!(link.next_frame().await, Some(Frame::Thinking { on: false })), "then the handshake");
        assert!(matches!(link.next_frame().await, Some(Frame::Thinking { on: true })), "then the queued mailbox");
        assert!(matches!(link.next_frame().await, Some(Frame::Token { delta, .. }) if delta == "queued while away"));

        eventually("the device to read as connected", WITHIN, || async { is_connected(&core, "phone").await }).await;
        assert!(!mailbox::has_pending("phone"), "the flush clears the mailbox");
        assert_eq!(core.get_events(Some("phone"), Some(5)).await.unwrap(), vec![connected("phone")]);

        drop(core);
        stub.shutdown().await;
        unisolate();
    }

    /// The houston case: the link drops and nothing is sent afterwards. The
    /// device reads as disconnected, a `disconnected` event is emitted, and the
    /// loop brings it back on its own, reporting `connected` again.
    #[tokio::test]
    async fn a_dropped_connection_is_noticed_and_redialed_without_any_send() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("dropped_then_redialed");

        let mut stub = PhoneStub::listening().await;
        let core = core_knowing("phone", &stub.ticket).await;
        // Connect first, then start the loop, so the first drop is the only thing under test.
        core.ensure_device("phone").await.expect("first dial");
        let mut first = stub.next_link(WITHIN).await.expect("first link");
        let core = core.with_presence(fast_timings());

        // Something the phone said just before it dropped must survive the
        // reconnect: the inbox is the device's, not the connection's.
        first.send_frame(&Frame::Chat { text: "last words".into(), id: None }).await;
        eventually("the chat to reach the inbox", WITHIN, || async {
            let conn = core.lookup_device("phone").await.unwrap();
            let held = conn.inbox.lock().unwrap().iter().any(|e| matches!(e, InboxEntry::Message(_)));
            held
        })
        .await;

        first.conn.close(0u32.into(), b"phone went away");
        eventually("the session to notice and redial", WITHIN, || async { stub.accepted() >= 2 }).await;
        let _second = stub.next_link(WITHIN).await.expect("second link");
        eventually("the device to read as connected again", WITHIN, || async { is_connected(&core, "phone").await }).await;

        let mut seen = Vec::new();
        while seen.len() < 4 {
            let batch = core.get_events(Some("phone"), Some(5)).await.unwrap();
            assert!(!batch.is_empty(), "events stopped at {seen:?}");
            seen.extend(batch);
        }
        let said = WatchEvent::Message { device: "phone".into(), text: "last words".into() };
        assert_eq!(seen, vec![connected("phone"), said, disconnected("phone"), connected("phone")]);

        drop(core);
        stub.shutdown().await;
        unisolate();
    }

    /// Many callers reaching for a down device at once produce one connection,
    /// not one each: the second and later wait on the first's dial and reuse it.
    #[tokio::test]
    async fn concurrent_ensure_device_calls_dial_once() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("concurrent_ensure");

        let mut stub = PhoneStub::listening().await;
        let core = Arc::new(core_knowing("phone", &stub.ticket).await);

        let calls: Vec<_> = (0..8)
            .map(|_| {
                let core = core.clone();
                tokio::spawn(async move { core.ensure_device("phone").await.is_ok() })
            })
            .collect();
        for call in calls {
            assert!(call.await.unwrap(), "every caller should get the one connection");
        }

        // Give a (wrongly) second dial time to land before counting.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(stub.accepted(), 1, "eight concurrent callers must share a single dial");
        let _link = stub.next_link(WITHIN).await.expect("the one link");

        drop(core);
        stub.shutdown().await;
        unisolate();
    }

    /// The guard itself, deterministically: while a dial to a device is in
    /// flight (its lock held), the background loop skips it instead of
    /// queueing, and a lazy caller waits for the dial rather than starting a
    /// second.
    #[tokio::test]
    async fn an_in_flight_dial_is_waited_on_by_callers_and_skipped_by_the_loop() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("in_flight_guard");

        let mut stub = PhoneStub::listening().await;
        let core = Arc::new(core_knowing("phone", &stub.ticket).await);
        let dialer = core.dialer();

        let dial_lock = core.devices.lock().await.get("phone").unwrap().dial_lock.clone();
        let in_flight = dial_lock.clone().lock_owned().await;

        assert_eq!(dialer.redial_idle("phone").await, crate::core::device::DialOutcome::Skipped);

        let waiting = {
            let core = core.clone();
            tokio::spawn(async move { core.ensure_device("phone").await.is_ok() })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!waiting.is_finished(), "a caller must wait for the in-flight dial, not start its own");
        assert_eq!(stub.accepted(), 0);

        drop(in_flight);
        assert!(waiting.await.unwrap());
        eventually("the one dial to reach the phone", WITHIN, || async { stub.accepted() == 1 }).await;
        let _link = stub.next_link(WITHIN).await.expect("link");

        drop(dialer);
        drop(core);
        stub.shutdown().await;
        unisolate();
    }

    /// `disconnect` means the operator wants the device down: the loop leaves
    /// it alone. The next send (a lazy redial) lifts that.
    #[tokio::test]
    async fn an_explicit_disconnect_is_not_undone_by_the_loop_until_the_next_send() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("explicit_disconnect");

        let mut stub = PhoneStub::listening().await;
        let core = core_knowing("phone", &stub.ticket).await;
        core.ensure_device("phone").await.expect("dial");
        let _first = stub.next_link(WITHIN).await.expect("first link");
        let core = core.with_presence(fast_timings());

        core.disconnect("phone", false).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(stub.accepted(), 1, "the loop must not redial a device the operator disconnected");
        assert!(!is_connected(&core, "phone").await);

        core.ensure_device("phone").await.expect("a send redials lazily");
        assert_eq!(stub.accepted(), 2);
        assert!(is_connected(&core, "phone").await);

        drop(core);
        stub.shutdown().await;
        unisolate();
    }

    /// A peer that closes every connection on arrival (a phone still awaiting
    /// approval does exactly this) is retried on a growing delay, not once per
    /// tick.
    #[tokio::test]
    async fn a_peer_that_keeps_refusing_is_backed_off() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("backoff");

        let mut stub = PhoneStub::bind().await;
        stub.listen(true);
        let core = core_knowing("phone", &stub.ticket).await.with_presence(fast_timings());

        tokio::time::sleep(Duration::from_millis(1000)).await;
        let attempts = stub.accepted();
        // 1 s at a 25 ms tick is 40 ticks; doubling from 25 ms to a 100 ms
        // ceiling allows roughly 14. Wide bounds: this must not be flaky, only
        // tell "backing off" from "every tick".
        assert!((3..=30).contains(&attempts), "expected a backed-off retry cadence, saw {attempts} attempts");

        drop(core);
        stub.shutdown().await;
        unisolate();
    }

    /// The loop is part of the session: dropping the core ends it, and with it
    /// any dial it had in flight, so nothing keeps dialing a phone after the
    /// session is gone (nor holds a one-shot verb's exit).
    #[tokio::test]
    async fn dropping_the_session_stops_the_loop() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("stops_on_drop");

        let mut stub = PhoneStub::bind().await;
        stub.listen(true);
        let core = core_knowing("phone", &stub.ticket).await.with_presence(fast_timings());

        eventually("the loop to dial a few times", WITHIN, || async { stub.accepted() >= 3 }).await;
        drop(core);
        tokio::time::sleep(Duration::from_millis(200)).await; // let anything in flight land
        let after_drop = stub.accepted();
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(stub.accepted(), after_drop, "no dials once the session is gone");

        stub.shutdown().await;
        unisolate();
    }
}
