//! `blackjack` — a self-contained A2UI demo: binds an iroh endpoint, prints a
//! connect code (ticket + URL + QR) to paste/scan into the azula app, and —
//! for each app that connects — deals a game of Blackjack rendered as an
//! interactive A2UI surface in the app's "azula" conversation.
//!
//! This demonstrates the same A2UI render → tap → update mechanism the bridge
//! exposes as the `render_ui` / `update_ui` MCP tools, but standalone: no MCP
//! client is needed. Unlike `demo-ui` (which dials a known device), this command
//! *accepts* inbound connections on the LLM ALPN, like `serve` does.
//!
//! The card faces are Unicode glyphs inside Text components (the renderer has no
//! suit icons), and each hand is a single pre-joined string bound into the
//! surface data model — the whole model is replaced on every update (path ""),
//! which keeps the game→UI mapping trivial.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use serde_json::{json, Value};
use tokio::io::BufReader;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info, warn};

use azula::mcp::LLM_ALPN;
use azula::proto::{read_frame, write_frame, Frame};
use azula::qr;

const CATALOG: &str = "https://a2ui.org/specification/v0_9_1/catalogs/basic/catalog.json";

/// Monotonic id for freshly-dealt games (see [`new_surface_id`]).
static GAME_CTR: AtomicU64 = AtomicU64::new(0);

/// A per-process tag mixed into surface ids so a *new* server run never reuses a
/// surface id from a previous run (which would make the app resume a stale card
/// after the table lost its state). Within a run, a player's id is stable so the
/// app can resume the same surface on reconnect.
static RUN_TAG: OnceLock<u64> = OnceLock::new();

fn new_surface_id() -> String {
    let run = *RUN_TAG.get_or_init(|| {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    });
    format!("blackjack-{}-{}", run, GAME_CTR.fetch_add(1, Ordering::Relaxed))
}

/// A player's live table, kept in memory and keyed by their endpoint id so a
/// reconnect resumes the same hand (and same A2UI surface) instead of dealing
/// a fresh one. In-memory only — a server restart starts everyone fresh.
#[derive(Clone, Debug)]
struct Table {
    surface_id: String,
    game: Game,
}

type Tables = Arc<AsyncMutex<HashMap<String, Table>>>;

/// Bind, print connect info, and serve Blackjack games until Ctrl-C.
pub async fn run() -> Result<()> {
    // Reuse a persisted key so restarts keep the same endpoint id (stable connect code).
    let (endpoint, ticket) = azula::endpoint::bind_server_endpoint("blackjack").await?;

    let lines = vec![
        "  Paste this code into the azula app (＋ connect a peer):".to_string(),
        String::new(),
        format!("    {ticket}"),
    ];
    azula::endpoint::print_banner("♠ ♥ ♦ ♣   azula blackjack   ♣ ♦ ♥ ♠", &lines);
    qr::print_pairing("Or scan to play:", &ticket);
    println!("  Then open the 'azula' conversation in the app. Ctrl-C to close the table.");
    println!();

    // A Router dispatches each inbound app connection to the Blackjack handler.
    // Games are kept per player (by endpoint id) so several apps can play at once and
    // a reconnecting player resumes their hand rather than getting a fresh deal.
    let tables: Tables = Arc::new(AsyncMutex::new(HashMap::new()));
    let router = Router::builder(endpoint)
        .accept(LLM_ALPN, BlackjackHandler { tables })
        .spawn();

    info!("blackjack table open — press Ctrl-C to close");
    tokio::signal::ctrl_c().await?;
    info!("closing table…");
    router.shutdown().await?;
    Ok(())
}

#[derive(Clone, Debug)]
struct BlackjackHandler {
    tables: Tables,
}

impl ProtocolHandler for BlackjackHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        handle_conn(connection, self.tables.clone())
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

/// One connection can host many bi-streams; wire each to the player's table.
async fn handle_conn(connection: Connection, tables: Tables) -> Result<()> {
    let remote = connection.remote_id().to_string();
    info!(%remote, "blackjack: player connected");
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                debug!(%remote, error = %e, "blackjack: connection closed");
                return Ok(());
            }
        };
        let remote = remote.clone();
        let tables = tables.clone();
        tokio::spawn(async move {
            if let Err(e) = play_game(send, recv, remote.clone(), tables).await {
                warn!(%remote, error = %e, "blackjack: game error");
            }
        });
    }
}

/// Render the Blackjack surface and run the deal → hit/stand → update loop.
/// Resumes the player's existing hand (same surface id) on reconnect; only deals
/// a fresh one if they've never played this run.
async fn play_game(send: SendStream, recv: RecvStream, remote: String, tables: Tables) -> Result<()> {
    let mut send = send;
    let mut reader = BufReader::new(recv);

    // Announce a name so the app gives the game its own conversation ("Blackjack")
    // instead of dropping the surface into the shared "azula" thread. The
    // thinking-off frame then confirms the channel is live.
    write_frame(&mut send, &Frame::Hello { name: "Blackjack".into(), invite: None, cert: None }).await?;
    write_frame(&mut send, &Frame::thinking(false)).await?;

    // Resume this player's table if we have one, otherwise deal a new hand.
    let (sid, mut game) = {
        let mut map = tables.lock().await;
        match map.get(&remote) {
            Some(t) => {
                info!(%remote, sid = %t.surface_id, "blackjack: resuming hand");
                (t.surface_id.clone(), t.game.clone())
            }
            None => {
                let sid = new_surface_id();
                let game = Game::new();
                map.insert(remote.clone(), Table { surface_id: sid.clone(), game: game.clone() });
                info!(%remote, %sid, "blackjack: dealt a new hand");
                (sid, game)
            }
        }
    };

    // Re-create the surface (the app treats a repeated surface id as "resume this
    // card") and paint the current state — a fresh deal or the hand in progress.
    write_frame(&mut send, &Frame::A2ui { message: create_surface_msg(&sid) }).await?;
    write_frame(&mut send, &Frame::A2ui { message: components_msg(&sid) }).await?;
    write_frame(&mut send, &Frame::A2ui { message: data_model_msg(&sid, &game) }).await?;

    loop {
        match read_frame(&mut reader).await {
            Ok(Some(Frame::A2uiAction { action })) => {
                let name = action_name(&action);
                debug!(%remote, %name, "blackjack: tap");
                match name.as_str() {
                    "hit" => game.hit(),
                    "stand" => game.stand(),
                    "deal" => game = Game::new(),
                    _ => {}
                }
                // Persist the move so a reconnect resumes from here.
                tables.lock().await.insert(remote.clone(), Table { surface_id: sid.clone(), game: game.clone() });
                // The whole data model is replaced (path ""); the bound Text
                // components re-resolve hands / totals / status.
                write_frame(&mut send, &Frame::A2ui { message: data_model_msg(&sid, &game) }).await?;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                info!(%remote, "blackjack: player left the table");
                break;
            }
            Err(e) => {
                warn!(%remote, error = %e, "blackjack: read error");
                break;
            }
        }
    }
    Ok(())
}

/// Pull the event name out of an `a2ui_action` payload. The app wraps it as
/// `{"version":..,"action":{"name":..}}`, so read the inner object (falling back
/// to a flat shape for safety).
fn action_name(action: &Value) -> String {
    let inner = action.get("action").unwrap_or(action);
    inner
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

// ───────────────────────────── A2UI surface ─────────────────────────────

fn create_surface_msg(sid: &str) -> Value {
    json!({
        "version": "v0.9.1",
        "createSurface": { "surfaceId": sid, "catalogId": CATALOG }
    })
}

fn components_msg(sid: &str) -> Value {
    let components = json!([
        { "id": "root", "component": "Card", "child": "col" },
        { "id": "col", "component": "Column", "align": "center", "children": [
            "title", "dealerLabel", "dealerHand", "dealerTotal", "divider",
            "playerLabel", "playerHand", "playerTotal", "status", "buttons"
        ] },
        { "id": "title",       "component": "Text", "text": "AZULA · BLACKJACK", "variant": "caption" },
        { "id": "dealerLabel", "component": "Text", "text": "DEALER", "variant": "caption" },
        { "id": "dealerHand",  "component": "Text", "text": { "path": "/dealer/hand" },  "variant": "h3" },
        { "id": "dealerTotal", "component": "Text", "text": { "path": "/dealer/total" }, "variant": "h1" },
        { "id": "divider",     "component": "Divider" },
        { "id": "playerLabel", "component": "Text", "text": "YOU", "variant": "caption" },
        { "id": "playerHand",  "component": "Text", "text": { "path": "/player/hand" },  "variant": "h3" },
        { "id": "playerTotal", "component": "Text", "text": { "path": "/player/total" }, "variant": "h1" },
        { "id": "status",      "component": "Text", "text": { "path": "/status" }, "variant": "body" },
        { "id": "buttons", "component": "Row", "justify": "center",
          "children": ["hitBtn", "standBtn", "dealBtn"] },
        { "id": "hitL",     "component": "Text",   "text": "Hit" },
        { "id": "hitBtn",   "component": "Button", "child": "hitL",   "variant": "primary",
          "action": { "event": { "name": "hit" } } },
        { "id": "standL",   "component": "Text",   "text": "Stand" },
        { "id": "standBtn", "component": "Button", "child": "standL", "variant": "primary",
          "action": { "event": { "name": "stand" } } },
        { "id": "dealL",    "component": "Text",   "text": "New deal" },
        { "id": "dealBtn",  "component": "Button", "child": "dealL",
          "action": { "event": { "name": "deal" } } }
    ]);
    json!({
        "version": "v0.9.1",
        "updateComponents": { "surfaceId": sid, "components": components }
    })
}

fn data_model_msg(sid: &str, game: &Game) -> Value {
    json!({
        "version": "v0.9.1",
        "updateDataModel": { "surfaceId": sid, "path": "", "value": game.data_model() }
    })
}

// ───────────────────────────── game logic ─────────────────────────────

const RANKS: [&str; 13] = [
    "A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K",
];
const SUITS: [&str; 4] = ["♠", "♥", "♦", "♣"];

#[derive(Clone, Copy, Debug)]
struct Card {
    rank: usize,
    suit: usize,
}

impl Card {
    fn glyph(&self) -> String {
        format!("{}{}", RANKS[self.rank], SUITS[self.suit])
    }
    /// Blackjack value; aces count 11 here and are softened in [`hand_total`].
    fn value(&self) -> u32 {
        match self.rank {
            0 => 11,                // Ace
            9..=12 => 10,        // 10, J, Q, K
            r => (r as u32) + 1,    // 2..9
        }
    }
    fn is_ace(&self) -> bool {
        self.rank == 0
    }
}

fn hand_total(cards: &[Card]) -> u32 {
    let mut total: u32 = cards.iter().map(Card::value).sum();
    let mut aces = cards.iter().filter(|c| c.is_ace()).count();
    while total > 21 && aces > 0 {
        total -= 10;
        aces -= 1;
    }
    total
}

fn hand_string(cards: &[Card]) -> String {
    cards
        .iter()
        .map(Card::glyph)
        .collect::<Vec<_>>()
        .join("  ")
}

#[derive(Clone, Debug)]
struct Game {
    deck: Vec<Card>,
    player: Vec<Card>,
    dealer: Vec<Card>,
    revealed: bool,
    over: bool,
    status: String,
}

impl Game {
    fn new() -> Game {
        let mut rng = Rng::new();
        let mut deck: Vec<Card> = (0..4)
            .flat_map(|suit| (0..13).map(move |rank| Card { rank, suit }))
            .collect();
        // Fisher–Yates shuffle.
        for i in (1..deck.len()).rev() {
            deck.swap(i, rng.below(i + 1));
        }

        let mut g = Game {
            deck,
            player: Vec::new(),
            dealer: Vec::new(),
            revealed: false,
            over: false,
            status: String::new(),
        };
        for _ in 0..2 {
            let c = g.draw();
            g.player.push(c);
            let c = g.draw();
            g.dealer.push(c);
        }

        // Naturals end the round immediately.
        let p = hand_total(&g.player);
        let d = hand_total(&g.dealer);
        if p == 21 || d == 21 {
            g.revealed = true;
            g.over = true;
            g.status = if p == 21 && d == 21 {
                "Push — both have blackjack. Tap New deal.".into()
            } else if p == 21 {
                "Blackjack! You win 🎉 Tap New deal.".into()
            } else {
                "Dealer has blackjack — dealer wins. Tap New deal.".into()
            };
        } else {
            g.status = "Your move — Hit or Stand.".into();
        }
        g
    }

    fn draw(&mut self) -> Card {
        // A single round can't exhaust a 52-card deck; the fallback keeps us safe.
        self.deck.pop().unwrap_or(Card { rank: 0, suit: 0 })
    }

    fn hit(&mut self) {
        if self.over {
            return;
        }
        let card = self.draw();
        self.player.push(card);
        let p = hand_total(&self.player);
        if p > 21 {
            self.revealed = true;
            self.over = true;
            self.status = format!("Bust at {p} — dealer wins. Tap New deal.");
        } else if p == 21 {
            // 21 — stand automatically and let the dealer play.
            self.stand();
        } else {
            self.status = "Your move — Hit or Stand.".into();
        }
    }

    fn stand(&mut self) {
        if self.over {
            return;
        }
        self.revealed = true;
        // Dealer draws to 17 (stands on all 17s).
        while hand_total(&self.dealer) < 17 {
            let card = self.draw();
            self.dealer.push(card);
        }
        let p = hand_total(&self.player);
        let d = hand_total(&self.dealer);
        self.over = true;
        self.status = if d > 21 {
            format!("Dealer busts at {d} — you win 🎉 Tap New deal.")
        } else if d > p {
            format!("Dealer {d} beats your {p} — dealer wins. Tap New deal.")
        } else if p > d {
            format!("You win, {p} to {d} 🎉 Tap New deal.")
        } else {
            format!("Push at {p} — it's a tie. Tap New deal.")
        };
    }

    fn data_model(&self) -> Value {
        // Hide the dealer's hole card until the round is revealed.
        let dealer_hand = if self.revealed {
            hand_string(&self.dealer)
        } else {
            format!("{}  🂠", self.dealer[0].glyph())
        };
        let dealer_total = if self.revealed {
            hand_total(&self.dealer).to_string()
        } else {
            "?".to_string()
        };
        json!({
            "dealer": { "hand": dealer_hand, "total": dealer_total },
            "player": { "hand": hand_string(&self.player), "total": hand_total(&self.player).to_string() },
            "status": self.status,
        })
    }
}

/// Tiny xorshift64 RNG seeded from the wall clock + a per-game counter, so two
/// games dealt in the same instant still shuffle differently. Good enough for a
/// demo — keeps the crate free of a `rand` dependency (like `demo::roll_two`).
struct Rng(u64);

static SEED_CTR: AtomicU64 = AtomicU64::new(0);

impl Rng {
    fn new() -> Rng {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let ctr = SEED_CTR.fetch_add(1, Ordering::Relaxed);
        let mut seed = nanos ^ ctr.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        if seed == 0 {
            seed = 0xDEAD_BEEF_CAFE_F00D;
        }
        Rng(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}
