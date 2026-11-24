//! A job's stdin on its way from the connection to the child's pipe.
//!
//! The connection's reader must never wait for a slow child: the `cancel` frame
//! and the disconnect that cancels a job arrive on the same connection, behind
//! the stdin. So a send always takes the bytes at once. Memory holds at most
//! [`BUDGET`] of them; the rest go to an unlinked file in the job's directory and
//! come back in order.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};

use crate::util::lock;

/// How much stdin a job may keep in memory. Frames are at most 1 MiB.
pub const BUDGET: usize = 4 << 20;
/// How much of the spool one read returns.
const SPOOL_READ: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Item {
    Data(Vec<u8>),
    /// `stdin_eof`: everything has been delivered.
    Eof,
    /// The sender is gone without `stdin_eof`, and everything it sent has been
    /// delivered.
    HungUp,
}

struct Spool {
    file: File,
    write_at: u64,
    read_at: u64,
}

#[derive(Default)]
struct State {
    mem: VecDeque<Vec<u8>>,
    mem_bytes: usize,
    spool: Option<Spool>,
    eof: bool,
    hung_up: bool,
    /// The receiver is gone, or the stdin can't be delivered: drop what comes.
    dead: bool,
}

impl State {
    fn spooled(&self) -> u64 {
        self.spool.as_ref().map_or(0, |s| s.write_at - s.read_at)
    }

    /// The input is lost from here on.
    fn fail(&mut self) {
        self.mem.clear();
        self.mem_bytes = 0;
        self.spool = None;
        self.dead = true;
        self.hung_up = true;
    }
}

struct Shared {
    state: Mutex<State>,
    cv: Condvar,
    dir: PathBuf,
    budget: usize,
}

pub struct Sender(Arc<Shared>);
pub struct Receiver(Arc<Shared>);

/// A queue whose overflow is spooled in `dir` (the job's own directory).
pub fn channel(dir: PathBuf) -> (Sender, Receiver) {
    with_budget(dir, BUDGET)
}

fn with_budget(dir: PathBuf, budget: usize) -> (Sender, Receiver) {
    let shared = Arc::new(Shared {
        state: Mutex::default(),
        cv: Condvar::new(),
        dir,
        budget,
    });
    (Sender(Arc::clone(&shared)), Receiver(shared))
}

impl Sender {
    /// Queue `chunk`. Never waits for the child. An error means the stdin is
    /// lost, and nothing after it will be delivered.
    pub fn data(&self, chunk: Vec<u8>) -> io::Result<()> {
        let mut st = lock(&self.0.state);
        if st.dead || st.eof || chunk.is_empty() {
            return Ok(());
        }
        // Once anything is spooled, later bytes must queue behind it.
        let fits = st.mem_bytes == 0 || st.mem_bytes + chunk.len() <= self.0.budget;
        let result = if st.spooled() == 0 && fits {
            st.mem_bytes += chunk.len();
            st.mem.push_back(chunk);
            Ok(())
        } else {
            self.spool(&mut st, &chunk)
        };
        if result.is_err() {
            st.fail();
        }
        self.0.cv.notify_all();
        result
    }

    fn spool(&self, st: &mut State, chunk: &[u8]) -> io::Result<()> {
        if st.spool.is_none() {
            let path = self.0.dir.join("stdin.spool");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            // Unlinked at once: it goes away with the job's last handle to it.
            fs::remove_file(&path)?;
            st.spool = Some(Spool {
                file,
                write_at: 0,
                read_at: 0,
            });
        }
        let sp = st.spool.as_mut().expect("just opened");
        sp.file.write_all_at(chunk, sp.write_at)?;
        sp.write_at += chunk.len() as u64;
        Ok(())
    }

    /// `stdin_eof`: no more input.
    pub fn eof(&self) {
        lock(&self.0.state).eof = true;
        self.0.cv.notify_all();
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        lock(&self.0.state).hung_up = true;
        self.0.cv.notify_all();
    }
}

impl Receiver {
    /// The next piece, waiting for one. Data always comes before `Eof`, and
    /// both before `HungUp`.
    pub fn recv(&self) -> Item {
        let mut st = lock(&self.0.state);
        loop {
            if let Some(chunk) = st.mem.pop_front() {
                st.mem_bytes -= chunk.len();
                return Item::Data(chunk);
            }
            if st.spooled() > 0 {
                return match read_spool(&mut st) {
                    Ok(chunk) => Item::Data(chunk),
                    Err(e) => {
                        eprintln!("azula-guest: reading spooled stdin: {e}");
                        st.fail();
                        Item::HungUp
                    }
                };
            }
            if st.eof {
                return Item::Eof;
            }
            if st.hung_up {
                return Item::HungUp;
            }
            st = self.0.cv.wait(st).unwrap_or_else(|p| p.into_inner());
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let mut st = lock(&self.0.state);
        st.mem.clear();
        st.mem_bytes = 0;
        st.spool = None;
        st.dead = true;
    }
}

fn read_spool(st: &mut State) -> io::Result<Vec<u8>> {
    let sp = st.spool.as_mut().expect("spooled > 0");
    let n = (sp.write_at - sp.read_at).min(SPOOL_READ as u64) as usize;
    let mut buf = vec![0u8; n];
    sp.file.read_exact_at(&mut buf, sp.read_at)?;
    sp.read_at += n as u64;
    if sp.read_at == sp.write_at {
        // Drained: give the disk back before the next overflow.
        sp.file.set_len(0)?;
        sp.read_at = 0;
        sp.write_at = 0;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Dir {
            let d = std::env::temp_dir().join(format!(
                "azula-stdinq-{tag}-{}-{}",
                std::process::id(),
                crate::util::random_hex(4)
            ));
            fs::create_dir_all(&d).unwrap();
            Dir(d)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mem_bytes(s: &Sender) -> usize {
        lock(&s.0.state).mem_bytes
    }

    /// Bytes are `i % 251`, so any lost, repeated or reordered byte shows.
    fn pattern(from: usize, len: usize) -> Vec<u8> {
        (from..from + len).map(|i| (i % 251) as u8).collect()
    }

    fn drain(r: &Receiver) -> (Vec<u8>, Item) {
        let mut out = Vec::new();
        loop {
            match r.recv() {
                Item::Data(d) => out.extend(d),
                end => return (out, end),
            }
        }
    }

    #[test]
    fn a_slow_child_costs_the_budget_not_the_input() {
        let d = Dir::new("budget");
        let (s, r) = with_budget(d.0.clone(), 64 * 1024);
        let mut sent = 0;
        for _ in 0..200 {
            s.data(pattern(sent, 10_000)).unwrap();
            sent += 10_000;
            assert!(mem_bytes(&s) <= 64 * 1024, "{}", mem_bytes(&s));
        }
        s.eof();
        let (got, end) = drain(&r);
        assert_eq!(end, Item::Eof);
        assert!(got == pattern(0, sent), "bytes lost or out of order");
        assert_eq!(mem_bytes(&s), 0);
        assert!(
            fs::read_dir(&d.0).unwrap().next().is_none(),
            "the spool must not outlive its handle"
        );
    }

    #[test]
    fn order_survives_draining_and_refilling_at_every_point() {
        let d = Dir::new("order");
        let (s, r) = with_budget(d.0.clone(), 4 * 1024);
        let (mut sent, mut got) = (0usize, Vec::new());
        // Cycle through fills that spill and drains that stop mid-spool.
        for round in 0..300usize {
            for k in 0..(round % 7) {
                let n = 700 + (round * 37 + k * 911) % 3000;
                s.data(pattern(sent, n)).unwrap();
                sent += n;
            }
            for _ in 0..(round % 5) {
                if got.len() == sent {
                    break;
                }
                match r.recv() {
                    Item::Data(x) => got.extend(x),
                    other => panic!("{other:?}"),
                }
            }
        }
        s.eof();
        let (rest, end) = drain(&r);
        got.extend(rest);
        assert_eq!(end, Item::Eof);
        assert!(got == pattern(0, sent), "bytes lost or out of order");
    }

    #[test]
    fn the_spool_is_reclaimed_when_it_drains() {
        let d = Dir::new("reclaim");
        let (s, r) = with_budget(d.0.clone(), 1000);
        for _ in 0..3 {
            s.data(vec![1; 900]).unwrap();
            s.data(vec![2; 5000]).unwrap(); // over budget: spooled
            assert!(lock(&s.0.state).spooled() > 0);
            let mut n = 0;
            while n < 5900 {
                let Item::Data(x) = r.recv() else { panic!() };
                n += x.len();
            }
            let st = lock(&s.0.state);
            let sp = st.spool.as_ref().unwrap();
            assert_eq!(
                (sp.write_at, sp.read_at, sp.file.metadata().unwrap().len()),
                (0, 0, 0)
            );
        }
    }

    #[test]
    fn eof_and_hangup_come_after_the_data() {
        let d = Dir::new("end");
        let (s, r) = with_budget(d.0.clone(), 100);
        s.data(vec![7; 60]).unwrap();
        s.data(vec![8; 80]).unwrap();
        s.eof();
        drop(s); // eof wins over hangup
        let (got, end) = drain(&r);
        assert_eq!((got.len(), end), (140, Item::Eof));

        let (s, r) = with_budget(d.0.clone(), 100);
        s.data(vec![7; 60]).unwrap();
        drop(s);
        let (got, end) = drain(&r);
        assert_eq!((got.len(), end), (60, Item::HungUp));
    }

    #[test]
    fn a_waiting_receiver_wakes_for_data_and_for_the_end() {
        let d = Dir::new("wake");
        let (s, r) = with_budget(d.0.clone(), 100);
        let t = thread::spawn(move || (r.recv(), r.recv()));
        thread::sleep(Duration::from_millis(50));
        s.data(b"x".to_vec()).unwrap();
        thread::sleep(Duration::from_millis(50));
        s.eof();
        assert_eq!(t.join().unwrap(), (Item::Data(b"x".to_vec()), Item::Eof));
    }

    #[test]
    fn a_child_that_stopped_reading_keeps_nothing() {
        let d = Dir::new("dead");
        let (s, r) = with_budget(d.0.clone(), 100);
        s.data(vec![1; 90]).unwrap();
        drop(r);
        for _ in 0..50 {
            s.data(vec![1; 1 << 20]).unwrap(); // not an error: the child just doesn't want it
        }
        assert_eq!(mem_bytes(&s), 0);
        assert_eq!(lock(&s.0.state).spooled(), 0);
    }

    #[test]
    fn a_spool_that_cannot_be_written_loses_the_stdin_not_the_job() {
        let d = Dir::new("nospool");
        let (s, r) = with_budget(d.0.join("missing"), 100);
        s.data(vec![1; 90]).unwrap();
        assert!(s.data(vec![2; 5000]).is_err());
        s.data(vec![3; 10]).unwrap(); // nothing after a hole is delivered
        assert_eq!(r.recv(), Item::HungUp);
    }
}
