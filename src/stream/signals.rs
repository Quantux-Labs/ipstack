//! Lock-free per-stream signals: TCP state machine + wakers.
//!
//! Replaces the previous `Mutex<Option<Waker>>` triple (`shutdown`,
//! `read_notify`, `write_notify`) and the `state: TcpState` field that lived
//! inside the `Mutex<Tcb>`. After this refactor:
//!
//! * State reads are a single relaxed `AtomicU8::load` — `poll_read`'s
//!   "is the connection still open?" check no longer competes for the `tcb`
//!   mutex with the per-stream task that holds it across most of its loop
//!   body.
//! * Waker registration/wake is wait-free via [`AtomicWaker`] (re-exported
//!   from the `atomic-waker` crate). Under contention this skips the futex
//!   slow path of `std::sync::Mutex` and stays in userspace.
//! * The `Shutdown` enum (`None | Pending(Waker) | Ready`) collapsed into
//!   `state == Closed` plus an [`AtomicWaker`]. The 3-state tag was
//!   redundant: "Ready" really meant "state has reached Closed", and
//!   "Pending" really meant "a waker is registered" — both already encoded
//!   by the new types.

use super::tcb::TcpState;
use std::sync::atomic::{AtomicU8, Ordering};

/// Wait-free single-slot waker cell. Re-exported from the `atomic-waker`
/// crate (smol-rs) — same algorithm we used to vendor inline.
pub(crate) use atomic_waker::AtomicWaker;

/// Lock-free TCP state cell.
///
/// Backed by an `AtomicU8` so the state can be peeked from the user-side
/// `poll_read` / `poll_write` / `poll_shutdown` without acquiring the `tcb`
/// mutex (which the per-stream task holds for ~all of its loop body). The
/// authoritative writes still happen from a single point inside
/// `tcp_main_logic_loop` so we don't need CAS — plain Acquire/Release loads
/// and stores suffice.
#[derive(Debug)]
pub(crate) struct AtomicTcpState(AtomicU8);

impl AtomicTcpState {
    pub(crate) fn new(state: TcpState) -> Self {
        Self(AtomicU8::new(state as u8))
    }

    #[inline]
    pub(crate) fn load(&self) -> TcpState {
        // Acquire ordering: pairs with `store(..., Release)` so that any
        // wake/notify side-effects observed AFTER the load (e.g. a packet
        // appearing on `data_rx`) are sequenced after the state transition.
        TcpState::from_u8(self.0.load(Ordering::Acquire))
    }

    #[inline]
    pub(crate) fn store(&self, state: TcpState) {
        self.0.store(state as u8, Ordering::Release);
    }
}

/// Per-stream control signals shared between the user-facing
/// `IpStackTcpStream` and the per-stream `tcp_main_logic_loop` task.
///
/// All fields are lock-free. The `state` is a 1-byte atomic; each waker is
/// roughly the size of `Mutex<Option<Waker>>` was but never blocks.
#[derive(Debug)]
pub(crate) struct StreamSignals {
    /// Authoritative TCP state. Mutated from `tcp_main_logic_loop` (and
    /// `poll_read`'s timeout branch); read everywhere lock-free.
    pub(crate) state: AtomicTcpState,
    /// Wakes `IpStackTcpStream::poll_read`. Fired when new data lands in
    /// `data_rx` or the stream transitions to `Closed`.
    pub(crate) read_waker: AtomicWaker,
    /// Wakes `IpStackTcpStream::poll_write`. Fired on send-window-freeing
    /// ACK, on `Closed`, on RST.
    pub(crate) write_waker: AtomicWaker,
    /// Wakes `IpStackTcpStream::poll_shutdown`. Fired on every transition to
    /// `Closed`.
    pub(crate) shutdown_waker: AtomicWaker,
}

impl StreamSignals {
    pub(crate) fn new(initial: TcpState) -> Self {
        Self {
            state: AtomicTcpState::new(initial),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
            shutdown_waker: AtomicWaker::new(),
        }
    }

    #[inline]
    pub(crate) fn state(&self) -> TcpState {
        self.state.load()
    }

    #[inline]
    pub(crate) fn set_state(&self, s: TcpState) {
        self.state.store(s);
    }

    /// Tear down the stream: store `Closed` and wake every parked future so
    /// `poll_read` / `poll_write` / `poll_shutdown` observe it without
    /// waiting on the per-stream 60s timeout.
    pub(crate) fn close(&self) {
        self.state.store(TcpState::Closed);
        self.read_waker.wake();
        self.write_waker.wake();
        self.shutdown_waker.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    #[test]
    fn atomic_tcp_state_round_trip() {
        let s = AtomicTcpState::new(TcpState::Listen);
        assert_eq!(s.load(), TcpState::Listen);
        s.store(TcpState::Established);
        assert_eq!(s.load(), TcpState::Established);
        s.store(TcpState::Closed);
        assert_eq!(s.load(), TcpState::Closed);
    }

    #[test]
    fn signals_close_wakes_everyone() {
        let signals = Arc::new(StreamSignals::new(TcpState::Established));

        // Use a tokio runtime to get real wakers.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

        rt.block_on(async {
            let s = signals.clone();
            let read_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let write_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let shutdown_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));

            let r = read_fired.clone();
            let w = write_fired.clone();
            let sh = shutdown_fired.clone();

            // Spawn three tasks that park on each waker.
            let h_read = tokio::spawn({
                let s = s.clone();
                async move {
                    std::future::poll_fn(|cx: &mut Context<'_>| -> Poll<()> {
                        if s.state() == TcpState::Closed {
                            r.store(true, Ordering::Release);
                            return Poll::Ready(());
                        }
                        s.read_waker.register(cx.waker());
                        if s.state() == TcpState::Closed {
                            r.store(true, Ordering::Release);
                            return Poll::Ready(());
                        }
                        Poll::Pending
                    })
                    .await
                }
            });
            let h_write = tokio::spawn({
                let s = s.clone();
                async move {
                    std::future::poll_fn(|cx: &mut Context<'_>| -> Poll<()> {
                        if s.state() == TcpState::Closed {
                            w.store(true, Ordering::Release);
                            return Poll::Ready(());
                        }
                        s.write_waker.register(cx.waker());
                        if s.state() == TcpState::Closed {
                            w.store(true, Ordering::Release);
                            return Poll::Ready(());
                        }
                        Poll::Pending
                    })
                    .await
                }
            });
            let h_shut = tokio::spawn({
                let s = s.clone();
                async move {
                    std::future::poll_fn(|cx: &mut Context<'_>| -> Poll<()> {
                        if s.state() == TcpState::Closed {
                            sh.store(true, Ordering::Release);
                            return Poll::Ready(());
                        }
                        s.shutdown_waker.register(cx.waker());
                        if s.state() == TcpState::Closed {
                            sh.store(true, Ordering::Release);
                            return Poll::Ready(());
                        }
                        Poll::Pending
                    })
                    .await
                }
            });

            // Yield so all three tasks have parked.
            tokio::task::yield_now().await;

            // Fire the close: all three should wake.
            s.close();

            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                h_read.await.unwrap();
                h_write.await.unwrap();
                h_shut.await.unwrap();
            })
            .await
            .expect("all three wakers fire on close()");

            assert!(read_fired.load(Ordering::Acquire));
            assert!(write_fired.load(Ordering::Acquire));
            assert!(shutdown_fired.load(Ordering::Acquire));
        });
    }
}
