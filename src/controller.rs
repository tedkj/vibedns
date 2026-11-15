//! The window's brain. It lives on the UI thread: it starts queries and traces, hands each
//! column to a worker, takes the answers back (each carries the query's epoch; anything for
//! another epoch does nothing), compares, keeps the prefs (in memory, saved on the prefs
//! thread), the history (written on a worker) and the toasts. The .slint files lay out what it
//! hands them; every word and choice is made here or in `view`.

use crate::ask::{self, Outcome, Resolved, WinSide};
use crate::check::{Dot, Fetched, Local, Release, Rows};
use crate::compare::{self, Comparison, Verdict};
use crate::history::{self, Entry, HistoryFile, Loaded};
use crate::prefs::{Change, Store};
use crate::query::{self, Question};
use crate::resolvers::{self, Adapter, Column, Custom, Kind, MAX_COLUMNS, MAX_CUSTOM, PRESETS};
use crate::text;
use crate::trace::{self, End, Step};
use crate::transport::{Net, Proto};
use crate::{AppWindow, Card, CheckDot, CheckRow, Pick, PresetRow, Prefs, Theme, ToastItem, ToastKind, view, windows};
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The detail panel shows at most this many lines (Copy has them all).
pub const DETAIL_LINES: usize = 1500;
/// A history write that failed is tried again after this long (and again, while it fails).
pub const HISTORY_RETRY_MS: u64 = 5000;

/// What the controller needs from the outside world; the tests hand it fakes.
pub struct Services {
    /// Asking servers (the columns).
    pub net: Arc<dyn Net>,
    /// Asking servers iteratively (the trace).
    pub tracer: Arc<dyn trace::Asker>,
    pub win: Arc<dyn WinSide>,
    /// Tests: no threads anywhere (workers run inline).
    pub manual: bool,
    /// Tests (manual only): while set, workers' jobs wait for `App::release`.
    pub hold: Rc<Cell<bool>>,
    /// %LOCALAPPDATA%\com.tedkj.vibedns (history.json).
    pub local_data: PathBuf,
    pub copy: Box<dyn Fn(&str) -> bool>,
    pub reveal: Box<dyn Fn(&Path)>,
    /// Unix seconds now.
    pub now: Box<dyn Fn() -> u64>,
    /// The root server a trace starts at (random in the app).
    pub root_start: Box<dyn Fn() -> usize>,
    /// A web page in the browser (About's link).
    pub open_url: Box<dyn Fn(&str)>,
    /// The install check's offline half, on its worker: this copy's files, their signatures and
    /// hashes (`trust::inspect_from`; true: installed, so the uninstaller too).
    pub inspect: Fetcher<bool, Local>,
    /// The install check's online half, on its worker: the release list at a path on the site,
    /// waited for at most `release.wait`. Only `main` hands in the real one (the exe's
    /// `net::fetch_release_list`, in no test build); the tests hand in fakes.
    pub fetch: Fetcher<str, Fetched>,
    /// What the check holds the list to: the app, its version, the list's key, the code signer.
    pub release: Release,
}

/// A blocking call the check's worker makes.
pub type Fetcher<A, R> = Arc<dyn Fn(&A) -> R + Send + Sync>;

impl Services {
    /// The real services. `fetch` is the release-list fetcher: `main` hands in the exe's
    /// `net::fetch_release_list`, and is the only place that names it.
    pub fn system(local_data: PathBuf, fetch: Fetcher<str, Fetched>) -> Services {
        // The exe's identity as this process started from it, taken now, before an install
        // could replace it, and handed to every check (FED3, RVD7).
        let started = crate::trust::exe_identity();
        let trace_net = crate::transport::System::with_timeouts(crate::transport::Timeouts { udp: trace::TIMEOUT, udp_tries: 1, ..Default::default() });
        Services {
            net: Arc::new(crate::transport::System::new()),
            tracer: Arc::new(trace::NetAsker { net: Arc::new(trace_net) }),
            win: Arc::new(ask::SystemWin),
            manual: false,
            hold: Rc::default(),
            local_data,
            copy: Box::new(|t| crate::host::copy_text(t).is_ok()),
            reveal: Box::new(|p| {
                let _ = crate::host::reveal(p, true);
            }),
            now: Box::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)),
            root_start: Box::new(|| query::random_id() as usize % trace::ROOTS.len()),
            // The shell can take a moment: never on the window's thread.
            open_url: Box::new(|u| {
                let u = u.to_string();
                std::thread::spawn(move || {
                    let _ = crate::host::open_url(&u);
                });
            }),
            inspect: Arc::new(move |installed: &bool| crate::trust::inspect_from(started, &crate::trust::own_exe(), *installed)),
            fetch,
            release: Release::this(),
        }
    }
}

/// How often the window looks whether a running check has its answer.
const CHECK_POLL_MS: u64 = 50;

/// `fetch` on a thread of its own, waited for at most `deadline` (FETCH_DEADLINE, review RAB-3):
/// past it the answer is `TimedOut`, whatever the site or a proxy is doing, and the thread is
/// left to end by itself (the real fetcher's read loop stops at the same deadline, and WinHTTP's
/// own timeouts bound each step); its late answer goes nowhere.
fn fetch_within(fetch: Fetcher<str, Fetched>, path: String, deadline: Duration) -> Fetched {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(fetch(&path));
    });
    match rx.recv_timeout(deadline) {
        Ok(f) => f,
        Err(RecvTimeoutError::Timeout) => Fetched::TimedOut,
        Err(RecvTimeoutError::Disconnected) => Fetched::Failed("the fetch stopped before it answered".into()),
    }
}

/// One change to the prefs, applied by the prefs thread onto the newest saved ones.
type PrefsChange = Change<Prefs>;

/// After a change, when the window looks whether the prefs thread met a garbled file.
const PREFS_TELL_MS: u64 = 500;

/// The thread that saves prefs changes, in order: the store keeps each until it is written, and
/// puts every unwritten one onto the file as read right before the write (another instance's
/// changes included), onto this window's own when the file is garbled or missing, and writes
/// nothing while the file cannot be read. Reading prefs.json is the disk too: never on the
/// window's thread (a profile on a dead share froze it).
fn prefs_writer(store: Store<Prefs>, pending: Arc<AtomicUsize>) -> Sender<PrefsChange> {
    let (tx, rx) = channel::<PrefsChange>();
    std::thread::spawn(move || {
        while let Ok(f) = rx.recv() {
            store.change(Arc::new(move |p: &mut Prefs| {
                *p = std::mem::take(p).sanitized();
                f(p);
            }));
            pending.fetch_sub(1, Ordering::SeqCst);
        }
    });
    tx
}

/// What a worker reports back. Every answer carries the epoch it belongs to.
enum Msg {
    /// The adapters, read for a query (or a trace) of `seq`.
    Started { seq: u64, adapters: Result<Vec<Adapter>, String>, trace: bool },
    /// The adapters, read for the Resolvers popup.
    Adapters(Result<Vec<Adapter>, String>),
    Answer { seq: u64, col: usize, round: u32, outcome: Box<Outcome> },
    Context { seq: u64, ctx: Box<windows::Context> },
    Step { seq: u64, step: Box<Step> },
    TraceEnd { seq: u64, end: End, queries: usize },
    Flushed { seq: u64, result: Result<(), String> },
    HistoryLoaded(Loaded),
    HistorySaved { result: Result<(HistoryFile, Option<PathBuf>), String>, written: Vec<u64> },
}

type Job = Box<dyn FnOnce(&dyn Fn(Msg)) + Send>;

thread_local! {
    /// The app on this (the UI) thread, for workers' wake-ups.
    static APP: RefCell<std::rc::Weak<App>> = const { RefCell::new(std::rc::Weak::new()) };
}

struct Col {
    col: Column,
    outcome: Outcome,
    /// Bumped when this column alone is asked again (Flush): older answers do nothing.
    round: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Idle,
    Columns,
    Trace,
}

#[derive(Default)]
struct State {
    prefs: Prefs,
    /// The epoch: every query, trace or rerun takes a new one.
    seq: u64,
    mode: Mode,
    question: Option<Question>,
    /// CD as the shown query asked it.
    cd: bool,
    cols: Vec<Col>,
    left_out: usize,
    /// The adapters as last read (None: not yet).
    adapters: Option<Result<Vec<Adapter>, String>>,
    /// Windows' side for the shown query, once read.
    ctx: Option<windows::Context>,
    selected: usize,
    /// The name field's text as last asked: Escape puts it back.
    committed: String,
    steps: Vec<Step>,
    trace_end: Option<(End, usize)>,
    trace_sel: Option<usize>,
    trace_root: String,
    /// A card's height (record rows are fitted into it).
    card_h: f32,
    /// The epochs already put into the history.
    recorded: u64,
    /// The history as last read or written.
    history: Vec<Entry>,
    /// Entries not written yet (the file could not be read or written), newest first, with the
    /// epoch they belong to.
    unsaved: Vec<(u64, Entry)>,
    history_writing: bool,
    /// The last history write failed (said once, until one works again).
    history_failing: bool,
    /// A retry of the history write is armed.
    history_retry: bool,
    toast_seq: i32,
    toast_paths: HashMap<i32, PathBuf>,
    /// Each toast's timer generation (only the newest timer counts) and its full time in ms.
    toast_time: HashMap<i32, (u64, u64)>,
    /// The install check: its number (an answer for another one does nothing), and while it
    /// runs, where its answer comes from.
    check_seq: u64,
    check_rx: Option<Receiver<(u64, Rows)>>,
}

pub struct App {
    ui: Weak<AppWindow>,
    svc: Services,
    store: Store<Prefs>,
    st: RefCell<State>,
    prefs_tx: Sender<PrefsChange>,
    /// Changes sent to the prefs thread and not yet handed to the store.
    prefs_pending: Arc<AtomicUsize>,
    toasts: Rc<VecModel<ToastItem>>,
    cards: Rc<VecModel<Card>>,
    inbox: Arc<Mutex<Vec<Msg>>>,
    held: RefCell<Vec<Job>>,
    draining: Cell<bool>,
    /// The newest epoch, for a trace running on a worker to stop at.
    epoch: Arc<AtomicU64>,
    resolved: Arc<Resolved>,
    me: RefCell<std::rc::Weak<App>>,
    check_rows: Rc<VecModel<CheckRow>>,
    check_timer: Timer,
}

fn s(t: impl AsRef<str>) -> SharedString {
    t.as_ref().into()
}

fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::from(Rc::new(VecModel::from(v)))
}

impl App {
    /// Wire the controller to a window made by `crate::window`.
    pub fn attach(ui: &AppWindow, store: Store<Prefs>, svc: Services) -> Rc<App> {
        let prefs = store.load().sanitized();
        let prefs_pending = Arc::new(AtomicUsize::new(0));
        let prefs_tx = prefs_writer(store.clone(), prefs_pending.clone());
        let app = Rc::new(App {
            ui: ui.as_weak(),
            svc,
            store,
            st: RefCell::new(State { prefs, card_h: 400.0, ..State::default() }),
            prefs_tx,
            prefs_pending,
            toasts: Rc::new(VecModel::default()),
            cards: Rc::new(VecModel::default()),
            inbox: Arc::new(Mutex::new(Vec::new())),
            held: RefCell::new(Vec::new()),
            draining: Cell::new(false),
            epoch: Arc::new(AtomicU64::new(0)),
            resolved: Arc::new(Resolved::default()),
            me: RefCell::new(std::rc::Weak::new()),
            check_rows: Rc::new(VecModel::default()),
            check_timer: Timer::default(),
        });
        *app.me.borrow_mut() = Rc::downgrade(&app);
        APP.with(|a| *a.borrow_mut() = Rc::downgrade(&app));
        ui.set_toasts(ModelRc::from(app.toasts.clone()));
        ui.set_cards(ModelRc::from(app.cards.clone()));
        ui.set_types(model(query::QTYPES.iter().map(|(n, _)| s(n)).collect()));
        ui.set_check_rows(ModelRc::from(app.check_rows.clone()));
        app.show_rows(&Rows::idle());
        let bits = if cfg!(target_pointer_width = "64") { "64-bit" } else { "32-bit" };
        // VibeDNS has no portable mode: always installed.
        ui.set_about_line(s(format!("version {} · {bits} · installed for you", crate::VERSION)));
        app.wire(ui);
        app.show_prefs();
        app.refresh();
        if app.store.broken() {
            app.toast("prefs.json could not be read: the settings are back to their defaults, and the old file will be kept as prefs.json.broken.", ToastKind::Error, None);
        }
        let path = history::path_in(&app.svc.local_data);
        app.bg(move |send| send(Msg::HistoryLoaded(history::load(&path))));
        let win = app.svc.win.clone();
        app.bg(move |send| send(Msg::Adapters(win.adapters())));
        ui.invoke_focus_name();
        app
    }

    fn wire(self: &Rc<Self>, ui: &AppWindow) {
        macro_rules! on {
            ($setter:ident, |$a:ident $(, $arg:ident)*| $body:expr) => {{
                let w = Rc::downgrade(self);
                ui.$setter(move |$($arg),*| {
                    let Some($a) = w.upgrade() else { return Default::default() };
                    $body
                });
            }};
        }
        on!(on_toggle_theme, |a| a.toggle_theme());
        on!(on_copy_text, |a, t| (a.svc.copy)(&t));
        on!(on_toast_dismissed, |a, id| a.drop_toast(id));
        on!(on_toast_action, |a, id| a.toast_action(id));
        on!(on_dialogs_closed, |a| a.dialogs_closed());
        on!(on_check_install, |a| a.check_install());
        on!(on_open_site, |a| (a.svc.open_url)(crate::check::SITE));
        on!(on_name_edited, |a, _t| a.name_edited());
        on!(on_query, |a| {
            let t = a.field_text();
            a.query(&t)
        });
        on!(on_trace, |a| {
            let t = a.field_text();
            a.trace(&t)
        });
        on!(on_name_escaped, |a| a.name_escaped());
        on!(on_history_picked, |a, i| a.history_picked(i));
        on!(on_type_picked, |a, i| a.type_picked(i));
        on!(on_cd_toggled, |a, v| a.cd_toggled(v));
        on!(on_flush, |a| a.flush());
        on!(on_copy_all, |a| a.copy_all());
        on!(on_pick_toggled, |a, id| a.pick_toggled(&id));
        on!(on_custom_removed, |a, id| a.custom_removed(&id));
        on!(on_add_custom, |a| a.open_custom());
        on!(on_resolvers_opened, |a| a.resolvers_opened());
        on!(on_card_clicked, |a, i| a.card_clicked(i));
        on!(on_cards_resized, |a, h| a.cards_resized(h));
        on!(on_trace_row_clicked, |a, i| a.trace_row_clicked(i));
        on!(on_follow_clicked, |a| a.follow_clicked());
        on!(on_copy_detail, |a| a.copy_detail());
        on!(on_custom_add, |a| a.custom_add());
        on!(on_custom_cancelled, |a| a.close_custom());
    }

    fn ui(&self) -> Option<AppWindow> {
        self.ui.upgrade()
    }

    fn field_text(&self) -> String {
        self.ui().map(|u| u.get_name().to_string()).unwrap_or_default()
    }

    // ---------- About's install check ----------

    /// "Check this install": one at a time, on a worker (it reads the files and may go online);
    /// the window looks for the answer every CHECK_POLL_MS meanwhile and goes on. Closing About
    /// leaves it running: the answer lands in the rows, which About shows when it opens again.
    fn check_install(&self) {
        let Some(ui) = self.ui() else { return };
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.check_rx.is_some() {
                return;
            }
            st.check_seq += 1;
            st.check_seq
        };
        let (tx, rx) = channel();
        self.st.borrow_mut().check_rx = Some(rx);
        ui.set_checking(true);
        let (inspect, fetch, release) = (self.svc.inspect.clone(), self.svc.fetch.clone(), self.svc.release.clone());
        let installed = true;
        std::thread::spawn(move || {
            let local = inspect(&installed);
            // The exe updated or replaced under this one while it ran: nothing to compare (FED3).
            let rows = if local.replaced {
                crate::check::replaced_rows(&release, &local)
            } else {
                let fetched = fetch_within(fetch, crate::check::list_path(release.app), release.wait);
                crate::check::rows(&release, &local, fetched)
            };
            let _ = tx.send((seq, rows));
        });
        let w = self.me.borrow().clone();
        self.check_timer.start(TimerMode::Repeated, Duration::from_millis(CHECK_POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll_check();
            }
        });
    }

    /// The check's answer, once it is there: the rows, and the button back.
    fn poll_check(&self) {
        let got = {
            let st = self.st.borrow();
            let Some(rx) = st.check_rx.as_ref() else { return };
            match rx.try_recv() {
                Ok((seq, rows)) => Some((seq == st.check_seq).then_some(rows)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Some(Rows::stopped())),
            }
        };
        let Some(rows) = got else { return };
        self.check_timer.stop();
        self.st.borrow_mut().check_rx = None;
        if let Some(rows) = rows {
            self.show_rows(&rows);
        }
        if let Some(ui) = self.ui() {
            ui.set_checking(false);
            ui.set_checked(true);
        }
    }

    fn show_rows(&self, rows: &Rows) {
        let dot = |d: Dot| match d {
            Dot::Idle => CheckDot::Idle,
            Dot::Ok => CheckDot::Ok,
            Dot::Warn => CheckDot::Warn,
            Dot::Danger => CheckDot::Danger,
        };
        let all: Vec<CheckRow> = rows.all().iter().map(|(name, r)| CheckRow { name: s(name), text: s(&r.text), dot: dot(r.dot) }).collect();
        self.check_rows.set_vec(all);
    }

    // ---------- workers ----------

    /// Run `work` off the UI thread; what it sends comes back to `handle`, one wake-up per batch
    /// (tests: at once, or held until `release`).
    fn bg(&self, work: impl FnOnce(&dyn Fn(Msg)) + Send + 'static) {
        if self.svc.manual && self.svc.hold.get() {
            self.held.borrow_mut().push(Box::new(work));
            return;
        }
        let inbox = self.inbox.clone();
        if self.svc.manual {
            work(&|m| inbox.lock().unwrap_or_else(|e| e.into_inner()).push(m));
            self.drain();
            return;
        }
        let _ = std::thread::Builder::new().name("worker".into()).stack_size(512 * 1024).spawn(move || {
            let send = |m: Msg| {
                let first = {
                    let mut i = inbox.lock().unwrap_or_else(|e| e.into_inner());
                    i.push(m);
                    i.len() == 1
                };
                if first {
                    let _ = slint::invoke_from_event_loop(|| {
                        APP.with(|a| {
                            if let Some(app) = a.borrow().upgrade() {
                                app.drain();
                            }
                        })
                    });
                }
            };
            work(&send);
        });
    }

    /// Tests: the jobs held back so far.
    pub fn held(&self) -> usize {
        self.held.borrow().len()
    }

    /// Tests: let the held jobs answer, in the order they were started (or `order`).
    pub fn release(&self) {
        let jobs = std::mem::take(&mut *self.held.borrow_mut());
        let inbox = self.inbox.clone();
        for j in jobs {
            j(&|m| inbox.lock().unwrap_or_else(|e| e.into_inner()).push(m));
        }
        self.drain();
    }

    /// Tests: release only the last held job (an answer that overtakes the others).
    pub fn release_last(&self) {
        let job = self.held.borrow_mut().pop();
        if let Some(j) = job {
            let inbox = self.inbox.clone();
            j(&|m| inbox.lock().unwrap_or_else(|e| e.into_inner()).push(m));
            self.drain();
        }
    }

    fn drain(&self) {
        if self.draining.replace(true) {
            return;
        }
        loop {
            let msgs = std::mem::take(&mut *self.inbox.lock().unwrap_or_else(|e| e.into_inner()));
            if msgs.is_empty() {
                break;
            }
            for m in msgs {
                self.handle(m);
            }
        }
        self.draining.set(false);
        self.refresh();
    }

    fn handle(&self, m: Msg) {
        match m {
            Msg::Started { seq, adapters, trace } => self.started(seq, adapters, trace),
            Msg::Adapters(a) => {
                self.st.borrow_mut().adapters = Some(a);
                self.refresh_picks();
            }
            Msg::Answer { seq, col, round, outcome } => self.answered(seq, col, round, *outcome),
            Msg::Context { seq, ctx } => {
                let mut st = self.st.borrow_mut();
                if seq == st.seq {
                    st.ctx = Some(*ctx);
                }
            }
            Msg::Step { seq, step } => {
                let mut st = self.st.borrow_mut();
                if seq == st.seq && st.mode == Mode::Trace {
                    st.steps.push(*step);
                }
            }
            Msg::TraceEnd { seq, end, queries } => self.trace_ended(seq, end, queries),
            Msg::Flushed { seq, result } => self.flushed(seq, result),
            Msg::HistoryLoaded(l) => self.history_loaded(l),
            Msg::HistorySaved { result, written } => self.history_saved(result, written),
        }
    }

    // ---------- prefs ----------

    /// The prefs as this window has them (its own choices, in memory).
    pub fn prefs(&self) -> Prefs {
        self.st.borrow().prefs.clone()
    }

    /// One change to the prefs: at once in memory (this window's own choices), and by the prefs
    /// thread onto the newest saved ones, which may hold another instance's changes. A file
    /// found garbled on the way is told shortly after.
    pub fn save_prefs(&self, change: impl Fn(&mut Prefs) + Send + Sync + 'static) {
        let f: PrefsChange = Arc::new(change);
        f(&mut self.st.borrow_mut().prefs);
        self.prefs_pending.fetch_add(1, Ordering::SeqCst);
        if self.prefs_tx.send(f).is_err() {
            self.prefs_pending.fetch_sub(1, Ordering::SeqCst);
        }
        let w = self.me.borrow().clone();
        Timer::single_shot(Duration::from_millis(PREFS_TELL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.tell_garbled();
            }
        });
    }

    fn tell_garbled(&self) {
        if self.store.take_garbled() {
            self.toast("prefs.json was damaged: it is kept as prefs.json.broken, and this window's settings are saved in its place.", ToastKind::Error, None);
        }
    }

    /// At exit (and in tests): let the prefs thread hand its last change to the store (at most
    /// two seconds), then write what is unwritten onto the file as it is now.
    ///
    /// The last write runs on a thread of its own, waited for at most two seconds: a prefs file
    /// on a share that stopped answering never holds the window's thread for good (VibePing
    /// PING-8, review X15CON-4). A prefs thread still busy after its two seconds is not waited
    /// for: at exit the process ends it, and the changes it had not written are lost, unsaid.
    pub fn finish_prefs(&self) {
        let start = Instant::now();
        let limit = Duration::from_secs(2);
        while self.prefs_pending.load(Ordering::SeqCst) > 0 && start.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(2));
        }
        if self.prefs_pending.load(Ordering::SeqCst) > 0 {
            return;
        }
        let store = self.store.clone();
        let (tx, rx) = channel::<()>();
        std::thread::spawn(move || {
            store.flush();
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(limit);
    }

    fn toggle_theme(&self) {
        let Some(ui) = self.ui() else { return };
        let theme = ui.global::<Theme>();
        let dark = !theme.get_dark();
        theme.set_dark(dark);
        self.save_prefs(move |p| p.theme = Some(if dark { "dark" } else { "light" }.into()));
    }

    fn show_prefs(&self) {
        let Some(ui) = self.ui() else { return };
        let p = self.st.borrow().prefs.clone();
        ui.set_type_index(query::QTYPES.iter().position(|(n, _)| *n == p.qtype).unwrap_or(0) as i32);
        ui.set_cd(p.cd);
    }

    // ---------- asking ----------

    pub fn mode(&self) -> Mode {
        self.st.borrow().mode
    }

    fn next_seq(&self) -> u64 {
        let mut st = self.st.borrow_mut();
        st.seq += 1;
        self.epoch.store(st.seq, Ordering::SeqCst);
        st.seq
    }

    /// The question from the field (or the command line), or the error said and the field marked.
    /// The field's text is left as it is (a rerun must not throw away what is being typed).
    fn question(&self, text: &str) -> Option<Question> {
        let qtype = self.st.borrow().prefs.qtype_code();
        match query::parse_input(text, qtype) {
            Ok(q) => {
                if let Some(ui) = self.ui() {
                    ui.set_name_invalid(false);
                }
                Some(q)
            }
            Err(e) => {
                if let Some(ui) = self.ui() {
                    ui.set_name_invalid(true);
                }
                self.toast(&e, ToastKind::Error, None);
                None
            }
        }
    }

    /// Ask every column (the field's text, the command line, a history entry).
    pub fn query(&self, text: &str) {
        let Some(q) = self.question(text) else { return };
        let seq = self.next_seq();
        {
            let mut st = self.st.borrow_mut();
            st.mode = Mode::Columns;
            st.cd = st.prefs.cd;
            st.question = Some(q);
            st.committed = text.trim().to_string();
            st.cols.clear();
            st.ctx = None;
            st.steps.clear();
            st.trace_end = None;
        }
        self.refresh();
        let win = self.svc.win.clone();
        self.bg(move |send| send(Msg::Started { seq, adapters: win.adapters(), trace: false }));
    }

    /// The adapters are in: the columns are known; ask them all, and read Windows' side.
    fn started(&self, seq: u64, adapters: Result<Vec<Adapter>, String>, is_trace: bool) {
        if seq != self.st.borrow().seq {
            return;
        }
        self.st.borrow_mut().adapters = Some(adapters.clone());
        if is_trace {
            self.start_trace(seq, adapters.as_ref().map(|a| a.iter().any(|x| x.global_v6)).unwrap_or(false));
            return;
        }
        if let Err(e) = &adapters {
            self.toast(&format!("The network adapters could not be read ({}): their DNS servers are not asked this time.", text::clean(e, 160)), ToastKind::Error, None);
        }
        let adapter_cols = adapters.as_ref().map(|a| resolvers::adapter_columns(a)).unwrap_or_default();
        let (cols, left_out) = {
            let st = self.st.borrow();
            resolvers::columns(&adapter_cols, &st.prefs.selection())
        };
        let n = cols.len();
        {
            let mut st = self.st.borrow_mut();
            st.cols = cols.into_iter().map(|col| Col { col, outcome: Outcome::Pending, round: 0 }).collect();
            st.left_out = left_out;
            if st.selected >= n {
                st.selected = 0;
            }
        }
        self.refresh_picks();
        for i in 0..n {
            self.launch(seq, i, 0);
        }
        let (win, list) = (self.svc.win.clone(), adapters.unwrap_or_default());
        self.bg(move |send| send(Msg::Context { seq, ctx: Box::new(win.context(&list)) }));
    }

    /// Ask column `i` on a worker; its answer carries (seq, i, round).
    fn launch(&self, seq: u64, i: usize, round: u32) {
        let (col, q, cd) = {
            let st = self.st.borrow();
            let Some(c) = st.cols.get(i) else { return };
            let Some(q) = st.question.clone() else { return };
            (c.col.clone(), q, st.cd)
        };
        let (net, win, resolved) = (self.svc.net.clone(), self.svc.win.clone(), self.resolved.clone());
        self.bg(move |send| {
            let outcome = ask::run(&col, &q, cd, &*net, &*win, &resolved);
            send(Msg::Answer { seq, col: i, round, outcome: Box::new(outcome) });
        });
    }

    fn answered(&self, seq: u64, i: usize, round: u32, outcome: Outcome) {
        {
            let mut st = self.st.borrow_mut();
            if seq != st.seq || st.mode != Mode::Columns {
                return;
            }
            let Some(c) = st.cols.get_mut(i) else { return };
            if c.round != round {
                return;
            }
            c.outcome = outcome;
        }
        self.maybe_record();
    }

    fn comparison(&self) -> Comparison {
        let st = self.st.borrow();
        let inputs: Vec<compare::Input> = st.cols.iter().map(|c| c.outcome.compare_input()).collect();
        let raw: Vec<bool> = st.cols.iter().map(|c| c.col.raw()).collect();
        compare::compare(&inputs, &raw)
    }

    /// Why Windows differs, once Windows' side has been read.
    fn reason(&self) -> Option<String> {
        let st = self.st.borrow();
        Some(windows::reason(st.ctx.as_ref()?, st.question.as_ref()?))
    }

    /// Every column has answered: the query goes into the history (once per epoch).
    fn maybe_record(&self) {
        let (seq, done, mode) = {
            let st = self.st.borrow();
            (st.seq, !st.cols.is_empty() && st.cols.iter().all(|c| !c.outcome.pending()), st.mode)
        };
        if !done || mode != Mode::Columns || self.st.borrow().recorded >= seq {
            return;
        }
        let summary = self.status_text();
        let entry = {
            let st = self.st.borrow();
            let Some(q) = &st.question else { return };
            Entry { name: st.committed.clone(), qtype: q.type_text(), resolvers: st.cols.iter().map(|c| c.col.short()).collect(), time: (self.svc.now)(), summary, trace: false }
        };
        self.st.borrow_mut().recorded = seq;
        self.record(seq, entry);
    }

    /// `VibeDNS.exe <name> [type]`: the type becomes the selected one (as if picked), then the
    /// name is asked. A type the window does not offer is said, and the selected one is used.
    pub fn command_line(&self, name: &str, qtype: Option<&str>) {
        if let Some(t) = qtype {
            let up = t.trim().to_ascii_uppercase();
            if query::QTYPES.iter().any(|(n, _)| *n == up) {
                self.save_prefs(move |p| p.qtype = up.clone());
                self.show_prefs();
            } else {
                let offered: Vec<&str> = query::QTYPES.iter().map(|(n, _)| *n).collect();
                let current = self.st.borrow().prefs.qtype.clone();
                self.toast(&format!("“{}” is not a type VibeDNS asks ({}); asking {current}.", text::clean(t, 20), offered.join(", ")), ToastKind::Error, None);
            }
        }
        if let Some(ui) = self.ui() {
            ui.set_name(s(name.trim()));
        }
        self.query(name);
    }

    // ---------- the trace ----------

    /// Trace from the root.
    pub fn trace(&self, text: &str) {
        let Some(q) = self.question(text) else { return };
        let seq = self.next_seq();
        {
            let mut st = self.st.borrow_mut();
            st.mode = Mode::Trace;
            st.question = Some(q);
            st.committed = text.trim().to_string();
            st.cols.clear();
            st.steps.clear();
            st.trace_end = None;
            st.trace_sel = None;
            st.trace_root = String::new();
        }
        self.refresh();
        let win = self.svc.win.clone();
        self.bg(move |send| send(Msg::Started { seq, adapters: win.adapters(), trace: true }));
    }

    fn start_trace(&self, seq: u64, v6: bool) {
        let Some(q) = self.st.borrow().question.clone() else { return };
        let start = (self.svc.root_start)() % trace::ROOTS.len();
        self.st.borrow_mut().trace_root = format!("from {}.root-servers.net (root hints of {}){}", trace::ROOTS[start].0, trace::NAMED_ROOT, if v6 { ", IPv6 too" } else { "" });
        let (asker, epoch) = (self.svc.tracer.clone(), self.epoch.clone());
        self.bg(move |send| {
            let mut emit = |step: Step| send(Msg::Step { seq, step: Box::new(step) });
            let counting = CountingAsker { inner: &*asker, n: AtomicUsize::new(0) };
            let end = trace::trace(&counting, &q.labels, q.qtype, v6, start, &mut emit, &|| epoch.load(Ordering::SeqCst) != seq);
            send(Msg::TraceEnd { seq, end, queries: counting.n.load(Ordering::SeqCst) });
        });
    }

    fn trace_ended(&self, seq: u64, end: End, queries: usize) {
        {
            let mut st = self.st.borrow_mut();
            if seq != st.seq || st.mode != Mode::Trace {
                return;
            }
            st.trace_end = Some((end, queries));
        }
        let summary = self.status_text();
        let entry = {
            let st = self.st.borrow();
            let Some(q) = &st.question else { return };
            Entry { name: st.committed.clone(), qtype: q.type_text(), resolvers: vec!["root".into()], time: (self.svc.now)(), summary, trace: true }
        };
        self.st.borrow_mut().recorded = seq;
        self.record(seq, entry);
    }

    fn trace_row_clicked(&self, i: i32) {
        let mut st = self.st.borrow_mut();
        if i >= 0 && (i as usize) < st.steps.len() {
            st.trace_sel = Some(i as usize);
        }
        drop(st);
        self.refresh();
    }

    fn follow_clicked(&self) {
        let target = match &self.st.borrow().trace_end {
            Some((End::Cname(t), _)) => text::name(t),
            _ => return,
        };
        let t = target.trim_end_matches('.').to_string();
        if let Some(ui) = self.ui() {
            ui.set_name(s(&t));
        }
        self.trace(&t);
    }

    // ---------- the bar ----------

    fn name_edited(&self) {
        if let Some(ui) = self.ui() {
            ui.set_name_invalid(false);
        }
    }

    /// Escape in the name field: the name last asked goes back (true: the key was used).
    fn name_escaped(&self) -> bool {
        let committed = self.st.borrow().committed.clone();
        let Some(ui) = self.ui() else { return false };
        if ui.get_name() == committed.as_str() {
            return false;
        }
        ui.set_name(s(&committed));
        ui.set_name_invalid(false);
        true
    }

    /// Rerun what is shown (a new type, CD switched, other resolvers): with the name last asked,
    /// never the half-typed field, which keeps its text.
    fn rerun(&self) {
        let (mode, committed) = {
            let st = self.st.borrow();
            (st.mode, st.committed.clone())
        };
        match mode {
            Mode::Columns => self.query(&committed),
            Mode::Trace => self.trace(&committed),
            Mode::Idle => {}
        }
    }

    fn type_picked(&self, i: i32) {
        let Some((name, _)) = query::QTYPES.get(i.max(0) as usize) else { return };
        let name = name.to_string();
        self.save_prefs(move |p| p.qtype = name.clone());
        self.show_prefs();
        self.rerun();
    }

    fn cd_toggled(&self, v: bool) {
        self.save_prefs(move |p| p.cd = v);
        self.show_prefs();
        if self.mode() == Mode::Columns {
            self.rerun();
        }
    }

    fn history_picked(&self, i: i32) {
        let e = {
            let st = self.st.borrow();
            let all = Self::history_all(&st);
            all.get(i.max(0) as usize).cloned()
        };
        let Some(e) = e else { return };
        if query::QTYPES.iter().any(|(n, _)| *n == e.qtype) {
            let t = e.qtype.clone();
            self.save_prefs(move |p| p.qtype = t.clone());
            self.show_prefs();
        }
        if let Some(ui) = self.ui() {
            ui.set_name(s(&e.name));
        }
        if e.trace { self.trace(&e.name) } else { self.query(&e.name) }
    }

    /// Flush Windows' cache, then ask Windows again.
    fn flush(&self) {
        let seq = self.st.borrow().seq;
        let win = self.svc.win.clone();
        self.bg(move |send| send(Msg::Flushed { seq, result: win.flush() }));
    }

    fn flushed(&self, seq: u64, result: Result<(), String>) {
        if let Err(e) = result {
            self.toast(&e, ToastKind::Error, None);
            return;
        }
        let rerun = {
            let mut st = self.st.borrow_mut();
            if seq != st.seq || st.mode != Mode::Columns {
                None
            } else {
                st.cols.iter().position(|c| c.col.kind == Kind::Windows).map(|i| {
                    let c = &mut st.cols[i];
                    c.round += 1;
                    c.outcome = Outcome::Pending;
                    (i, c.round)
                })
            }
        };
        self.toast(if rerun.is_some() { "Windows' DNS cache is flushed; Windows is asked again." } else { "Windows' DNS cache is flushed." }, ToastKind::Ok, None);
        if let Some((i, round)) = rerun {
            self.st.borrow_mut().recorded = 0;
            self.launch(seq, i, round);
        }
    }

    fn card_clicked(&self, i: i32) {
        let mut st = self.st.borrow_mut();
        if i >= 0 && (i as usize) < st.cols.len() {
            st.selected = i as usize;
        }
        drop(st);
        self.refresh();
    }

    /// The cards area's height: a card is 24 px less (its margins).
    fn cards_resized(&self, h: f32) {
        let card = (h - 24.0).max(0.0);
        if (self.st.borrow().card_h - card).abs() >= 1.0 {
            self.st.borrow_mut().card_h = card;
            self.refresh();
        }
    }

    // ---------- copying ----------

    /// The selected column's response, or the trace (its step when one is picked).
    fn detail(&self) -> (String, String) {
        let st = self.st.borrow();
        let Some(q) = &st.question else { return (String::new(), String::new()) };
        match st.mode {
            Mode::Idle => (String::new(), String::new()),
            Mode::Trace => match st.trace_sel.and_then(|i| st.steps.get(i).map(|x| (i, x))) {
                Some((i, step)) => (format!("Step {} · {} at {}", i + 1, text::name(&step.zone), text::name(&step.server)), view::step_text(i, step)),
                None => ("The whole trace".into(), view::trace_text(q, &st.steps, &st.trace_end, &st.trace_root)),
            },
            Mode::Columns => match st.cols.get(st.selected) {
                Some(c) => (format!("{} · {} · full response", text::clean(&c.col.short(), 80), c.col.detail), ask::dig_text(&c.col, q, st.cd, &c.outcome)),
                None => (String::new(), String::new()),
            },
        }
    }

    fn copy_detail(&self) -> bool {
        let (_, body) = self.detail();
        !body.is_empty() && (self.svc.copy)(&body)
    }

    /// Every column as dig-style text, the status line first (or the whole trace).
    fn copy_all(&self) -> bool {
        let status = self.status_text();
        let body = {
            let st = self.st.borrow();
            let Some(q) = &st.question else { return false };
            match st.mode {
                Mode::Trace => view::trace_text(q, &st.steps, &st.trace_end, &st.trace_root),
                Mode::Columns => {
                    let mut t = format!(";; {status}\n");
                    for c in &st.cols {
                        t.push('\n');
                        t.push_str(&ask::dig_text(&c.col, q, st.cd, &c.outcome));
                    }
                    t
                }
                Mode::Idle => return false,
            }
        };
        (self.svc.copy)(&body)
    }

    // ---------- resolvers ----------

    fn resolvers_opened(&self) {
        self.refresh_picks();
        let win = self.svc.win.clone();
        self.bg(move |send| send(Msg::Adapters(win.adapters())));
    }

    fn adapter_cols(&self) -> Vec<Column> {
        match &self.st.borrow().adapters {
            Some(Ok(a)) => resolvers::adapter_columns(a),
            _ => Vec::new(),
        }
    }

    fn refresh_picks(&self) {
        let Some(ui) = self.ui() else { return };
        let adapter_cols = self.adapter_cols();
        let st = self.st.borrow();
        let sel = st.prefs.selection();
        let picks: Vec<Pick> = adapter_cols
            .iter()
            .map(|c| {
                let ip = c.id.trim_start_matches("adapter/").to_string();
                Pick { id: s(&c.id), label: s(&c.label), sub: s(c.detail.split(" · ").next().unwrap_or("")), checked: !sel.adapters_off.contains(&ip), enabled: true }
            })
            .collect();
        let note = match &st.adapters {
            None => "Reading the adapters…".to_string(),
            Some(Err(e)) => format!("The adapters could not be read: {}", text::clean(e, 160)),
            Some(Ok(_)) if picks.is_empty() => "No adapter that is up has a DNS server configured.".into(),
            Some(Ok(_)) => String::new(),
        };
        let presets: Vec<PresetRow> = PRESETS
            .iter()
            .flat_map(|p| {
                [false, true].map(|v6| {
                    let ids: Vec<SharedString> = Proto::ALL.iter().map(|x| s(resolvers::preset_id(p.key, *x, v6))).collect();
                    let on: Vec<bool> = ids.iter().map(|id| sel.on.iter().any(|o| o == id.as_str())).collect();
                    PresetRow { name: s(p.name), sub: s(if v6 { p.v6.to_string() } else { p.v4.to_string() }), ids: model(ids), on: model(on) }
                })
            })
            .collect();
        let customs: Vec<Pick> = st
            .prefs
            .customs
            .iter()
            .map(|c| {
                let col = c.column().ok();
                Pick {
                    id: s(c.column_id()),
                    label: s(col.as_ref().map(|x| x.label.clone()).unwrap_or_else(|| text::clean(&c.address, 80))),
                    sub: s(col.map(|x| x.detail).unwrap_or_default()),
                    checked: sel.on.contains(&c.column_id()),
                    enabled: true,
                }
            })
            .collect();
        let (cols, _) = resolvers::columns(&adapter_cols, &sel);
        drop(st);
        ui.set_adapter_picks(model(picks));
        ui.set_adapters_note(s(note));
        ui.set_presets(model(presets));
        ui.set_custom_picks(model(customs));
        ui.set_columns_text(s(format!("{} of {MAX_COLUMNS} columns", cols.len())));
    }

    /// A resolver switched on or off in the popup (refused past eight columns), then the shown
    /// question asked again with the new set.
    pub fn pick_toggled(&self, id: &str) {
        let adapter_cols = self.adapter_cols();
        let mut sel = self.st.borrow().prefs.selection();
        if let Some(ip) = id.strip_prefix("adapter/") {
            if let Some(i) = sel.adapters_off.iter().position(|a| a == ip) {
                sel.adapters_off.remove(i);
                if resolvers::columns(&adapter_cols, &sel).1 > 0 {
                    self.toast(&format!("At most {MAX_COLUMNS} columns: switch one off first."), ToastKind::Error, None);
                    return;
                }
            } else {
                sel.adapters_off.push(ip.to_string());
            }
        } else if let Some(i) = sel.on.iter().position(|o| o == id) {
            sel.on.remove(i);
        } else {
            sel.on.push(id.to_string());
            if resolvers::columns(&adapter_cols, &sel).1 > 0 {
                self.toast(&format!("At most {MAX_COLUMNS} columns: switch one off first."), ToastKind::Error, None);
                return;
            }
        }
        let (on, off) = (sel.on, sel.adapters_off);
        self.save_prefs(move |p| {
            p.columns = Some(on.clone());
            p.adapters_off = off.clone();
        });
        self.refresh_picks();
        if self.mode() == Mode::Columns {
            self.rerun();
        }
    }

    fn open_custom(&self) {
        let Some(ui) = self.ui() else { return };
        ui.set_custom_address(s(""));
        ui.set_custom_port(s(""));
        ui.set_custom_proto(0);
        ui.set_custom_tls(s(""));
        ui.set_custom_url(s(""));
        ui.set_custom_method(0);
        ui.set_custom_error(s(""));
        ui.set_custom_open(true);
    }

    fn close_custom(&self) {
        if let Some(ui) = self.ui() {
            ui.set_custom_open(false);
        }
    }

    /// Add the dialog's resolver: checked in words, switched on when there is room.
    fn custom_add(&self) {
        let Some(ui) = self.ui() else { return };
        let port_text = ui.get_custom_port().trim().to_string();
        let port = if port_text.is_empty() {
            0
        } else {
            match port_text.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => {
                    ui.set_custom_error(s("The port is a number from 1 to 65535."));
                    return;
                }
            }
        };
        let proto = Proto::ALL.get(ui.get_custom_proto().max(0) as usize).copied().unwrap_or(Proto::Udp);
        let mut p = self.st.borrow().prefs.clone();
        if p.customs.len() >= MAX_CUSTOM {
            ui.set_custom_error(s(format!("At most {MAX_CUSTOM} resolvers of your own: remove one first.")));
            return;
        }
        let c = Custom {
            id: p.next_custom_id(),
            address: ui.get_custom_address().to_string(),
            port,
            proto,
            tls_name: ui.get_custom_tls().to_string(),
            url: ui.get_custom_url().to_string(),
            post: ui.get_custom_method() == 1,
        };
        let c = match c.validated() {
            Ok(c) => c,
            Err(e) => {
                ui.set_custom_error(s(e));
                return;
            }
        };
        let id = c.column_id();
        p.customs.push(c);
        let mut sel = p.selection();
        sel.customs = p.customs.clone();
        sel.on.push(id);
        let room = resolvers::columns(&self.adapter_cols(), &sel).1 == 0;
        if !room {
            sel.on.pop();
            self.toast(&format!("Added, but switched off: at most {MAX_COLUMNS} columns."), ToastKind::Info, None);
        }
        let (customs, on) = (p.customs.clone(), sel.on);
        self.save_prefs(move |p| {
            p.customs = customs.clone();
            p.columns = Some(on.clone());
        });
        ui.set_custom_open(false);
        self.refresh_picks();
        if room && self.mode() == Mode::Columns {
            self.rerun();
        }
    }

    fn custom_removed(&self, id: &str) {
        let p = self.st.borrow().prefs.clone();
        let customs: Vec<Custom> = p.customs.iter().filter(|c| c.column_id() != id).cloned().collect();
        let on: Vec<String> = p.selection().on.into_iter().filter(|o| o != id).collect();
        let was_on = p.selection().on.iter().any(|o| o == id);
        self.save_prefs(move |p| {
            p.customs = customs.clone();
            p.columns = Some(on.clone());
        });
        self.refresh_picks();
        if was_on && self.mode() == Mode::Columns {
            self.rerun();
        }
    }

    // ---------- history ----------

    fn history_all(st: &State) -> Vec<Entry> {
        let mut all: Vec<Entry> = st.unsaved.iter().map(|(_, e)| e.clone()).collect();
        for e in &st.history {
            if !all.iter().any(|x| x.name.eq_ignore_ascii_case(&e.name) && x.qtype == e.qtype && x.trace == e.trace) {
                all.push(e.clone());
            }
        }
        all.truncate(history::MAX);
        all
    }

    fn history_loaded(&self, l: Loaded) {
        match l {
            Loaded::Fresh => {}
            Loaded::Read(f) => self.st.borrow_mut().history = f.entries,
            Loaded::Damaged { kept: Some(k) } => {
                let name = k.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                self.toast(&format!("history.json was damaged: it is kept as {name}, and a new history starts."), ToastKind::Error, Some(k));
            }
            Loaded::Damaged { kept: None } => self.toast("history.json is damaged and could not be set aside: the history is not written this time.", ToastKind::Error, None),
            Loaded::Unreadable(e) => self.toast(&format!("history.json cannot be read right now ({}): new queries are kept and written once it can be read.", text::clean(&e, 120)), ToastKind::Error, None),
        }
        self.refresh_history();
    }

    /// Into the history: kept in memory first, then written onto the file as it is now (every
    /// entry not written yet goes with it).
    fn record(&self, seq: u64, e: Entry) {
        {
            let mut st = self.st.borrow_mut();
            st.unsaved.insert(0, (seq, e));
            st.unsaved.truncate(history::MAX);
        }
        self.refresh_history();
        self.write_history();
    }

    fn write_history(&self) {
        let todo: Vec<(u64, Entry)> = {
            let mut st = self.st.borrow_mut();
            if st.history_writing || st.unsaved.is_empty() {
                return;
            }
            st.history_writing = true;
            st.unsaved.clone()
        };
        let path = history::path_in(&self.svc.local_data);
        self.bg(move |send| {
            let written: Vec<u64> = todo.iter().map(|(s, _)| *s).collect();
            let result = history::update(&path, |f| {
                for (_, e) in todo.iter().rev() {
                    history::add(f, e.clone());
                }
            });
            send(Msg::HistorySaved { result, written });
        });
    }

    fn history_saved(&self, result: Result<(HistoryFile, Option<PathBuf>), String>, written: Vec<u64>) {
        self.st.borrow_mut().history_writing = false;
        match result {
            Ok((f, kept)) => {
                {
                    let mut st = self.st.borrow_mut();
                    st.history = f.entries;
                    st.unsaved.retain(|(s, _)| !written.contains(s));
                    st.history_failing = false;
                }
                if let Some(k) = kept {
                    let name = k.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    self.toast(&format!("history.json was damaged: it is kept as {name}, and a new history starts."), ToastKind::Error, Some(k));
                }
                // Queries that finished while this write was under way.
                if !self.st.borrow().unsaved.is_empty() {
                    self.write_history();
                }
            }
            Err(e) => {
                let (said, armed) = {
                    let mut st = self.st.borrow_mut();
                    let said = std::mem::replace(&mut st.history_failing, true);
                    (said, std::mem::replace(&mut st.history_retry, true))
                };
                if !said {
                    self.toast(&e, ToastKind::Error, None);
                }
                // Read again shortly (family rule for state files), not only at the next query:
                // the entries waiting in memory would be lost at exit.
                if !armed {
                    let w = self.me.borrow().clone();
                    Timer::single_shot(Duration::from_millis(HISTORY_RETRY_MS), move || {
                        let Some(a) = w.upgrade() else { return };
                        a.st.borrow_mut().history_retry = false;
                        a.write_history();
                    });
                }
            }
        }
        self.refresh_history();
    }

    fn refresh_history(&self) {
        let Some(ui) = self.ui() else { return };
        let rows = view::history_rows(&Self::history_all(&self.st.borrow()), (self.svc.now)());
        ui.set_history(model(rows));
    }

    // ---------- the window ----------

    fn status_text(&self) -> String {
        let st = self.st.borrow();
        let Some(q) = &st.question else { return "Ready. Type a name or an address.".into() };
        match st.mode {
            Mode::Idle => "Ready. Type a name or an address.".into(),
            Mode::Trace => {
                let (end, _) = view::trace_end(&st.trace_end, st.steps.len());
                format!("Trace of {} {} · {end}", view::short_name(q), q.type_text())
            }
            Mode::Columns => {
                if st.cols.is_empty() {
                    return format!("{} {} · reading the adapters…", view::short_name(q), q.type_text());
                }
                drop(st);
                let cmp = self.comparison();
                let reason = self.reason();
                let st = self.st.borrow();
                let Some(q) = &st.question else { return String::new() };
                let pairs: Vec<(&Column, &Outcome)> = st.cols.iter().map(|c| (&c.col, &c.outcome)).collect();
                view::status(q, &pairs, &cmp, reason.as_deref())
            }
        }
    }

    /// Everything the window shows, from the state (one pass per batch of answers).
    fn refresh(&self) {
        let Some(ui) = self.ui() else { return };
        if self.draining.get() {
            return;
        }
        let cmp = self.comparison();
        let reason = self.reason();
        let status = self.status_text();
        let (title, body) = self.detail();
        let st = self.st.borrow();
        ui.set_started(st.mode != Mode::Idle);
        ui.set_tracing(st.mode == Mode::Trace);
        ui.set_status_left(s(&status));
        ui.set_status_warn(!cmp.differing().is_empty() && cmp.done());
        let (asked, note) = st.question.as_ref().map(|q| view::asked(q, st.left_out)).unwrap_or_default();
        ui.set_asked(s(asked));
        ui.set_asked_note(s(note));
        ui.set_asked_right(s(match st.mode {
            Mode::Idle => String::new(),
            Mode::Columns => format!("RD=1 · DO=1 · CD={} · EDNS {}", u8::from(st.cd), query::UDP_PAYLOAD),
            Mode::Trace => format!("RD=0 · DO=1 · EDNS {}", query::UDP_PAYLOAD),
        }));
        ui.set_status_right(s(match st.mode {
            Mode::Trace => "trace".to_string(),
            Mode::Columns => format!("{} columns", st.cols.len()),
            Mode::Idle => String::new(),
        }));
        // The cards.
        let pairs: Vec<(&Column, &Outcome)> = st.cols.iter().map(|c| (&c.col, &c.outcome)).collect();
        let intercepted = view::interceptions(&pairs);
        let cards: Vec<Card> = st
            .cols
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let q = st.question.as_ref().expect("columns exist only for a question");
                let verdict = cmp.verdicts.get(i).cloned().unwrap_or(Verdict::Waiting);
                view::card(&view::CardInput { col: &c.col, outcome: &c.outcome, verdict: &verdict, q, cd: st.cd, height: st.card_h, selected: i == st.selected, reason: if c.col.kind == Kind::Windows { reason.clone() } else { None }, intercepted: intercepted.get(i).cloned().flatten() })
            })
            .collect();
        if self.cards.row_count() == cards.len() {
            for (i, c) in cards.into_iter().enumerate() {
                self.cards.set_row_data(i, c);
            }
        } else {
            self.cards.set_vec(cards);
        }
        ui.set_has_answer(match st.mode {
            Mode::Columns => st.cols.iter().any(|c| !c.outcome.pending()),
            Mode::Trace => !st.steps.is_empty(),
            Mode::Idle => false,
        });
        // The trace.
        if st.mode == Mode::Trace {
            ui.set_trace_rows(model(view::trace_rows(&st.steps, st.trace_sel)));
            let q = st.question.as_ref().map(|q| format!("{} {}", q.name_text(), q.type_text())).unwrap_or_default();
            ui.set_trace_title(s(format!("Trace of {q} {}", st.trace_root)));
            let (end, kind) = view::trace_end(&st.trace_end, st.steps.len());
            ui.set_trace_end(s(end));
            ui.set_trace_end_kind(kind);
            ui.set_trace_follow(s(match &st.trace_end {
                Some((End::Cname(t), _)) => format!("Trace {}", text::name(t)),
                _ => String::new(),
            }));
        }
        // The detail: at most DETAIL_LINES lines (Copy has every one).
        let lines = body.lines().count();
        let shown = if lines > DETAIL_LINES {
            let mut t: String = body.lines().take(DETAIL_LINES).collect::<Vec<_>>().join("\n");
            t.push_str(&format!("\n;; … {} more lines: Copy has them all", lines - DETAIL_LINES));
            t
        } else {
            body
        };
        ui.set_detail_title(s(title));
        ui.set_detail_body(s(view::expand_tabs(shown.trim_end())));
    }

    /// The state's columns as (label, outcome) (tests and the command line).
    pub fn outcomes(&self) -> Vec<(String, Outcome)> {
        self.st.borrow().cols.iter().map(|c| (c.col.id.clone(), c.outcome.clone())).collect()
    }

    pub fn steps(&self) -> Vec<Step> {
        self.st.borrow().steps.clone()
    }

    pub fn status(&self) -> String {
        self.status_text()
    }

    // ---------- toasts ----------

    /// A toast, bottom right: errors stay 10 s, the rest 5 s. With `reveal` it offers "Show"
    /// (that file selected in Explorer).
    pub fn toast(&self, text: &str, kind: ToastKind, reveal: Option<PathBuf>) {
        let id = {
            let mut st = self.st.borrow_mut();
            st.toast_seq += 1;
            let id = st.toast_seq;
            if let Some(p) = reveal.clone() {
                st.toast_paths.insert(id, p);
            }
            id
        };
        while self.toasts.row_count() >= 3 {
            let old = self.toasts.row_data(0).map(|t| t.id).unwrap_or(0);
            self.drop_toast(old);
        }
        self.toasts.push(ToastItem { id, text: s(text::clean(text, 600)), kind, action: if reveal.is_some() { s("Show") } else { s("") } });
        self.arm_toast(id, if kind == ToastKind::Error { 10_000 } else { 5_000 });
    }

    fn dialog_open(&self) -> bool {
        self.ui().is_some_and(|ui| ui.get_about_open() || ui.get_custom_open())
    }

    /// A toast's timer, `ms` from now. Only its newest timer counts, and while a dialog is open
    /// it waits: the toast is in sight but out of reach there (`dialogs_closed` gives it its
    /// full time again).
    fn arm_toast(&self, id: i32, ms: u64) {
        let generation = {
            let mut st = self.st.borrow_mut();
            let t = st.toast_time.entry(id).or_insert((0, ms));
            t.0 += 1;
            t.0
        };
        let w = self.me.borrow().clone();
        Timer::single_shot(Duration::from_millis(ms), move || {
            let Some(a) = w.upgrade() else { return };
            let current = a.st.borrow().toast_time.get(&id).is_some_and(|t| t.0 == generation);
            if current && !a.dialog_open() {
                a.drop_toast(id);
            }
        });
    }

    /// A dialog closed: every toast gets its full time again.
    fn dialogs_closed(&self) {
        let all: Vec<(i32, u64)> = self.st.borrow().toast_time.iter().map(|(id, t)| (*id, t.1)).collect();
        for (id, ms) in all {
            self.arm_toast(id, ms);
        }
    }

    fn drop_toast(&self, id: i32) {
        if let Some(i) = self.toasts.iter().position(|t| t.id == id) {
            self.toasts.remove(i);
        }
        self.st.borrow_mut().toast_time.remove(&id);
        self.st.borrow_mut().toast_paths.remove(&id);
    }

    fn toast_action(&self, id: i32) {
        let p = self.st.borrow().toast_paths.get(&id).cloned();
        if let Some(p) = p {
            (self.svc.reveal)(&p);
        }
        self.drop_toast(id);
    }
}

/// Counts the trace's queries as they go (the end line says how many).
struct CountingAsker<'a> {
    inner: &'a dyn trace::Asker,
    n: AtomicUsize,
}

impl trace::Asker for CountingAsker<'_> {
    fn ask(&self, server: std::net::IpAddr, name: &query::Labels, qtype: u16) -> Result<(query::Reply, Duration), String> {
        self.n.fetch_add(1, Ordering::SeqCst);
        self.inner.ask(server, name, qtype)
    }
}
