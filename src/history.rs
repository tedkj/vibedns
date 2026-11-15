//! The last 50 queries (`%LOCALAPPDATA%\com.tedkj.vibedns\history.json`), newest first: name,
//! type, the resolvers asked, when, and the one-line summary. Under the prefs rules: a file
//! that cannot be parsed is kept aside as `.broken` (never saved over), one that cannot be read
//! right now is not written at all, and every write reads the file again first (another window
//! may have added its own queries).

use crate::prefs::write_atomic;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const MAX: usize = 50;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    /// As typed ("bücher.example", "192.0.2.7").
    pub name: String,
    /// "AAAA".
    pub qtype: String,
    /// The columns asked ("Windows", "Wi-Fi", "Cloudflare UDP").
    pub resolvers: Vec<String>,
    /// Unix seconds.
    pub time: u64,
    /// The status line it ended with.
    pub summary: String,
    /// A trace from the root, not a query.
    pub trace: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryFile {
    pub version: u32,
    pub entries: Vec<Entry>,
}

fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// A query to the front: the same name and type asked before goes (newest wins), at most `MAX`.
pub fn add(f: &mut HistoryFile, e: Entry) {
    f.version = 1;
    let e = Entry { name: cut(&e.name, 300), qtype: cut(&e.qtype, 12), resolvers: e.resolvers.iter().take(8).map(|r| cut(r, 80)).collect(), summary: cut(&e.summary, 300), ..e };
    f.entries.retain(|x| !(x.name.eq_ignore_ascii_case(&e.name) && x.qtype == e.qtype && x.trace == e.trace));
    f.entries.insert(0, e);
    f.entries.truncate(MAX);
}

/// What reading the file found.
#[derive(Debug, PartialEq, Eq)]
pub enum Loaded {
    /// No file yet.
    Fresh,
    Read(HistoryFile),
    /// It could not be parsed: kept aside under `kept` (None: even that failed).
    Damaged { kept: Option<PathBuf> },
    /// It is there but cannot be read right now.
    Unreadable(String),
}

pub fn load(path: &Path) -> Loaded {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Fresh,
        Err(e) => return Loaded::Unreadable(e.to_string()),
    };
    match serde_json::from_slice::<HistoryFile>(&bytes) {
        Ok(f) => Loaded::Read(f),
        Err(_) => Loaded::Damaged { kept: set_aside(path) },
    }
}

/// `history.json` -> `history.json.broken` (`.broken-2`, `-3` ... when one is there already).
fn set_aside(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_os_string();
    for i in 1..100 {
        let mut n = name.clone();
        n.push(if i == 1 { ".broken".to_string() } else { format!(".broken-{i}") });
        let aside = path.with_file_name(n);
        if aside.exists() {
            continue;
        }
        return std::fs::rename(path, &aside).ok().map(|_| aside);
    }
    None
}

static WRITE: Mutex<()> = Mutex::new(());

/// Change the file: read it again (the newest), change it, write it whole. A damaged file is set
/// aside first (the change starts a fresh one); an unreadable one is left alone (Err). Returns
/// the file as written and where a damaged one was kept.
pub fn update(path: &Path, change: impl FnOnce(&mut HistoryFile)) -> Result<(HistoryFile, Option<PathBuf>), String> {
    let _w = WRITE.lock().unwrap_or_else(|e| e.into_inner());
    let (mut f, kept) = match load(path) {
        Loaded::Fresh => (HistoryFile::default(), None),
        Loaded::Read(f) => (f, None),
        Loaded::Damaged { kept: Some(k) } => (HistoryFile::default(), Some(k)),
        Loaded::Damaged { kept: None } => return Err("history.json is damaged and could not be set aside, so it was left as it is.".into()),
        Loaded::Unreadable(e) => return Err(format!("history.json cannot be read right now ({e}), so the query was not added to it.")),
    };
    change(&mut f);
    let body = serde_json::to_vec_pretty(&f).map_err(|e| e.to_string())?;
    write_atomic(path, &body).map_err(|e| format!("The history could not be saved: {e}"))?;
    Ok((f, kept))
}

pub fn path_in(local_data: &Path) -> PathBuf {
    local_data.join("history.json")
}
