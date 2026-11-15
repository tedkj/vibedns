//! VibeDNS: dig for Windows, with resolvers side by side and a column for what Windows itself
//! answers. A VibeWare app: Rust and Slint on the software renderer, one small exe, no runtime
//! beside it.
//!
//! The engine (`query`, `transport`, `windows`, `resolvers`, `compare`, `trace`, `history`)
//! asks and reads; `ask` runs one column and writes dig's text; `view` says what it means;
//! `controller` ties it to the window, which only lays out and draws.

pub mod ask;
pub mod check;
pub mod compare;
pub mod controller;
pub mod fake;
pub mod history;
pub mod host;
pub mod launch;
pub mod prefs;
pub mod query;
pub mod resolvers;
pub mod text;
pub mod trace;
pub mod transport;
pub mod trust;
pub mod view;
pub mod windows;

use resolvers::{Custom, MAX_CUSTOM, Selection, default_presets, preset_column};
use serde::{Deserialize, Serialize};
use slint::ComponentHandle;

slint::include_modules!();

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the window remembers between runs (prefs.json in %APPDATA%\com.tedkj.vibedns).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// "dark" or "light" once the user has picked one; until then the system's choice.
    pub theme: Option<String>,
    /// The record type asked ("AAAA").
    pub qtype: String,
    /// Checking disabled (CD=1).
    pub cd: bool,
    /// The public and custom columns that are on (ids); None until the user picks: the defaults
    /// (Cloudflare, Google and Quad9 over UDP).
    pub columns: Option<Vec<String>>,
    /// Adapter DNS servers the user switched off (addresses).
    pub adapters_off: Vec<String>,
    pub customs: Vec<Custom>,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { theme: None, qtype: "A".into(), cd: false, columns: None, adapters_off: Vec::new(), customs: Vec::new() }
    }
}

impl Prefs {
    pub fn dark(&self) -> bool {
        match self.theme.as_deref() {
            Some("dark") => true,
            Some("light") => false,
            _ => host::system_dark(),
        }
    }

    /// Only the values the window offers survive a hand-edited file; the rest fall back.
    pub fn sanitized(mut self) -> Prefs {
        if !matches!(self.theme.as_deref(), None | Some("dark") | Some("light")) {
            self.theme = None;
        }
        if !query::QTYPES.iter().any(|(n, _)| *n == self.qtype) {
            self.qtype = "A".into();
        }
        let mut seen = std::collections::HashSet::new();
        self.customs = std::mem::take(&mut self.customs).into_iter().filter_map(|c| c.validated().ok()).filter(|c| c.id > 0 && seen.insert(c.id)).take(MAX_CUSTOM).collect();
        if let Some(cols) = self.columns.take() {
            let mut out: Vec<String> = Vec::new();
            for id in cols {
                let known = preset_column(&id).is_some() || self.customs.iter().any(|c| c.column_id() == id);
                if known && !out.contains(&id) {
                    out.push(id);
                }
            }
            self.columns = Some(out);
        }
        self.adapters_off.retain(|a| a.parse::<std::net::IpAddr>().is_ok());
        self.adapters_off.dedup();
        self.adapters_off.truncate(64);
        self
    }

    pub fn qtype_code(&self) -> u16 {
        query::QTYPES.iter().find(|(n, _)| *n == self.qtype).map(|(_, c)| *c).unwrap_or(1)
    }

    pub fn selection(&self) -> Selection {
        Selection { on: self.columns.clone().unwrap_or_else(default_presets), adapters_off: self.adapters_off.clone(), customs: self.customs.clone() }
    }

    /// A free id for a new custom server.
    pub fn next_custom_id(&self) -> u32 {
        self.customs.iter().map(|c| c.id).max().unwrap_or(0) + 1
    }
}

/// The window with its basics wired: theme, version, copying. The controller adds the rest (the
/// theme switch too: it saves on the prefs thread).
pub fn window(prefs: prefs::Store<Prefs>) -> Result<AppWindow, slint::PlatformError> {
    let ui = AppWindow::new()?;
    let p = prefs.load().sanitized();
    ui.global::<Theme>().set_dark(p.dark());
    ui.set_version(VERSION.into());
    ui.on_copy_text(|t| host::copy_text(&t).is_ok());
    Ok(ui)
}

/// The command line's words (`VibeDNS.exe <name> [type]`), from `std::env::args_os`: a word that
/// is not valid Unicode (a lone surrogate) comes through with U+FFFD in its place and is refused
/// in words by the name check, never a panic at start (`args()` would abort the app silently).
pub fn command_line_words(args: impl Iterator<Item = std::ffi::OsString>) -> Vec<String> {
    args.skip(1).map(|a| a.to_string_lossy().into_owned()).collect()
}
