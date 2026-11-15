//! One column's question asked, and its answer written down as dig would: the work a column's
//! worker does (Windows through `DnsQueryEx`, every other column over its transport), and the
//! text the detail panel shows and Copy copies.

use crate::query::{self, Question, Reply, Rr};
use crate::resolvers::{Adapter, Column, Kind};
use crate::text;
use crate::transport::{Exchange, Net, Server};
use crate::windows::{self, WinAnswer};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The Windows side the app reads: adapters, DnsQueryEx, the cache flush, why Windows may
/// differ, and resolving a custom server's host name. The tests hand it a fake.
pub trait WinSide: Send + Sync {
    fn adapters(&self) -> Result<Vec<Adapter>, String>;
    fn query(&self, name: &str, qtype: u16) -> WinAnswer;
    fn flush(&self) -> Result<(), String>;
    fn context(&self, adapters: &[Adapter]) -> windows::Context;
    fn resolve(&self, host: &str) -> Result<IpAddr, String>;
    /// "2026-10-22 14:03:11" now, local time.
    fn now_text(&self) -> String;
}

/// The real Windows.
pub struct SystemWin;

impl WinSide for SystemWin {
    fn adapters(&self) -> Result<Vec<Adapter>, String> {
        crate::resolvers::system_adapters()
    }
    fn query(&self, name: &str, qtype: u16) -> WinAnswer {
        windows::query(name, qtype)
    }
    fn flush(&self) -> Result<(), String> {
        windows::flush()
    }
    fn context(&self, adapters: &[Adapter]) -> windows::Context {
        let mut doh = Ok(Vec::new());
        for a in adapters {
            match windows::doh_settings(&a.guid) {
                Ok(mut d) => {
                    if let Ok(all) = &mut doh {
                        all.append(&mut d);
                    }
                }
                // An interface without settings of its own fails with "not found": nothing to tell.
                Err(e) if e.contains("not an interface GUID") => {}
                Err(e) => {
                    if !e.contains("(os error 2)") {
                        doh = Err(e);
                    }
                }
            }
        }
        let mut suffixes = windows::search_list();
        for a in adapters {
            if !a.suffix.is_empty() && !suffixes.contains(&a.suffix) {
                suffixes.push(a.suffix.clone());
            }
        }
        windows::Context { hosts: windows::read_hosts(), nrpt: windows::read_nrpt(), doh, suffixes }
    }
    fn resolve(&self, host: &str) -> Result<IpAddr, String> {
        (host, 0u16)
            .to_socket_addrs()
            .map_err(|e| format!("“{}” could not be resolved by Windows: {}", text::clean(host, 80), text::clean(&e.to_string(), 120)))?
            .map(|a| a.ip())
            .next()
            .ok_or_else(|| format!("“{}” has no address.", text::clean(host, 80)))
    }
    fn now_text(&self) -> String {
        use windows_sys::Win32::Foundation::SYSTEMTIME;
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        let mut t = SYSTEMTIME { wYear: 0, wMonth: 0, wDayOfWeek: 0, wDay: 0, wHour: 0, wMinute: 0, wSecond: 0, wMilliseconds: 0 };
        // SAFETY: an out parameter.
        unsafe { GetLocalTime(&mut t) };
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond)
    }
}

/// What one column got.
#[derive(Clone, Debug, PartialEq)]
// One per column and query, never held in bulk: boxing the reply would only add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum Outcome {
    Pending,
    /// A DNS answer from a server.
    Raw { reply: Reply, server: Server, rtt_ms: f64, setup_ms: Option<f64>, via: String, ignored: u32, reused: bool, when: String },
    /// What Windows answered (`asked`: the name as handed to DnsQueryEx).
    Win { answer: WinAnswer, ms: f64, asked: String, when: String },
    /// No answer, in words.
    Failed(String),
}

impl Outcome {
    pub fn pending(&self) -> bool {
        matches!(self, Outcome::Pending)
    }

    /// For the comparison: the RCODE and the answer records, or no answer.
    pub fn compare_input(&self) -> crate::compare::Input {
        use crate::compare::Input;
        match self {
            Outcome::Pending => Input::Pending,
            Outcome::Failed(_) => Input::Failed,
            Outcome::Raw { reply, .. } => Input::Answer { rcode: reply.rcode, records: reply.answer.clone() },
            Outcome::Win { answer, .. } => match windows::status_rcode(answer.status) {
                Some(rcode) => Input::Answer { rcode, records: answer.answer.clone() },
                None => Input::Failed,
            },
        }
    }

    /// The answer records shown (answer section).
    pub fn records(&self) -> &[Rr] {
        match self {
            Outcome::Raw { reply, .. } => &reply.answer,
            Outcome::Win { answer, .. } => &answer.answer,
            _ => &[],
        }
    }
}

/// Custom servers' host names, resolved once per session (only answers are kept: a failure is
/// asked again next time).
#[derive(Default)]
pub struct Resolved(Mutex<HashMap<String, IpAddr>>);

impl Resolved {
    pub fn get(&self, host: &str, win: &dyn WinSide) -> Result<IpAddr, String> {
        let key = host.to_ascii_lowercase();
        if let Some(ip) = self.0.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            return Ok(*ip);
        }
        let ip = win.resolve(host)?;
        self.0.lock().unwrap_or_else(|e| e.into_inner()).insert(key, ip);
        Ok(ip)
    }
}

/// Ask one column (on a worker): Windows through DnsQueryEx, the rest over their transport with
/// a fresh random ID, RD=1, EDNS0 with DO=1 and CD as asked.
pub fn run(col: &Column, q: &Question, cd: bool, net: &dyn Net, win: &dyn WinSide, resolved: &Resolved) -> Outcome {
    if col.kind == Kind::Windows {
        let Some(name) = q.windows_name() else {
            return Outcome::Failed("Windows can only be asked for names it can write as text; this one has escaped bytes in a label.".into());
        };
        let t0 = Instant::now();
        let answer = win.query(&name, q.qtype);
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        if windows::status_rcode(answer.status).is_none() {
            return Outcome::Failed(windows::status_text(answer.status));
        }
        return Outcome::Win { answer, ms, asked: name, when: win.now_text() };
    }
    let Some(mut server) = col.server.clone() else { return Outcome::Failed("This column has no server.".into()) };
    if let Some((host, port)) = &col.resolve {
        match resolved.get(host, win) {
            Ok(ip) => server.addr = SocketAddr::new(ip, *port),
            Err(e) => return Outcome::Failed(e),
        }
    }
    let sent = query::build(&q.labels, q.qtype, query::random_id(), true, cd);
    match net.ask(&server, &sent) {
        Ok(Exchange { reply, rtt, setup, via, ignored, reused }) => match query::parse(&reply) {
            Ok(r) => Outcome::Raw { reply: r, server, rtt_ms: rtt.as_secs_f64() * 1000.0, setup_ms: setup.map(|d| d.as_secs_f64() * 1000.0), via, ignored, reused, when: win.now_text() },
            Err(e) => Outcome::Failed(format!("The answer from {} could not be read: {e}", server.addr)),
        },
        Err(e) => Outcome::Failed(e),
    }
}

fn section(out: &mut String, title: &str, records: &[Rr]) {
    if records.is_empty() {
        return;
    }
    out.push_str(&format!("\n;; {title} SECTION:\n"));
    for r in records {
        out.push_str(&r.line());
        out.push('\n');
    }
}

/// The question as dig's header names it: "example.com AAAA".
fn asked(q: &Question) -> String {
    format!("{} {}", q.name_text(), q.type_text())
}

/// One column's full response in dig's text format (the detail panel, Copy).
pub fn dig_text(col: &Column, q: &Question, cd: bool, o: &Outcome) -> String {
    let mut s = String::new();
    match o {
        Outcome::Pending => {
            s.push_str(&format!("; <<>> VibeDNS {} <<>> {}\n;; {}: asking…\n", crate::VERSION, asked(q), col.short()));
        }
        Outcome::Failed(e) => {
            let at = col.server.as_ref().map(|sv| format!(" @{}", sv.addr.ip())).unwrap_or_default();
            s.push_str(&format!("; <<>> VibeDNS {} <<>>{at} {} ({})\n;; {}: no answer\n;; {}\n", crate::VERSION, asked(q), col.detail, col.short(), text::clean(e, 400)));
        }
        Outcome::Raw { reply: r, server, rtt_ms, setup_ms, via, ignored, reused, when } => {
            s.push_str(&format!("; <<>> VibeDNS {} <<>> @{} {} +dnssec{} ({})\n", crate::VERSION, server.addr.ip(), asked(q), if cd { " +cdflag" } else { "" }, via));
            s.push_str(&format!(";; ->>HEADER<<- opcode: {}, status: {}, id: {}\n", if r.opcode == 0 { "QUERY".to_string() } else { format!("OPCODE{}", r.opcode) }, r.rcode_text(), r.id));
            let additional = r.additional.len() + usize::from(r.edns.is_some());
            s.push_str(&format!(";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n", r.flags.text(), r.question.len(), r.answer.len(), r.authority.len(), additional));
            if let Some(e) = &r.edns {
                s.push_str("\n;; OPT PSEUDOSECTION:\n");
                s.push_str(&format!("; EDNS: version: {}, flags:{}; udp: {}\n", e.version, if e.dnssec_ok { " do" } else { "" }, e.udp));
                for (code, t) in &e.ede {
                    s.push_str(&format!("; EDE: {code} ({}){}\n", text::ede_name(*code), if t.is_empty() { String::new() } else { format!(": ({t})") }));
                }
                if let Some(n) = &e.nsid {
                    s.push_str(&format!("; NSID: {}\n", text::clean(n, 120)));
                }
            }
            if !r.question.is_empty() {
                s.push_str("\n;; QUESTION SECTION:\n");
                for (n, t, c) in &r.question {
                    s.push_str(&format!(";{}\t\t{}\t{}\n", text::name(n), text::class_name(*c), text::type_name(*t)));
                }
            }
            section(&mut s, "ANSWER", &r.answer);
            section(&mut s, "AUTHORITY", &r.authority);
            section(&mut s, "ADDITIONAL", &r.additional);
            s.push_str(&format!("\n;; Query time: {}\n", text::ms(*rtt_ms).replace(" ms", " msec")));
            if let Some(su) = setup_ms {
                s.push_str(&format!(";; Connection setup: {} (new connection{})\n", text::ms(*su).replace(" ms", " msec"), if server.proto == crate::transport::Proto::Udp { "" } else { ", TCP and TLS where used" }));
            } else if *reused {
                s.push_str(";; Connection: kept from an earlier query\n");
            }
            s.push_str(&format!(";; SERVER: {}#{}({}) ({})\n", server.addr.ip(), server.addr.port(), if server.tls_name.is_empty() { server.addr.ip().to_string() } else { server.tls_name.clone() }, via));
            s.push_str(&format!(";; WHEN: {when} (local)\n"));
            s.push_str(&format!(";; MSG SIZE  rcvd: {}\n", r.size));
            if *ignored > 0 {
                s.push_str(&format!(";; {} other {} ignored (another ID, question or address)\n", ignored, if *ignored == 1 { "reply" } else { "replies" }));
            }
        }
        Outcome::Win { answer, ms, asked: name, when } => {
            s.push_str(&format!("; <<>> VibeDNS {} <<>> Windows (DnsQueryEx) {}\n", crate::VERSION, asked(q)));
            s.push_str(&format!(";; asked as: {}\n", text::clean(name, 300)));
            s.push_str(&format!(";; status: {}\n", windows::status_text(answer.status)));
            s.push_str(";; Windows does not report flags, the server it asked, or the message itself.\n");
            section(&mut s, "ANSWER", &answer.answer);
            if !answer.other.is_empty() {
                section(&mut s, "OTHER (authority and additional, as Windows passed them)", &answer.other);
            }
            if answer.not_decoded > 0 {
                s.push_str(&format!("\n;; {} more {}: answer present, not decoded\n", answer.not_decoded, if answer.not_decoded == 1 { "record" } else { "records" }));
            }
            s.push_str(&format!("\n;; Query time: {} (DnsQueryEx; from Windows' cache or the network, Windows does not say)\n", text::ms(*ms).replace(" ms", " msec")));
            s.push_str(&format!(";; WHEN: {when} (local)\n"));
        }
    }
    s
}

/// Several outcomes over one shared net, for a whole query (tests and the command line use it).
pub fn run_all(cols: &[Column], q: &Question, cd: bool, net: Arc<dyn Net>, win: Arc<dyn WinSide>) -> Vec<Outcome> {
    let resolved = Resolved::default();
    cols.iter().map(|c| run(c, q, cd, &*net, &*win, &resolved)).collect()
}
