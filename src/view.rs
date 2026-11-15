//! What the window shows, as words and numbers: cards, the status line, the question line, the
//! trace rows and texts, the history rows. Pure functions of the state (tested); every text
//! from outside is cleaned here or comes already escaped (names, RDATA).

use crate::ask::Outcome;
use crate::compare::{self, Comparison, Verdict};
use crate::history::Entry;
use crate::query::{self, Question, RRSIG};
use crate::resolvers::{Column, Kind, PRESETS};
use crate::text;
use crate::trace::{End, Outcome as StepOutcome, Step};
use crate::transport::Proto;
use crate::windows;
use crate::{Card, Chip, HistoryRow, RecordRow, TraceRow};
use slint::{ModelRc, SharedString, VecModel};
use std::net::IpAddr;
use std::rc::Rc;

fn s(t: impl AsRef<str>) -> SharedString {
    t.as_ref().into()
}

fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::from(Rc::new(VecModel::from(v)))
}

/// The name as the status line says it: "example.com" (the root stays ".").
pub fn short_name(q: &Question) -> String {
    let n = q.name_text();
    if n == "." { n } else { n.trim_end_matches('.').to_string() }
}

pub const SERVFAIL_HINT: &str = "Try again with Checking disabled: if that answers, DNSSEC validation is failing.";
/// What the Windows card says where the others show flags.
pub const WINDOWS_FLAGS: &str = "Windows reports no flags and no server.";
pub const AD_TIP: &str = "AD: validated by this resolver. Its claim, not ours, and only as trustworthy as the path to it.";

/// The words before a reason's colon: "hosts file", "NRPT", "suffix search".
pub fn reason_short(reason: &str) -> String {
    if reason.starts_with("reason") {
        return reason.split(" (").next().unwrap_or(reason).to_string();
    }
    reason.split(':').next().unwrap_or(reason).to_string()
}

/// Everything one card needs.
pub struct CardInput<'a> {
    pub col: &'a Column,
    pub outcome: &'a Outcome,
    pub verdict: &'a Verdict,
    pub q: &'a Question,
    pub cd: bool,
    /// The card's height in pixels (record rows are fitted into it).
    pub height: f32,
    pub selected: bool,
    /// Why Windows differs (Windows' card only), once known.
    pub reason: Option<String>,
    /// This plain DNS answer looks intercepted, and why (`interceptions`).
    pub intercepted: Option<String>,
}

fn chip(text: &str, on: bool, kind: i32, tip: &str) -> Chip {
    Chip { text: s(text), on, kind, tip: s(tip) }
}

pub fn card(c: &CardInput) -> Card {
    let mut card = Card { title: s(text::clean(&c.col.label, 80)), sub: s(&c.col.detail), selected: c.selected, ..Card::default() };
    let mut notes: Vec<(String, i32)> = Vec::new();
    let mut a11y: Vec<String> = Vec::new();
    match c.outcome {
        Outcome::Pending => {
            card.state = 0;
            a11y.push("asking".into());
        }
        Outcome::Failed(e) => {
            card.state = 2;
            card.rcode = s("no answer");
            card.rcode_kind = 2;
            notes.push((text::clean(e, 400), 2));
            a11y.push(format!("no answer: {}", text::clean(e, 400)));
        }
        Outcome::Raw { reply, server, rtt_ms, setup_ms, via, .. } => {
            card.state = 1;
            let shown: Vec<&query::Rr> = reply.answer.iter().filter(|r| r.rtype != RRSIG).collect();
            let nodata = reply.rcode == 0 && shown.is_empty();
            card.rcode = s(reply.rcode_text());
            card.rcode_kind = if reply.rcode == 3 || nodata { 1 } else if reply.rcode == 0 { 0 } else { 2 };
            card.time = s(text::ms(*rtt_ms));
            card.setup = s(setup_ms.map(|su| format!("+{} connect", text::ms(su))).unwrap_or_default());
            card.time_tip = s(match setup_ms {
                Some(su) => format!("The query's round trip. Opening the connection took {} more ({}).", text::ms(*su), server.proto.name()),
                None => "The query's round trip.".to_string(),
            });
            if via != &server.via() || c.col.resolve.is_some() {
                let at = match &c.col.resolve {
                    Some((h, _)) => format!("{} → {}", text::clean(h, 60), server.addr.ip()),
                    None => server.addr.ip().to_string(),
                };
                card.sub = s(format!("{at} · {via}"));
            }
            let f = reply.flags;
            card.chips = model(vec![
                chip("AA", f.aa, 0, "AA: an authoritative answer"),
                chip("TC", f.tc, 2, "TC: the answer was truncated"),
                chip("RD", f.rd, 0, "RD: recursion desired (asked for)"),
                chip("RA", f.ra, 0, "RA: recursion available"),
                chip("AD", f.ad, 1, AD_TIP),
                chip("CD", f.cd, 0, "CD: checking disabled (asked for)"),
                chip("RRSIG", reply.signed(), 0, "Signatures came back (DO=1 asked for them)"),
            ]);
            card.count = s(text::count(shown.len(), "answer", "answers"));
            if reply.rcode == 3 {
                notes.push((format!("the name does not exist{}", neg(reply.negative_ttl())), 3));
            } else if nodata {
                notes.push((format!("no records of this type (NODATA){}", neg(reply.negative_ttl())), 3));
            }
            if let Some(e) = &reply.edns {
                for (code, t) in &e.ede {
                    notes.push((format!("EDE {code} ({}){}", text::ede_name(*code), if t.is_empty() { String::new() } else { format!(": {t}") }), 3));
                }
            }
            if reply.rcode == 2 && !c.cd {
                notes.push((SERVFAIL_HINT.into(), 1));
            }
            if let Some(t) = &c.intercepted {
                notes.insert(0, (t.clone(), 1));
                a11y.push(t.clone());
            }
            a11y.push(format!("{}, {}, {}", reply.rcode_text(), text::ms(*rtt_ms), card.count));
            if f.ad {
                a11y.push("validated by this resolver (AD)".into());
            }
        }
        Outcome::Win { answer, ms, .. } => {
            card.state = 1;
            let rcode = windows::status_rcode(answer.status).unwrap_or(2);
            let nodata = rcode == 0 && answer.answer.is_empty() && answer.not_decoded == 0;
            card.rcode = s(text::rcode_name(rcode));
            card.rcode_kind = if rcode == 3 || nodata { 1 } else if rcode == 0 { 0 } else { 2 };
            card.time = s(text::ms(*ms));
            card.time_tip = s("DnsQueryEx's round trip: from Windows' cache or the network, Windows does not say.");
            card.flags_note = s(WINDOWS_FLAGS);
            card.count = s(text::count(answer.answer.len(), "answer", "answers"));
            if rcode == 3 {
                notes.push(("the name does not exist".into(), 3));
            } else if nodata {
                notes.push(("no records of this type (NODATA)".into(), 3));
            }
            if answer.not_decoded > 0 && answer.answer.is_empty() {
                notes.push(("answer present, not decoded".into(), 3));
            }
            a11y.push(format!("{}, {}, {}", text::rcode_name(rcode), text::ms(*ms), card.count));
        }
    }
    // The verdict, once every column has answered.
    let mut extra: &[usize] = &[];
    match c.verdict {
        Verdict::Agrees => {
            card.verdict = s("agrees");
            card.verdict_kind = 1;
            card.verdict_tip = s("The same answer as the most common one (TTLs and order aside).");
            a11y.push("agrees".into());
        }
        Verdict::Differs { extra: e, missing, rcode } => {
            extra = e;
            card.verdict = s("differs");
            card.verdict_kind = 2;
            let mut parts = Vec::new();
            if *rcode {
                parts.push("another status".to_string());
            }
            if !e.is_empty() {
                parts.push(format!("{} not in the most common answer", text::count(e.len(), "record", "records")));
            }
            if *missing > 0 {
                parts.push(format!("{} of it missing", text::count(*missing, "record", "records")));
            }
            card.verdict_tip = s(format!("Differs from the most common answer: {}.", parts.join(", ")));
            a11y.push(format!("differs: {}", parts.join(", ")));
            if c.col.kind == Kind::Windows {
                match &c.reason {
                    Some(r) => notes.insert(0, (format!("Why: {r}"), 1)),
                    None => notes.insert(0, ("Why: checking…".into(), 3)),
                }
            }
        }
        Verdict::Waiting | Verdict::NoAnswer => {}
    }
    let records: Vec<RecordRow> = c
        .outcome
        .records()
        .iter()
        .enumerate()
        .filter(|(_, r)| r.rtype != RRSIG)
        .map(|(i, r)| RecordRow { r#type: s(text::type_name(r.rtype)), data: s(&r.text), ttl: s(r.ttl.to_string()), differs: extra.contains(&i) })
        .collect();
    let rows = rows_that_fit(c.height, &notes);
    if records.len() > rows {
        let keep = rows.saturating_sub(1).max(1);
        card.more = s(format!("+{} more in the detail below", records.len() - keep));
        card.records = model(records[..keep].to_vec());
    } else {
        card.records = model(records);
    }
    card.note = s(notes.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>().join("\n"));
    card.note_kind = notes.iter().map(|(_, k)| *k).find(|k| *k == 2).or_else(|| notes.iter().map(|(_, k)| *k).find(|k| *k == 1)).or(notes.first().map(|(_, k)| *k)).unwrap_or(0);
    card.a11y = s(a11y.join(", "));
    card
}

/// How many record rows fit a card of `height`: the fixed part (title, address, status, flags,
/// count, the rule) is 154 px, each wrapped note line 16 px, each row 25 px with its spacing.
pub fn rows_that_fit(height: f32, notes: &[(String, i32)]) -> usize {
    let lines: usize = notes.iter().flat_map(|(t, _)| t.split('\n')).map(|l| l.chars().count().div_ceil(40).max(1)).sum();
    let notes_h = if lines == 0 { 0.0 } else { lines as f32 * 16.0 + 5.0 };
    (((height - 154.0 - notes_h + 5.0) / 25.0).floor().max(1.0)) as usize
}

fn neg(ttl: Option<u32>) -> String {
    ttl.map(|t| format!(" · negative TTL {t} s")).unwrap_or_default()
}

/// The status line while asking and once every answer is in.
pub fn status(q: &Question, cols: &[(&Column, &Outcome)], cmp: &Comparison, reason: Option<&str>) -> String {
    let head = format!("{} {}", short_name(q), q.type_text());
    let n = cols.len();
    if !cmp.done() {
        return format!("{head} · asking {} · {} answered", text::count(n, "resolver", "resolvers"), n - cmp.pending);
    }
    let mut parts = vec![head, text::count(n, "resolver", "resolvers")];
    let differ = cmp.differing();
    let failed = cols.iter().filter(|(_, o)| matches!(o, Outcome::Failed(_))).count();
    if cmp.answered == 0 {
        parts.push("no answers".into());
    } else if differ.is_empty() {
        parts.push(if cmp.agree == n { "all agree".into() } else { format!("{} agree", cmp.agree) });
    } else {
        parts.push(format!("{} agree", cmp.agree));
        let names: Vec<String> = differ
            .iter()
            .map(|&i| {
                let c = cols[i].0;
                if c.kind == Kind::Windows {
                    match reason {
                        Some(r) => format!("Windows ({})", reason_short(r)),
                        None => "Windows".into(),
                    }
                } else {
                    text::clean(&c.short(), 60)
                }
            })
            .collect();
        let list = match names.len() {
            1 => names[0].clone(),
            2 => format!("{} and {}", names[0], names[1]),
            _ => format!("{} and {}", names[..names.len() - 1].join(", "), names[names.len() - 1]),
        };
        parts.push(format!("{list} {}", if names.len() == 1 { "differs" } else { "differ" }));
    }
    if failed > 0 {
        parts.push(format!("{failed} no answer"));
    }
    parts.join(" · ")
}

/// The words a card carries when its resolver's plain answer looks intercepted.
pub const INTERCEPTED: &str = "port 53 looks intercepted on the way";
/// The words when both are validated but differ: no claim of interception.
pub const DIFFERS: &str = "port 53 answer differs";

/// Port 53 interception, seen from the columns alone (no trace needed): the same resolver (one
/// provider's addresses, else one address) asked over plain DNS (UDP or TCP) and over DoT or
/// DoH, where the encrypted answer is validated (AD) and the plain answer (NOERROR or NXDOMAIN)
/// is not. Nothing protects port 53, so something on the way answered in the resolver's place.
/// Both validated with other records or another status: said as a difference only (another
/// cache explains it too). One entry per column: the reason, for the plain column's card.
pub fn interceptions(cols: &[(&Column, &Outcome)]) -> Vec<Option<String>> {
    let who = |ip: IpAddr| PRESETS.iter().find(|p| IpAddr::V4(p.v4) == ip || IpAddr::V6(p.v6) == ip).map(|p| p.key.to_string()).unwrap_or_else(|| ip.to_string());
    let same = |a: &query::Reply, b: &query::Reply| {
        let set = |r: &query::Reply| r.answer.iter().filter_map(compare::key).collect::<std::collections::BTreeSet<_>>();
        a.rcode == b.rcode && set(a) == set(b)
    };
    cols.iter()
        .map(|(_, o)| {
            let Outcome::Raw { reply, server, .. } = o else { return None };
            if !matches!(server.proto, Proto::Udp | Proto::Tcp) {
                return None;
            }
            let me = who(server.addr.ip());
            cols.iter().find_map(|(c, e)| {
                let Outcome::Raw { reply: enc, server: es, .. } = e else { return None };
                if !matches!(es.proto, Proto::Dot | Proto::Doh) || !enc.flags.ad || who(es.addr.ip()) != me {
                    return None;
                }
                let (name, plain) = (text::clean(&c.short(), 60), server.proto.name());
                // A plain failure (SERVFAIL, REFUSED, ...) never carries AD: not an answer to
                // compare, the ordinary verdict says it.
                if !matches!(reply.rcode, 0 | 3) {
                    None
                } else if !reply.flags.ad {
                    Some(format!("{INTERCEPTED}: {name}'s answer is validated (AD), this one over {plain} is not"))
                } else if !same(reply, enc) {
                    // Both validated: another cache (the provider's v4 and v6 land on different
                    // anycast sites) explains it as well as an interceptor. Said, not claimed.
                    Some(format!("{DIFFERS}: {name}'s validated (AD) answer is not this one over {plain}"))
                } else {
                    None
                }
            })
        })
        .collect()
}

/// The question line: what goes on the wire, and the notes about it.
pub fn asked(q: &Question, left_out: usize) -> (String, String) {
    let line = format!("{} {}", q.name_text(), q.type_text());
    let mut notes = Vec::new();
    if let Some(u) = &q.unicode {
        notes.push(format!("IDN: {}", text::clean(u, 120)));
    }
    if let Some(ip) = q.ptr_of {
        notes.push(format!("the reverse name of {ip}"));
    }
    if q.single_label {
        notes.push("a single label: sent as typed; Windows adds its search suffixes".into());
    }
    if left_out > 0 {
        notes.push(format!("{} left out: at most 8 columns", text::count(left_out, "resolver", "resolvers")));
    }
    (line, notes.join(" · "))
}

// ---------- the trace ----------

fn step_result(o: &StepOutcome) -> (String, i32, String) {
    match o {
        StepOutcome::Referral { zone, ns, ds, glue } => {
            let g = if *glue == ns.len() { String::new() } else { format!(", {glue} with glue") };
            (format!("→ {} ({}{g})", text::name(zone), text::count(ns.len(), "NS", "NS")), 0, if *ds { "DS".into() } else { "no DS".into() })
        }
        StepOutcome::Answer { records } => {
            let n = records.iter().filter(|r| r.rtype != RRSIG).count();
            let first = records.iter().find(|r| r.rtype != RRSIG).map(|r| format!(": {} {}", text::type_name(r.rtype), r.text)).unwrap_or_default();
            (format!("answer, {}{first}", text::count(n, "record", "records")), 1, String::new())
        }
        StepOutcome::Cname { target, .. } => (format!("CNAME to {}", text::name(target)), 3, String::new()),
        StepOutcome::NxDomain { soa } => (format!("NXDOMAIN{}", neg(*soa)), 3, String::new()),
        StepOutcome::NoData { soa } => (format!("no records of this type (NODATA){}", neg(*soa)), 3, String::new()),
        StepOutcome::Failed(e) => (text::clean(e, 300), 2, String::new()),
    }
}

pub fn trace_rows(steps: &[Step], selected: Option<usize>) -> Vec<TraceRow> {
    steps
        .iter()
        .enumerate()
        .map(|(i, st)| {
            let (result, kind, ds) = step_result(&st.outcome);
            let indent = "  ".repeat(st.depth as usize);
            let zone = if st.depth > 0 { format!("{indent}↳ {}", text::name(&st.zone)) } else { text::name(&st.zone) };
            let addr = st.ip.map(|ip| ip.to_string()).unwrap_or_else(|| "no address".into());
            let time = st.ms.map(text::ms).unwrap_or_default();
            let mut a11y = format!("zone {}, server {} {addr}, {time}, {result}", text::name(&st.zone), text::name(&st.server));
            if let Some(n) = &st.for_ns {
                a11y.push_str(&format!(", resolving {}", text::name(n)));
            }
            TraceRow {
                index: i as i32,
                num: s((i + 1).to_string()),
                depth: st.depth as i32,
                zone: s(zone),
                server: s(text::name(&st.server)),
                addr: s(addr),
                time: s(time),
                result: s(result),
                kind,
                ds: s(ds),
                selected: selected == Some(i),
                a11y: s(a11y),
            }
        })
        .collect()
}

/// The end in words and its colour kind.
pub fn trace_end(end: &Option<(End, usize)>, steps: usize) -> (String, i32) {
    match end {
        None => (format!("tracing… {}", text::count(steps, "step", "steps")), 0),
        Some((e, n)) => {
            let kind = match e {
                End::Answer => 1,
                End::Error(_) | End::Limit => 2,
                _ => 3,
            };
            let words = text::clean(&e.text(), 300);
            // An error is a sentence; a name keeps its dot.
            let words = if matches!(e, End::Error(_)) { words.trim_end_matches('.').to_string() } else { words };
            (format!("{words} · {}", text::count(*n, "query", "queries")), kind)
        }
    }
}

/// One step as text (the detail panel when a step is selected).
pub fn step_text(i: usize, st: &Step) -> String {
    let (result, _, ds) = step_result(&st.outcome);
    let mut t = format!(";; step {}: {} asked as a server of {}\n", i + 1, text::name(&st.server), text::name(&st.zone));
    if let Some(ip) = st.ip {
        t.push_str(&format!(";; SERVER: {ip}#53 (UDP, RD=0, DO=1)\n"));
    }
    if let Some(ms) = st.ms {
        t.push_str(&format!(";; Query time: {}\n", text::ms(ms).replace(" ms", " msec")));
    }
    if let Some(n) = &st.for_ns {
        t.push_str(&format!(";; resolving {} (it has no glue)\n", text::name(n)));
    }
    t.push_str(&format!(";; {result}{}\n", if ds.is_empty() { String::new() } else { format!(" · {ds}") }));
    match &st.outcome {
        StepOutcome::Referral { zone, ns, .. } => {
            t.push('\n');
            for n in ns {
                t.push_str(&format!("{}\t\tIN\tNS\t{}\n", text::name(zone), text::name(n)));
            }
        }
        StepOutcome::Answer { records } | StepOutcome::Cname { records, .. } => {
            t.push('\n');
            for r in records {
                t.push_str(&r.line());
                t.push('\n');
            }
        }
        _ => {}
    }
    t
}

/// The whole trace as text (Copy, and the detail before a step is picked), dig +trace's way.
pub fn trace_text(q: &Question, steps: &[Step], end: &Option<(End, usize)>, root_note: &str) -> String {
    let mut t = format!("; <<>> VibeDNS {} <<>> {} {} +trace\n;; {root_note}\n", crate::VERSION, q.name_text(), q.type_text());
    for (i, st) in steps.iter().enumerate() {
        t.push('\n');
        t.push_str(&step_text(i, st));
    }
    let (e, _) = trace_end(end, steps.len());
    t.push_str(&format!("\n;; {e}\n"));
    t
}

/// Tabs as spaces to the next stop of 8 (the window has no tab stops; Copy keeps the tabs).
pub fn expand_tabs(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 4);
    for (i, line) in s.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let mut col = 0;
        for c in line.chars() {
            if c == '\t' {
                let n = 8 - col % 8;
                out.extend(std::iter::repeat_n(' ', n));
                col += n;
            } else {
                out.push(c);
                col += 1;
            }
        }
    }
    out
}

// ---------- history ----------

/// "just now", "5 min ago", "3 h ago", "2 d ago".
pub fn age(then: u64, now: u64) -> String {
    let d = now.saturating_sub(then);
    match d {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", d / 60),
        3600..86_400 => format!("{} h ago", d / 3600),
        _ => format!("{} d ago", d / 86_400),
    }
}

pub fn history_rows(entries: &[Entry], now: u64) -> Vec<HistoryRow> {
    entries
        .iter()
        .map(|e| HistoryRow {
            name: s(text::clean(&e.name, 120)),
            r#type: s(if e.trace { format!("{} trace", text::clean(&e.qtype, 12)) } else { text::clean(&e.qtype, 12) }),
            summary: s(text::clean(&e.summary, 200)),
            when: s(age(e.time, now)),
        })
        .collect()
}
