//! Trace from the root, as `dig +trace`: iterative (RD=0, DO=1), starting at a random root
//! server from the built-in hints, following referrals by their glue. An NS name without glue is
//! resolved by its own iterative walk (at most 4 deep). A server that does not answer in 3 s, or
//! answers lamely, gives way to the next NS of that zone. Only public addresses are asked:
//! glue or an NS address in loopback, private, link-local, multicast or reserved space is
//! skipped and the step says so (`not_global`, SNB4). The walk stops at the answer, at a
//! CNAME, at an error, or after 40 queries.

use crate::query::{self, Data, Labels, Reply, Rr};
use crate::text;
use crate::transport::{Net, Proto, Server};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// The root hints: IANA's named.root, last update December 20, 2023 (root zone 2023122001),
/// the one after B-root moved to 170.247.170.2 and 2801:1b8:10::b.
pub const NAMED_ROOT: &str = "2023-12-20";
pub const ROOTS: [(&str, Ipv4Addr, Ipv6Addr); 13] = [
    ("a", Ipv4Addr::new(198, 41, 0, 4), Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 2, 0x30)),
    ("b", Ipv4Addr::new(170, 247, 170, 2), Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb)),
    ("c", Ipv4Addr::new(192, 33, 4, 12), Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc)),
    ("d", Ipv4Addr::new(199, 7, 91, 13), Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd)),
    ("e", Ipv4Addr::new(192, 203, 230, 10), Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe)),
    ("f", Ipv4Addr::new(192, 5, 5, 241), Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf)),
    ("g", Ipv4Addr::new(192, 112, 36, 4), Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d)),
    ("h", Ipv4Addr::new(198, 97, 190, 53), Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53)),
    ("i", Ipv4Addr::new(192, 36, 148, 17), Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53)),
    ("j", Ipv4Addr::new(192, 58, 128, 30), Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 2, 0x30)),
    ("k", Ipv4Addr::new(193, 0, 14, 129), Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 1)),
    ("l", Ipv4Addr::new(199, 7, 83, 42), Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42)),
    ("m", Ipv4Addr::new(202, 12, 27, 33), Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35)),
];

pub const MAX_QUERIES: usize = 40;
pub const MAX_DEPTH: u8 = 4;
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// One question to one server, iteratively.
pub trait Asker: Send + Sync {
    /// The reply and its round trip, or what went wrong in words.
    fn ask(&self, server: IpAddr, name: &Labels, qtype: u16) -> Result<(Reply, Duration), String>;
}

/// Over the network: UDP (one try of 3 s; TC=1 retried over TCP), RD=0, DO=1.
pub struct NetAsker {
    pub net: Arc<dyn Net>,
}

impl Asker for NetAsker {
    fn ask(&self, server: IpAddr, name: &Labels, qtype: u16) -> Result<(Reply, Duration), String> {
        let sent = query::build(name, qtype, query::random_id(), false, false);
        let x = self.net.ask(&Server::plain(SocketAddr::new(server, 53), Proto::Udp), &sent)?;
        let r = query::parse(&x.reply).map_err(|e| format!("The answer could not be read: {e}"))?;
        Ok((r, x.rtt))
    }
}

/// What one step found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Sent down to `zone`'s servers.
    Referral { zone: Labels, ns: Vec<Labels>, ds: bool, glue: usize },
    /// The authoritative answer.
    Answer { records: Vec<Rr> },
    /// The name is an alias: the walk stops here (trace the target next).
    Cname { target: Labels, records: Vec<Rr> },
    NxDomain { soa: Option<u32> },
    NoData { soa: Option<u32> },
    /// No use (a timeout, a lame or failing server): the next server is asked.
    Failed(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    /// The zone the server was asked as a server of.
    pub zone: Labels,
    pub server: Labels,
    pub ip: Option<IpAddr>,
    pub ms: Option<f64>,
    pub outcome: Outcome,
    /// 0: the walk itself; 1..4: resolving a glueless NS name (`for_ns`).
    pub depth: u8,
    pub for_ns: Option<Labels>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum End {
    Answer,
    Cname(Labels),
    NxDomain,
    NoData,
    Error(String),
    /// Stopped after `MAX_QUERIES`.
    Limit,
}

impl End {
    pub fn text(&self) -> String {
        match self {
            End::Answer => "authoritative answer".into(),
            End::Cname(t) => format!("CNAME to {}", text::name(t)),
            End::NxDomain => "NXDOMAIN: the name does not exist".into(),
            End::NoData => "no records of this type (NODATA)".into(),
            End::Error(e) => e.clone(),
            End::Limit => format!("stopped after {MAX_QUERIES} queries"),
        }
    }
}

struct Walk<'a> {
    asker: &'a dyn Asker,
    v6: bool,
    queries: usize,
    emit: &'a mut dyn FnMut(Step),
    /// Stops the walk between queries (a newer trace or query started).
    cancelled: &'a dyn Fn() -> bool,
}

type Candidate = (Labels, Option<IpAddr>);

/// The root servers, starting at `start` (random in the app): IPv4, plus IPv6 when this PC has
/// a global IPv6 address.
pub fn root_servers(start: usize, v6: bool) -> Vec<Candidate> {
    let mut v: Vec<Candidate> = Vec::new();
    for i in 0..ROOTS.len() {
        let (l, a, _) = ROOTS[(start + i) % ROOTS.len()];
        v.push((root_name(l), Some(IpAddr::V4(a))));
    }
    if v6 {
        for i in 0..ROOTS.len() {
            let (l, _, a) = ROOTS[(start + i) % ROOTS.len()];
            v.push((root_name(l), Some(IpAddr::V6(a))));
        }
    }
    v
}

fn root_name(letter: &str) -> Labels {
    vec![letter.as_bytes().to_vec(), b"root-servers".to_vec(), b"net".to_vec()]
}

/// Walk from the root for `name`/`qtype`; every step goes to `emit` as it happens.
pub fn trace(asker: &dyn Asker, name: &Labels, qtype: u16, v6: bool, start: usize, emit: &mut dyn FnMut(Step), cancelled: &dyn Fn() -> bool) -> End {
    let mut w = Walk { asker, v6, queries: 0, emit, cancelled };
    match w.walk(name, qtype, 0, None, root_servers(start, v6)) {
        Ok((end, _)) => end,
        Err(end) => end,
    }
}

impl Walk<'_> {
    // One field per argument of the Step it emits: a struct here would only repeat Step.
    #[allow(clippy::too_many_arguments)]
    fn step(&mut self, zone: &Labels, server: &Labels, ip: Option<IpAddr>, ms: Option<f64>, outcome: Outcome, depth: u8, for_ns: &Option<Labels>) {
        (self.emit)(Step { zone: zone.clone(), server: server.clone(), ip, ms, outcome, depth, for_ns: for_ns.clone() });
    }

    /// The walk for one name: its end, and the answer's records when it ends in one. Err
    /// carries an end that stops the whole trace (the query limit, a cancel).
    fn walk(&mut self, name: &Labels, qtype: u16, depth: u8, for_ns: Option<Labels>, roots: Vec<Candidate>) -> Result<(End, Vec<Rr>), End> {
        let mut zone: Labels = Vec::new();
        let mut servers = roots;
        'zones: loop {
            for (sname, sip) in servers.clone() {
                if (self.cancelled)() {
                    return Err(End::Error("stopped".into()));
                }
                let ip = match sip {
                    Some(ip) => ip,
                    None => match self.address_of(&sname, depth)? {
                        Ok(ip) => ip,
                        Err(why) => {
                            self.step(&zone, &sname, None, None, Outcome::Failed(why), depth, &for_ns);
                            continue;
                        }
                    },
                };
                if self.queries >= MAX_QUERIES {
                    return Err(End::Limit);
                }
                self.queries += 1;
                let (reply, rtt) = match self.asker.ask(ip, name, qtype) {
                    Ok(x) => x,
                    Err(e) => {
                        self.step(&zone, &sname, Some(ip), None, Outcome::Failed(e), depth, &for_ns);
                        continue;
                    }
                };
                let ms = Some(rtt.as_secs_f64() * 1000.0);
                // Only an authoritative server's reply ends the walk (an answer, NXDOMAIN, NODATA,
                // a CNAME): without AA it came from a recursive resolver (a lame delegation, or
                // something on the way). The next server is asked.
                let lame = |what: &str| Outcome::Failed(format!("{what} without AA (a recursive or lame server)"));
                if reply.rcode == 3 {
                    if !reply.flags.aa {
                        self.step(&zone, &sname, Some(ip), ms, lame("NXDOMAIN"), depth, &for_ns);
                        continue;
                    }
                    self.step(&zone, &sname, Some(ip), ms, Outcome::NxDomain { soa: reply.negative_ttl() }, depth, &for_ns);
                    return Ok((End::NxDomain, Vec::new()));
                }
                // A root server never offers recursion: RA from one means something on the way
                // answers in its place (port 53 intercepted).
                let posing = zone.is_empty() && reply.flags.ra;
                if posing {
                    let why = format!("{} with RA set: not a root server's answer; something on the way intercepts DNS on port 53", reply.rcode_text());
                    self.step(&zone, &sname, Some(ip), ms, Outcome::Failed(why), depth, &for_ns);
                    continue;
                }
                if reply.rcode != 0 {
                    let why = format!("{} (a lame or failing server)", reply.rcode_text());
                    self.step(&zone, &sname, Some(ip), ms, Outcome::Failed(why), depth, &for_ns);
                    continue;
                }
                let mine: Vec<Rr> = reply.answer.iter().filter(|r| query::same_name(&r.owner, name)).cloned().collect();
                if mine.iter().any(|r| r.rtype == qtype) {
                    if !reply.flags.aa {
                        self.step(&zone, &sname, Some(ip), ms, lame("an answer"), depth, &for_ns);
                        continue;
                    }
                    self.step(&zone, &sname, Some(ip), ms, Outcome::Answer { records: reply.answer.clone() }, depth, &for_ns);
                    return Ok((End::Answer, reply.answer.clone()));
                }
                if let Some(Data::Target(t)) = mine.iter().find(|r| r.rtype == query::CNAME).map(|r| r.data.clone()) {
                    if !reply.flags.aa {
                        self.step(&zone, &sname, Some(ip), ms, lame("a CNAME"), depth, &for_ns);
                        continue;
                    }
                    self.step(&zone, &sname, Some(ip), ms, Outcome::Cname { target: t.clone(), records: reply.answer.clone() }, depth, &for_ns);
                    return Ok((End::Cname(t), Vec::new()));
                }
                if let Some((child, ns)) = referral(&reply, &zone, name) {
                    let ds = reply.authority.iter().any(|r| r.rtype == query::DS && query::same_name(&r.owner, &child));
                    let (next, skipped) = self.candidates(&reply, &ns);
                    let glue = next.iter().filter(|c| c.1.is_some()).count();
                    self.step(&zone, &sname, Some(ip), ms, Outcome::Referral { zone: child.clone(), ns: ns.clone(), ds, glue }, depth, &for_ns);
                    for (n, a, why) in skipped {
                        self.step(&child, &n, Some(a), None, Outcome::Failed(not_public(a, why, "glue")), depth, &for_ns);
                    }
                    zone = child;
                    servers = next;
                    continue 'zones;
                }
                if reply.answer.is_empty() && (reply.flags.aa || reply.negative_ttl().is_some()) {
                    if !reply.flags.aa {
                        self.step(&zone, &sname, Some(ip), ms, lame("no records (NODATA)"), depth, &for_ns);
                        continue;
                    }
                    self.step(&zone, &sname, Some(ip), ms, Outcome::NoData { soa: reply.negative_ttl() }, depth, &for_ns);
                    return Ok((End::NoData, Vec::new()));
                }
                let why = if reply.authority.iter().any(|r| r.rtype == query::NS) { "a referral that does not lead down (a lame server)" } else { "neither an answer nor a referral (a lame server)" };
                self.step(&zone, &sname, Some(ip), ms, Outcome::Failed(why.into()), depth, &for_ns);
            }
            return Ok((End::Error(format!("No server of {} gave a usable answer.", text::name(&zone))), Vec::new()));
        }
    }

    /// The next servers: glued ones first (IPv4, then IPv6 when usable), then glueless names.
    /// Glue that is not a public address is left out and handed back with why (SNB4); a name
    /// whose glue is all left out is not walked either (its own zone would say the same).
    fn candidates(&self, reply: &Reply, ns: &[Labels]) -> (Vec<Candidate>, Vec<(Labels, IpAddr, &'static str)>) {
        let mut glued = Vec::new();
        let mut v6s = Vec::new();
        let mut bare = Vec::new();
        let mut skipped = Vec::new();
        for n in ns {
            let all: Vec<IpAddr> = reply
                .additional
                .iter()
                .filter(|r| query::same_name(&r.owner, n))
                .filter_map(|r| match r.data {
                    Data::A(a) => Some(IpAddr::V4(a)),
                    Data::Aaaa(a) if self.v6 => Some(IpAddr::V6(a)),
                    _ => None,
                })
                .collect();
            let mut addrs = Vec::new();
            for a in &all {
                match not_global(*a) {
                    Some(why) => skipped.push((n.clone(), *a, why)),
                    None => addrs.push(*a),
                }
            }
            let v4: Vec<IpAddr> = addrs.iter().copied().filter(IpAddr::is_ipv4).collect();
            let v6: Vec<IpAddr> = addrs.iter().copied().filter(IpAddr::is_ipv6).collect();
            if let Some(a) = v4.first() {
                glued.push((n.clone(), Some(*a)));
            }
            if let Some(a) = v6.first() {
                v6s.push((n.clone(), Some(*a)));
            }
            if all.is_empty() {
                bare.push((n.clone(), None));
            }
        }
        glued.extend(v6s);
        glued.extend(bare);
        (glued, skipped)
    }

    /// A glueless NS name's address, by its own walk from the root (depth-limited). Ok(Err) a
    /// failure of this name only; Err the whole trace stops.
    fn address_of(&mut self, ns: &Labels, depth: u8) -> Result<Result<IpAddr, String>, End> {
        if depth + 1 > MAX_DEPTH {
            return Ok(Err(format!("{} has no glue, and resolving it would go deeper than {MAX_DEPTH} levels", text::name(ns))));
        }
        let mut types = vec![query::A];
        if self.v6 {
            types.push(query::AAAA);
        }
        for t in types {
            let start = (ns.len() + t as usize) % ROOTS.len();
            let (_, records) = self.walk(ns, t, depth + 1, Some(ns.clone()), root_servers(start, self.v6))?;
            let found = records.iter().filter(|r| query::same_name(&r.owner, ns)).find_map(|r| match r.data {
                Data::A(a) => Some(IpAddr::V4(a)),
                Data::Aaaa(a) => Some(IpAddr::V6(a)),
                _ => None,
            });
            if let Some(ip) = found {
                if let Some(why) = not_global(ip) {
                    return Ok(Err(not_public(ip, why, &format!("{} resolves to", text::name(ns)))));
                }
                return Ok(Ok(ip));
            }
        }
        Ok(Err(format!("{} has no glue, and its address could not be found", text::name(ns))))
    }
}
/// Why a server address is not one the trace asks, or None for a public one (SNB4). The trace
/// starts at the public root, so every server it is sent to should be on the public internet; a
/// referral into loopback, this PC's or the LAN's own addresses or a multicast group is a
/// broken or hostile zone pointing the walk at things inside the network. Private addresses
/// (RFC 1918, CGNAT, ULA) are skipped too: to see what a private server says, ask it directly
/// with a query to that resolver, which is the user's own choice. Documentation ranges pass:
/// they lead nowhere and harm nothing.
pub fn not_global(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            if a.is_loopback() {
                Some("loopback")
            } else if a.is_unspecified() || o[0] == 0 {
                Some("unspecified")
            } else if a.is_broadcast() {
                Some("broadcast")
            } else if a.is_multicast() {
                Some("multicast")
            } else if a.is_link_local() {
                Some("link-local")
            } else if a.is_private() || (o[0] == 100 && (o[1] & 0xC0) == 64) {
                Some("private")
            } else if o[0] >= 240 {
                Some("reserved")
            } else {
                None
            }
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return not_global(IpAddr::V4(v4));
            }
            let s = a.segments();
            if a.is_loopback() {
                Some("loopback")
            } else if a.is_unspecified() {
                Some("unspecified")
            } else if a.is_multicast() {
                Some("multicast")
            } else if (s[0] & 0xFFC0) == 0xFE80 {
                Some("link-local")
            } else if (s[0] & 0xFE00) == 0xFC00 {
                Some("private")
            } else {
                None
            }
        }
    }
}

/// The step's words for a skipped server address.
fn not_public(ip: IpAddr, why: &str, what: &str) -> String {
    let a = if why.starts_with(['a', 'e', 'i', 'o', 'u']) { "an" } else { "a" };
    format!("{what} {ip}, {a} {why} address, not a public one: skipped (a trace from the root asks only public servers)")
}

/// A referral down: NS records in the authority section for a zone strictly below `zone` that
/// holds `name`. Anything else (upward, sideways, the same zone) is no referral: the loop guard.
fn referral(reply: &Reply, zone: &Labels, name: &Labels) -> Option<(Labels, Vec<Labels>)> {
    let ns: Vec<&Rr> = reply.authority.iter().filter(|r| r.rtype == query::NS).collect();
    let child = ns.first()?.owner.clone();
    if child.len() <= zone.len() || !query::is_under(&child, zone) || !query::is_under(name, &child) {
        return None;
    }
    let names: Vec<Labels> = ns
        .iter()
        .filter(|r| query::same_name(&r.owner, &child))
        .filter_map(|r| match &r.data {
            Data::Target(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    (!names.is_empty()).then_some((child, names))
}
