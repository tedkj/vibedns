//! A scripted world for the tests (and for looking at the window without a network): resolvers
//! that answer from one shared truth (validating ones set AD, sign, and refuse a bogus zone),
//! a router that does not validate, a server that never answers, one with a TLS name mismatch,
//! one that answers DoH with 404, and a Windows with a hosts file and a slow name.

use crate::ask::WinSide;
use crate::query::{self, Sent};
use crate::resolvers::Adapter;
use crate::transport::{Exchange, Net, Server};
use crate::windows::{self, HostsLine, WinAnswer};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{self, CNAME, MX, NS, NULL, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::rr::rdata::opt::EdnsOption;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

/// What the fake's records are made of.
#[derive(Clone, Debug)]
pub struct Rec {
    pub owner: String,
    pub ttl: u32,
    pub data: RData,
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap_or_else(|_| Name::root())
}

fn raw(t: u16, b: &[u8]) -> RData {
    RData::Unknown { code: RecordType::from(t), rdata: NULL::with(b.to_vec()) }
}

fn rec(owner: &str, ttl: u32, data: RData) -> Rec {
    Rec { owner: owner.into(), ttl, data }
}

/// The truth every resolver answers from: (name, type) -> records; names that do not exist.
#[derive(Clone, Debug, Default)]
pub struct Zone {
    pub records: HashMap<(String, u16), Vec<Rec>>,
    /// Names that exist (for NODATA versus NXDOMAIN).
    pub names: Vec<String>,
    /// Signed names: validating resolvers set AD and add an RRSIG.
    pub signed: Vec<String>,
    /// Names whose DNSSEC is broken: validating resolvers answer SERVFAIL (EDE 6) unless CD.
    pub bogus: Vec<String>,
}

impl Zone {
    pub fn add(&mut self, owner: &str, t: u16, ttl: u32, data: RData) {
        let o = owner.to_ascii_lowercase();
        if !self.names.contains(&o) {
            self.names.push(o.clone());
        }
        self.records.entry((o.clone(), t)).or_default().push(rec(&o, ttl, data));
    }

    /// The answer for (name, type): records (following CNAMEs) or None for NXDOMAIN.
    fn lookup(&self, qname: &str, t: u16) -> Option<Vec<Rec>> {
        let mut out = Vec::new();
        let mut n = qname.to_ascii_lowercase();
        for _ in 0..10 {
            if !self.names.contains(&n) {
                return if out.is_empty() { None } else { Some(out) };
            }
            if let Some(r) = self.records.get(&(n.clone(), t)) {
                out.extend(r.iter().cloned());
                return Some(out);
            }
            match self.records.get(&(n.clone(), query::CNAME)) {
                Some(c) if t != query::CNAME => {
                    out.extend(c.iter().cloned());
                    let RData::CNAME(CNAME(target)) = &c[0].data else { break };
                    n = target.to_ascii().to_ascii_lowercase();
                }
                _ => break,
            }
        }
        Some(out)
    }

    fn soa(&self, qname: &str) -> Rec {
        let zone = qname.split_once('.').map(|(_, z)| z).filter(|z| z.contains('.')).unwrap_or(qname);
        rec(zone, 900, RData::SOA(SOA::new(name(&format!("ns1.{zone}")), name(&format!("hostmaster.{zone}")), 2026102201, 7200, 3600, 1209600, 300)))
    }

    /// The showcase: example.com with every offered type, a CNAME, long TXT and IPv6, a name
    /// that does not exist, a bogus zone, and blocked.example (which Windows' hosts file pins).
    pub fn showcase() -> Zone {
        let mut z = Zone::default();
        z.add("example.com.", 1, 300, RData::A(rdata::A::new(93, 184, 215, 14)));
        z.add("example.com.", 28, 300, RData::AAAA(rdata::AAAA::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c)));
        z.add("example.com.", 15, 3600, RData::MX(MX::new(0, name("."))));
        z.add("example.com.", 16, 3600, RData::TXT(TXT::new(vec!["v=spf1 -all".into()])));
        z.add("example.com.", 16, 3600, RData::TXT(TXT::new(vec!["_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9".into()])));
        z.add("example.com.", 2, 86400, RData::NS(NS(name("a.iana-servers.net."))));
        z.add("example.com.", 2, 86400, RData::NS(NS(name("b.iana-servers.net."))));
        z.add("example.com.", 6, 3600, RData::SOA(SOA::new(name("ns.icann.org."), name("noc.dns.icann.org."), 2026102201, 7200, 3600, 1209600, 3600)));
        z.add("example.com.", 257, 3600, raw(257, b"\x00\x05issueletsencrypt.org"));
        z.add("example.com.", 257, 3600, raw(257, b"\x00\x0afuturetagx\"weird\""));
        z.add("example.com.", 65, 300, raw(65, &[0, 1, 0, 0, 1, 0, 6, 2, b'h', b'3', 2, b'h', b'2', 0, 4, 0, 4, 93, 184, 215, 14, 0xFD, 0xE8, 0, 2, b'h', b'i']));
        z.add("example.com.", 43, 86400, raw(43, &[0x89, 0x3B, 13, 2, 0x5A, 0x3B, 0x1F, 0x22, 0xC4, 0x7A, 0x6E, 0x10]));
        z.add("example.com.", 48, 3600, raw(48, &[1, 1, 3, 13, 0x99, 0xDB, 0x2C, 0xC1, 0x4C, 0xAB, 0xDC, 0x33, 0xD6, 0xD7, 0x7D, 0xA6, 0x3A, 0x2F, 0x15, 0xF7, 0x11, 0x12, 0x58, 0x4F, 0x23, 0x4E, 0x8D, 0x1D, 0xC4, 0x28, 0xE3, 0x9E, 0x8A, 0x4A, 0x97, 0xE1, 0xAA, 0x27, 0x1A, 0x55, 0x5D, 0xC9, 0x07, 0x01, 0xE1, 0x7E, 0x2A, 0x4C, 0x4B, 0x6F, 0x12, 0x0B, 0x7C, 0x32, 0xD4, 0x4F, 0x4A, 0xC0, 0x2B, 0xD8, 0x94, 0xCF, 0x2D, 0x4B, 0xE7, 0x77, 0x8A, 0x19]));
        z.add("www.example.com.", 5, 300, RData::CNAME(CNAME(name("example.com."))));
        z.add("_sip._tcp.example.com.", 33, 300, RData::SRV(rdata::SRV::new(10, 60, 5060, name("sip.example.com."))));
        z.add("7.2.0.192.in-addr.arpa.", 12, 300, RData::PTR(rdata::PTR(name("host.example.com."))));
        let long: Vec<String> = (0..6).map(|i| format!("long-txt-string-{i}-{}", "abcdefghijklmnopqrstuvwxyz0123456789".repeat(5))).collect();
        z.add("long.example.", 16, 300, RData::TXT(TXT::new(long)));
        z.add("long.example.", 16, 300, RData::TXT(TXT::new((0..40).map(|i| format!("s{i}")).collect())));
        for i in 1..=6u16 {
            z.add("v6.example.", 28, 300, RData::AAAA(rdata::AAAA::new(0x2001, 0xdb8, 0xfedc, 0xba98, 0x7654, 0x3210, 0xabcd, 0xef00 + i)));
        }
        z.add("blocked.example.", 1, 60, RData::A(rdata::A::new(203, 0, 113, 9)));
        z.add("bogus.example.", 1, 60, RData::A(rdata::A::new(203, 0, 113, 66)));
        z.add("slow.example.", 1, 60, RData::A(rdata::A::new(203, 0, 113, 77)));
        z.add("xn--bcher-kva.example.", 1, 60, RData::A(rdata::A::new(203, 0, 113, 12)));
        let mut chain = Vec::new();
        for i in 0..8 {
            chain.push((format!("c{i}.example."), format!("c{}.example.", i + 1)));
        }
        for (a, b) in chain {
            z.add(&a, 5, 60, RData::CNAME(CNAME(name(&b))));
        }
        z.add("c8.example.", 1, 60, RData::A(rdata::A::new(203, 0, 113, 8)));
        z.signed = vec!["example.com.".into(), "www.example.com.".into()];
        z.bogus = vec!["bogus.example.".into()];
        z
    }
}

/// How a fake server behaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Behaviour {
    /// Answers from the truth; `validating` sets AD, signs, refuses bogus zones.
    Answer { validating: bool },
    /// Never answers.
    Silent,
    /// Fails with this text (a TLS name mismatch, an HTTP 404).
    Fails(String),
    /// Answers this name with other addresses (a stale or filtered resolver).
    Differs { name: String, a: [u8; 4] },
}

/// A query the fake saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentInfo {
    pub server: SocketAddr,
    pub via: String,
    pub name: String,
    pub qtype: u16,
    pub rd: bool,
    pub cd: bool,
}

pub struct FakeNet {
    pub zone: Zone,
    pub servers: HashMap<IpAddr, Behaviour>,
    /// What answers plain DNS (UDP, TCP) to these addresses in the server's place: something
    /// on the way that intercepts port 53. DoT and DoH still reach the server.
    pub port53: HashMap<IpAddr, Behaviour>,
    pub sent: Mutex<Vec<SentInfo>>,
}

impl FakeNet {
    pub fn showcase() -> FakeNet {
        let mut servers = HashMap::new();
        for ip in ["1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111", "2001:4860:4860::8888", "2620:fe::fe"] {
            servers.insert(ip.parse().unwrap(), Behaviour::Answer { validating: true });
        }
        servers.insert("192.168.1.1".parse().unwrap(), Behaviour::Answer { validating: false });
        servers.insert("fe80::1".parse().unwrap(), Behaviour::Answer { validating: false });
        servers.insert("192.0.2.53".parse().unwrap(), Behaviour::Answer { validating: false });
        servers.insert("192.0.2.250".parse().unwrap(), Behaviour::Silent);
        servers.insert("192.0.2.251".parse().unwrap(), Behaviour::Fails("The server's certificate is not valid for dns.wrong.example (TLS name mismatch).".into()));
        servers.insert("192.0.2.252".parse().unwrap(), Behaviour::Fails("The DoH server answered HTTP 404 Not Found.".into()));
        FakeNet { zone: Zone::showcase(), servers, port53: HashMap::new(), sent: Mutex::new(Vec::new()) }
    }

    /// The answer bytes a server gives to `sent`.
    pub fn answer(&self, b: &Behaviour, sent: &Sent) -> Result<Vec<u8>, String> {
        let q = Message::from_vec(&sent.bytes).map_err(|e| e.to_string())?;
        let qn = q.queries[0].name().to_ascii().to_ascii_lowercase();
        let qt = u16::from(q.queries[0].query_type());
        let validating = matches!(b, Behaviour::Answer { validating: true });
        let cd = q.metadata.checking_disabled;
        let mut m = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
        m.metadata.recursion_desired = q.metadata.recursion_desired;
        m.metadata.recursion_available = true;
        m.metadata.checking_disabled = cd;
        m.add_queries(q.queries.clone());
        let mut e = Edns::new();
        e.set_max_payload(1232);
        e.set_dnssec_ok(true);
        if validating && !cd && self.zone.bogus.contains(&qn) {
            m.metadata.response_code = ResponseCode::ServFail;
            e.options_mut().insert(EdnsOption::Unknown(15, [&[0u8, 6][..], b"signature expired"].concat()));
            m.set_edns(e);
            return m.to_vec().map_err(|e| e.to_string());
        }
        match self.zone.lookup(&qn, qt) {
            None => {
                m.metadata.response_code = ResponseCode::NXDomain;
                let s = self.zone.soa(&qn);
                m.add_authority(Record::from_rdata(name(&s.owner), s.ttl, s.data));
            }
            Some(recs) => {
                for r in &recs {
                    let mut data = r.data.clone();
                    if let (Behaviour::Differs { name: dn, a }, RData::A(_)) = (b, &data)
                        && *dn == qn
                    {
                        data = RData::A(rdata::A::new(a[0], a[1], a[2], a[3]));
                    }
                    m.add_answer(Record::from_rdata(name(&r.owner), r.ttl, data));
                }
                if recs.is_empty() {
                    let s = self.zone.soa(&qn);
                    m.add_authority(Record::from_rdata(name(&s.owner), s.ttl, s.data));
                }
                if validating && self.zone.signed.contains(&qn) && !recs.is_empty() {
                    m.metadata.authentic_data = true;
                    let mut sig = qt.to_be_bytes().to_vec();
                    sig.extend_from_slice(&[13, 2, 0, 0, 1, 44]);
                    sig.extend_from_slice(&1_761_220_991u32.to_be_bytes());
                    sig.extend_from_slice(&1_761_134_591u32.to_be_bytes());
                    sig.extend_from_slice(&[0x86, 0xC9, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
                    sig.extend_from_slice(b"signature-bytes-here");
                    m.add_answer(Record::from_rdata(name(&qn), 300, raw(46, &sig)));
                }
            }
        }
        m.set_edns(e);
        m.to_vec().map_err(|e| e.to_string())
    }
}

impl Net for FakeNet {
    fn ask(&self, server: &Server, sent: &Sent) -> Result<Exchange, String> {
        let q = Message::from_vec(&sent.bytes).map_err(|e| e.to_string())?;
        self.sent.lock().unwrap().push(SentInfo {
            server: server.addr,
            via: server.via(),
            name: q.queries[0].name().to_ascii(),
            qtype: u16::from(q.queries[0].query_type()),
            rd: q.metadata.recursion_desired,
            cd: q.metadata.checking_disabled,
        });
        let plain = matches!(server.proto, crate::transport::Proto::Udp | crate::transport::Proto::Tcp);
        let on_the_way = if plain { self.port53.get(&server.addr.ip()) } else { None };
        let b = on_the_way.or_else(|| self.servers.get(&server.addr.ip())).cloned().unwrap_or(Behaviour::Silent);
        match &b {
            Behaviour::Silent => Err(format!("No answer from {} over {} in 2 s (2 tries).", server.addr, server.proto.name())),
            Behaviour::Fails(e) => Err(e.clone()),
            _ => {
                let reply = self.answer(&b, sent)?;
                let plain = server.proto == crate::transport::Proto::Udp;
                Ok(Exchange { reply, rtt: Duration::from_micros(if plain { 8_400 } else { 23_000 }), setup: (!plain).then(|| Duration::from_millis(31)), via: server.via(), ignored: 0, reused: false })
            }
        }
    }
}

/// A Windows with one Wi-Fi adapter (the router at 192.168.1.1), a hosts file that pins
/// blocked.example, a name that times out, and one custom host name it can resolve.
pub struct FakeWin {
    pub zone: Zone,
    pub adapters: Mutex<Result<Vec<Adapter>, String>>,
    pub hosts: Vec<HostsLine>,
    pub flushed: Mutex<usize>,
    pub asked: Mutex<Vec<String>>,
    pub resolved: Mutex<Vec<String>>,
    /// While set, every Windows query answers this status (a cache that went bad, a test).
    pub status: Mutex<Option<u32>>,
}

impl FakeWin {
    pub fn showcase() -> FakeWin {
        let wifi = Adapter { index: 12, name: "Wi-Fi".into(), guid: "{6B29FC40-CA47-1067-B31D-00DD010662DA}".into(), dns: vec!["192.168.1.1:53".parse().unwrap()], suffix: "lan".into(), global_v6: true };
        let hosts = windows::parse_hosts("# hosts\n127.0.0.1 localhost\n0.0.0.0 blocked.example # ad blocker\n");
        FakeWin { zone: Zone::showcase(), adapters: Mutex::new(Ok(vec![wifi])), hosts, flushed: Mutex::new(0), asked: Mutex::new(Vec::new()), resolved: Mutex::new(Vec::new()), status: Mutex::new(None) }
    }
}

fn to_rr(r: &Rec) -> Option<query::Rr> {
    // Through the same parser as everything else: encode the one record and read it back.
    let mut m = Message::new(0, MessageType::Response, OpCode::Query);
    m.add_answer(Record::from_rdata(name(&r.owner), r.ttl, r.data.clone()));
    let b = m.to_vec().ok()?;
    query::parse(&b).ok()?.answer.into_iter().next()
}

impl WinSide for FakeWin {
    fn adapters(&self) -> Result<Vec<Adapter>, String> {
        self.adapters.lock().unwrap().clone()
    }

    fn query(&self, qname: &str, qtype: u16) -> WinAnswer {
        self.asked.lock().unwrap().push(format!("{qname} {qtype}"));
        if let Some(s) = *self.status.lock().unwrap() {
            return WinAnswer { status: s, ..WinAnswer::default() };
        }
        let n = format!("{}.", qname.trim_end_matches('.').to_ascii_lowercase());
        if n == "slow.example." {
            return WinAnswer { status: 1460, ..WinAnswer::default() };
        }
        let hit: Vec<&HostsLine> = windows::hosts_match(&self.hosts, &n, qtype, None);
        if let Some(h) = hit.first() {
            let IpAddr::V4(v4) = h.ip else { return WinAnswer { status: 9501, ..WinAnswer::default() } };
            let rr = to_rr(&rec(&n, 0, RData::A(rdata::A(v4))));
            return WinAnswer { status: 0, answer: rr.into_iter().collect(), ..WinAnswer::default() };
        }
        match self.zone.lookup(&n, qtype) {
            None => WinAnswer { status: 9003, ..WinAnswer::default() },
            Some(recs) if recs.is_empty() => WinAnswer { status: 9501, ..WinAnswer::default() },
            Some(recs) => WinAnswer { status: 0, answer: recs.iter().filter_map(to_rr).map(|mut r| {
                r.ttl = r.ttl.saturating_sub(17); // cache-decremented
                r
            }).collect(), ..WinAnswer::default() },
        }
    }

    fn flush(&self) -> Result<(), String> {
        *self.flushed.lock().unwrap() += 1;
        Ok(())
    }

    fn context(&self, _: &[Adapter]) -> windows::Context {
        windows::Context { hosts: Ok(Some(("C:\\Windows\\System32\\drivers\\etc\\hosts".into(), self.hosts.clone()))), nrpt: Ok(Vec::new()), doh: Ok(Vec::new()), suffixes: vec!["lan".into()] }
    }

    fn resolve(&self, host: &str) -> Result<IpAddr, String> {
        self.resolved.lock().unwrap().push(host.to_string());
        match host {
            "resolver.example" => Ok("192.0.2.53".parse().unwrap()),
            _ => Err(format!("“{host}” could not be resolved by Windows: no such host.")),
        }
    }

    fn now_text(&self) -> String {
        "2026-10-22 14:03:11".into()
    }
}
