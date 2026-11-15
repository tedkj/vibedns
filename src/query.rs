//! One DNS question and its answer: what the user typed as a question (IDN to A-labels, an
//! address to its PTR name), the query on the wire (hickory-proto builds it: random ID, RD,
//! EDNS0 with 1232 bytes and DO=1, CD on demand), whether a reply belongs to it, and the reply
//! read by this module's own parser into dig's presentation.
//!
//! The parser is our own (DECISIONS.md): it never gives up a whole answer for one record it
//! cannot read (that record is shown in RFC 3597's `\# len hex` form), and it is strict where
//! the wire can lie: compression pointers only point backwards, labels are at most 63 bytes,
//! names at most 255, and every RDATA is read to its exact length.

use crate::text;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The types the window offers, in its order. One per query; no ANY (RFC 8482).
pub const QTYPES: [(&str, u16); 14] = [
    ("A", 1),
    ("AAAA", 28),
    ("CNAME", 5),
    ("MX", 15),
    ("TXT", 16),
    ("NS", 2),
    ("SOA", 6),
    ("SRV", 33),
    ("PTR", 12),
    ("CAA", 257),
    ("HTTPS", 65),
    ("SVCB", 64),
    ("DS", 43),
    ("DNSKEY", 48),
];

pub const PTR: u16 = 12;
pub const MX: u16 = 15;
pub const TXT: u16 = 16;
pub const DNSKEY: u16 = 48;
pub const HTTPS: u16 = 65;
pub const CAA_TYPE: u16 = 257;
pub const CNAME: u16 = 5;
pub const SOA: u16 = 6;
pub const NS: u16 = 2;
pub const A: u16 = 1;
pub const AAAA: u16 = 28;
pub const DS: u16 = 43;
pub const OPT: u16 = 41;
pub const RRSIG: u16 = 46;
pub const NSEC: u16 = 47;
pub const NSEC3: u16 = 50;
pub const DNAME: u16 = 39;

/// The EDNS0 UDP payload size every query offers (DNS flag day 2020).
pub const UDP_PAYLOAD: u16 = 1232;

pub type Labels = Vec<Vec<u8>>;

/// The question as it goes out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// The name on the wire (A-labels, case as typed; the root is empty).
    pub labels: Labels,
    pub qtype: u16,
    /// What was asked, trimmed (the field and the history keep it).
    pub typed: String,
    /// The name as typed when it was not ASCII ("bücher.example"), shown beside the A-labels.
    pub unicode: Option<String>,
    /// An address turned into its PTR name.
    pub ptr_of: Option<IpAddr>,
    /// One label, no trailing dot: sent as typed; Windows would add its search suffixes.
    pub single_label: bool,
    /// The user wrote the trailing dot (Windows then asks the name as it is, no suffixes).
    pub absolute: bool,
}

impl Question {
    /// dig's form: "xn--bcher-kva.example."
    pub fn name_text(&self) -> String {
        text::name(&self.labels)
    }

    /// What Windows is asked (DnsQueryEx takes text, as apps hand it): the A-label form without
    /// the trailing dot unless the user wrote one, so search suffixes apply exactly as for an
    /// app. None for a name Windows' text interface cannot carry (a label with a dot, a space or
    /// a byte outside printable ASCII).
    pub fn windows_name(&self) -> Option<String> {
        if self.labels.is_empty() {
            return Some(".".into());
        }
        let mut parts = Vec::new();
        for l in &self.labels {
            if l.iter().any(|b| !(0x21..=0x7E).contains(b) || *b == b'.' || *b == b'\\') {
                return None;
            }
            parts.push(String::from_utf8_lossy(l).to_string());
        }
        let mut s = parts.join(".");
        if self.absolute {
            s.push('.');
        }
        Some(s)
    }

    pub fn type_text(&self) -> String {
        text::type_name(self.qtype)
    }
}

/// The question from what the user typed (or the command line named): a name, an IP literal
/// (its PTR name, type PTR), a pasted URL (its host), `.` for the root. IDN labels become
/// A-labels (UTS 46, as hickory-proto does it); dig's escapes (`\.`, `\\`, `\DDD`) work.
pub fn parse_input(input: &str, qtype: u16) -> Result<Question, String> {
    let mut s = input.trim();
    if s.len() >= 2 && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))) {
        s = s[1..s.len() - 1].trim();
    }
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
        if let Some(i) = s.find(['/', '?', '#']) {
            s = &s[..i];
        }
        if let Some(i) = s.rfind('@') {
            s = &s[i + 1..];
        }
        if let Some(rest) = s.strip_prefix('[') {
            s = rest.split(']').next().unwrap_or("");
        } else if s.matches(':').count() == 1 {
            s = s.split(':').next().unwrap_or("");
        }
    }
    let s = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(s);
    if s.is_empty() {
        return Err("Type a name (example.com) or an address to look up.".into());
    }
    if s.chars().any(|c| c.is_whitespace() || text::invisible(c)) {
        return Err(format!("“{}” is not a name or an address (it has spaces or invisible characters in it).", text::clean(s, 120)));
    }
    let bare = s.split('%').next().unwrap_or(s); // fe80::1%12: the zone is not part of the name
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(Question { labels: ptr_labels(ip), qtype: PTR, typed: s.to_string(), unicode: None, ptr_of: Some(ip), single_label: false, absolute: true });
    }
    if s == "." {
        return Ok(Question { labels: Vec::new(), qtype, typed: ".".into(), unicode: None, ptr_of: None, single_label: false, absolute: true });
    }
    let absolute = s.ends_with('.') && !s.ends_with("\\.");
    let body = if absolute { &s[..s.len() - 1] } else { s };
    let raw = split_labels(body)?;
    let mut labels = Vec::with_capacity(raw.len());
    let mut idn = false;
    for (l, typed_unicode) in raw {
        // Bytes written as escapes (\226) are bytes; only text typed as Unicode goes to IDNA.
        if !typed_unicode {
            labels.push(l);
        } else {
            let u = String::from_utf8(l).map_err(|_| "That name is not valid text.".to_string())?;
            let a = hickory_proto::rr::domain::Label::from_utf8(&u).map_err(|_| format!("“{}” is not a valid international (IDN) label.", text::clean(&u, 80)))?;
            idn = true;
            labels.push(a.as_bytes().to_vec());
        }
    }
    for l in &labels {
        if l.len() > 63 {
            return Err(format!("A label can be at most 63 bytes; “{}” is {}.", text::clean(&text::label(l), 40), l.len()));
        }
    }
    let wire: usize = labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1;
    if wire > 255 {
        return Err(format!("A name can be at most 255 bytes on the wire; this one is {wire}."));
    }
    let single_label = labels.len() == 1 && !absolute;
    Ok(Question { labels, qtype, typed: s.to_string(), unicode: idn.then(|| s.trim_end_matches('.').to_string()), ptr_of: None, single_label, absolute })
}

/// Labels split at unescaped dots, dig's escapes undone: `\.` a dot inside a label, `\\` a
/// backslash, `\DDD` any byte. Each label says whether it had characters typed as Unicode.
fn split_labels(s: &str) -> Result<Vec<(Vec<u8>, bool)>, String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut unicode = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                let d: Vec<u8> = b[i + 1..].iter().take(3).copied().collect();
                if d.len() == 3 && d.iter().all(u8::is_ascii_digit) {
                    let v = (d[0] - b'0') as u32 * 100 + (d[1] - b'0') as u32 * 10 + (d[2] - b'0') as u32;
                    if v > 255 {
                        return Err(format!("\\{} is not a byte (000 to 255).", String::from_utf8_lossy(&d)));
                    }
                    cur.push(v as u8);
                    i += 4;
                } else if let Some(&c) = b.get(i + 1) {
                    cur.push(c);
                    i += 2;
                } else {
                    return Err("The name ends in a lone backslash.".into());
                }
            }
            b'.' => {
                if cur.is_empty() {
                    return Err("The name has an empty label (two dots in a row, or a dot at the start).".into());
                }
                out.push((std::mem::take(&mut cur), std::mem::take(&mut unicode)));
                i += 1;
            }
            c => {
                unicode |= c >= 0x80;
                cur.push(c);
                i += 1;
            }
        }
    }
    if cur.is_empty() {
        return Err("The name has an empty label (two dots in a row, or a dot at the start).".into());
    }
    out.push((cur, unicode));
    Ok(out)
}

/// An address's reverse name: "4.3.2.1.in-addr.arpa", or its 32 nibbles under "ip6.arpa".
pub fn ptr_labels(ip: IpAddr) -> Labels {
    let mut v: Labels = Vec::new();
    match ip {
        IpAddr::V4(a) => {
            for o in a.octets().iter().rev() {
                v.push(o.to_string().into_bytes());
            }
            v.push(b"in-addr".to_vec());
        }
        IpAddr::V6(a) => {
            for o in a.octets().iter().rev() {
                v.push(format!("{:x}", o & 0xf).into_bytes());
                v.push(format!("{:x}", o >> 4).into_bytes());
            }
            v.push(b"ip6".to_vec());
        }
    }
    v.push(b"arpa".to_vec());
    v
}

/// A fresh, random message ID (the system's preferred RNG).
pub fn random_id() -> u16 {
    u16::from_be_bytes(random_bytes::<2>())
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
    let mut b = [0u8; N];
    // SAFETY: a buffer of N bytes; no algorithm handle with the system-preferred flag.
    let r = unsafe { BCryptGenRandom(std::ptr::null_mut(), b.as_mut_ptr(), N as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if r != 0 {
        // Never seen; a clock-derived value still differs per query.
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(7);
        for (i, x) in b.iter_mut().enumerate() {
            *x = (t >> ((i % 8) * 8)) as u8 ^ (i as u8).wrapping_mul(151);
        }
    }
    b
}

/// A query as it goes out, with what its answer must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub id: u16,
    pub labels: Labels,
    pub qtype: u16,
    pub bytes: Vec<u8>,
}

/// The query: `id`, RD as asked, CD as asked, EDNS0 (1232 bytes, version 0, DO=1), no ECS.
pub fn build(labels: &Labels, qtype: u16, id: u16, rd: bool, cd: bool) -> Sent {
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    let name = Name::from_labels(labels.iter().map(|l| l.as_slice())).unwrap_or_else(|_| Name::root());
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = rd;
    m.metadata.checking_disabled = cd;
    m.add_query(Query::query(name, RecordType::from(qtype)));
    let mut e = Edns::new();
    e.set_max_payload(UDP_PAYLOAD);
    e.set_version(0);
    e.set_dnssec_ok(true);
    m.set_edns(e);
    let bytes = m.to_vec().unwrap_or_default();
    Sent { id, labels: labels.clone(), qtype, bytes }
}

impl Sent {
    /// The same query with another ID (DoH GET uses 0, RFC 8484 section 4.1).
    pub fn with_id(&self, id: u16) -> Sent {
        let mut s = self.clone();
        s.id = id;
        if s.bytes.len() >= 2 {
            s.bytes[..2].copy_from_slice(&id.to_be_bytes());
        }
        s
    }
}

/// Why a reply is not the answer to a query (it is ignored and counted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    TooShort,
    NotAResponse,
    WrongId,
    WrongQuestion,
}

/// Whether `reply` answers `sent`: a response, the same ID, and the same question (name without
/// regard to ASCII case, type, class IN). An error reply that dropped its question (FORMERR,
/// NOTIMP, REFUSED from some servers) is taken on its ID alone: waiting it out would turn the
/// server's "no" into a timeout (DECISIONS.md).
pub fn check(sent: &Sent, reply: &[u8]) -> Result<(), Mismatch> {
    if reply.len() < 12 {
        return Err(Mismatch::TooShort);
    }
    if reply[2] & 0x80 == 0 {
        return Err(Mismatch::NotAResponse);
    }
    if u16::from_be_bytes([reply[0], reply[1]]) != sent.id {
        return Err(Mismatch::WrongId);
    }
    let qd = u16::from_be_bytes([reply[4], reply[5]]);
    let rcode = reply[3] & 0x0f;
    if qd == 0 && rcode != 0 {
        return Ok(());
    }
    if qd != 1 {
        return Err(Mismatch::WrongQuestion);
    }
    let Ok((name, end)) = read_name(reply, 12) else { return Err(Mismatch::WrongQuestion) };
    if end + 4 > reply.len() {
        return Err(Mismatch::WrongQuestion);
    }
    let qt = u16::from_be_bytes([reply[end], reply[end + 1]]);
    let qc = u16::from_be_bytes([reply[end + 2], reply[end + 3]]);
    if qt != sent.qtype || qc != 1 || !same_name(&name, &sent.labels) {
        return Err(Mismatch::WrongQuestion);
    }
    Ok(())
}

/// Names equal without regard to ASCII case (RFC 4343).
pub fn same_name(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// `child` is `parent` or below it.
pub fn is_under(child: &[Vec<u8>], parent: &[Vec<u8>]) -> bool {
    child.len() >= parent.len() && same_name(&child[child.len() - parent.len()..], parent)
}

pub fn lower(labels: &[Vec<u8>]) -> Labels {
    labels.iter().map(|l| l.to_ascii_lowercase()).collect()
}

/// The header's TC bit (read before anything else: a cut-off answer may not parse at all).
pub fn truncated(reply: &[u8]) -> bool {
    reply.len() >= 3 && reply[2] & 0x02 != 0
}

// ---------- the reply ----------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub qr: bool,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
}

impl Flags {
    /// dig's flags line: "qr rd ra ad".
    pub fn text(&self) -> String {
        [(self.qr, "qr"), (self.aa, "aa"), (self.tc, "tc"), (self.rd, "rd"), (self.ra, "ra"), (self.ad, "ad"), (self.cd, "cd")]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, n)| *n)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What a record holds, where the app needs more than its text (trace, compare, negative TTL).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// NS, CNAME, PTR, DNAME: the name it points to.
    Target(Labels),
    Soa { minimum: u32 },
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rr {
    pub owner: Labels,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Data,
    /// The RDATA in dig's presentation.
    pub text: String,
    /// The RDATA in a canonical form (names uncompressed and lower case): what comparisons use.
    pub canon: Vec<u8>,
    /// The RDATA could not be read as its type: `text` is RFC 3597's `\# len hex`.
    pub undecoded: bool,
}

impl Rr {
    /// dig's line: "example.com.\t300\tIN\tA\t93.184.216.34".
    pub fn line(&self) -> String {
        format!("{}\t{}\t{}\t{}\t{}", text::name(&self.owner), self.ttl, text::class_name(self.class), text::type_name(self.rtype), self.text)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Edns {
    pub udp: u16,
    pub version: u8,
    pub dnssec_ok: bool,
    /// Extended DNS Errors (RFC 8914): code and the server's text (cleaned).
    pub ede: Vec<(u16, String)>,
    /// NSID (RFC 5001), as text when printable, else hex.
    pub nsid: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    pub id: u16,
    pub opcode: u8,
    pub flags: Flags,
    /// With the OPT record's upper bits (extended RCODE).
    pub rcode: u16,
    pub question: Vec<(Labels, u16, u16)>,
    pub answer: Vec<Rr>,
    pub authority: Vec<Rr>,
    /// Without the OPT record (that is `edns`).
    pub additional: Vec<Rr>,
    pub edns: Option<Edns>,
    pub size: usize,
}

impl Reply {
    pub fn rcode_text(&self) -> String {
        text::rcode_name(self.rcode)
    }

    /// NOERROR with no record of the asked type (or a CNAME to it) for the name: NODATA.
    pub fn nodata(&self) -> bool {
        self.rcode == 0 && self.answer.iter().all(|r| r.rtype == RRSIG)
    }

    /// The SOA in the authority section and its negative TTL (RFC 2308: the smaller of the
    /// SOA's own TTL and its MINIMUM).
    pub fn negative_ttl(&self) -> Option<u32> {
        self.authority.iter().find_map(|r| match r.data {
            Data::Soa { minimum } => Some(r.ttl.min(minimum)),
            _ => None,
        })
    }

    /// RRSIG records in any section (DO=1 asked for them).
    pub fn signed(&self) -> bool {
        self.answer.iter().chain(&self.authority).any(|r| r.rtype == RRSIG)
    }
}

/// A name at `pos`: its labels and where the bytes after it start. Pointers must point strictly
/// backwards (no loops, no pointers past the end), labels are 1..63 bytes (the 01 and 10 label
/// types are refused), and the whole name is at most 255 bytes on the wire.
pub fn read_name(msg: &[u8], mut pos: usize) -> Result<(Labels, usize), String> {
    let mut labels = Vec::new();
    let mut end: Option<usize> = None;
    let mut wire = 1usize;
    // Every jump goes to a smaller offset than the pointer it came from: no loop can last.
    let mut limit = pos;
    loop {
        let len = *msg.get(pos).ok_or("a name runs past the end of the message")? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Ok((labels, end.unwrap_or(pos + 1)));
                }
                let l = (pos + 1).checked_add(len).and_then(|e| msg.get(pos + 1..e)).ok_or("a label runs past the end of the message")?;
                wire += len + 1;
                if wire > 255 {
                    return Err("a name is longer than 255 bytes".into());
                }
                labels.push(l.to_vec());
                pos += 1 + len;
            }
            0xC0 => {
                let lo = *msg.get(pos + 1).ok_or("a compression pointer runs past the end of the message")? as usize;
                let target = (len & 0x3F) << 8 | lo;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                if target >= limit || target >= msg.len() {
                    return Err("a compression pointer points forward or past the end (a loop)".into());
                }
                limit = target;
                pos = target;
            }
            _ => return Err(format!("a label of unknown type 0x{:02X}", len & 0xC0)),
        }
    }
}

struct Cur<'a> {
    msg: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn u8(&mut self) -> Result<u8, String> {
        let v = *self.msg.get(self.pos).ok_or("the message ends early")?;
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes([self.u8()?, self.u8()?, self.u8()?, self.u8()?]))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let s = self.pos.checked_add(n).and_then(|e| self.msg.get(self.pos..e)).ok_or("the message ends early")?;
        self.pos += n;
        Ok(s)
    }
    fn name(&mut self) -> Result<Labels, String> {
        let (l, end) = read_name(self.msg, self.pos)?;
        self.pos = end;
        Ok(l)
    }
}

/// Read a whole reply. A broken structure (a cut-off header or record, a looping name) is an
/// error; one record whose RDATA cannot be read as its type is kept in `\#` form.
pub fn parse(msg: &[u8]) -> Result<Reply, String> {
    if msg.len() < 12 {
        return Err(format!("the answer is {} bytes, shorter than a DNS header", msg.len()));
    }
    let mut c = Cur { msg, pos: 0 };
    let id = c.u16()?;
    let b2 = c.u8()?;
    let b3 = c.u8()?;
    let counts = [c.u16()?, c.u16()?, c.u16()?, c.u16()?];
    let flags = Flags { qr: b2 & 0x80 != 0, aa: b2 & 0x04 != 0, tc: b2 & 0x02 != 0, rd: b2 & 0x01 != 0, ra: b3 & 0x80 != 0, ad: b3 & 0x20 != 0, cd: b3 & 0x10 != 0 };
    let mut r = Reply { id, opcode: (b2 >> 3) & 0x0f, flags, rcode: (b3 & 0x0f) as u16, size: msg.len(), ..Reply::default() };
    for _ in 0..counts[0] {
        let n = c.name().map_err(|e| format!("the question is broken: {e}"))?;
        let t = c.u16()?;
        let cl = c.u16()?;
        r.question.push((n, t, cl));
    }
    let mut opt_seen = false;
    for (section, &n) in counts[1..].iter().enumerate() {
        for i in 0..n {
            let rr = read_rr(&mut c).map_err(|e| format!("record {} of the {} section is broken: {e}", i + 1, ["answer", "authority", "additional"][section]))?;
            match rr {
                Read::Opt { udp, ext_rcode, version, dnssec_ok, options } if section == 2 && !opt_seen => {
                    opt_seen = true;
                    r.rcode |= (ext_rcode as u16) << 4;
                    r.edns = Some(edns_from(udp, version, dnssec_ok, options));
                }
                Read::Opt { .. } => {} // a second OPT, or one outside additional: not EDNS
                Read::Rr(rr) => match section {
                    0 => r.answer.push(rr),
                    1 => r.authority.push(rr),
                    _ => r.additional.push(rr),
                },
            }
        }
    }
    Ok(r)
}

enum Read {
    Rr(Rr),
    Opt { udp: u16, ext_rcode: u8, version: u8, dnssec_ok: bool, options: Vec<u8> },
}

fn read_rr(c: &mut Cur) -> Result<Read, String> {
    let owner = c.name()?;
    let rtype = c.u16()?;
    let class = c.u16()?;
    let ttl = c.u32()?;
    let len = c.u16()? as usize;
    let start = c.pos;
    if len > c.msg.len().saturating_sub(start) {
        return Err(format!("its data ({len} bytes) runs past the end of the message"));
    }
    c.pos = start + len;
    if rtype == OPT {
        return Ok(Read::Opt { udp: class, ext_rcode: (ttl >> 24) as u8, version: (ttl >> 16) as u8, dnssec_ok: ttl & 0x8000 != 0, options: c.msg[start..start + len].to_vec() });
    }
    let (data, text, canon, undecoded) = match rdata(c.msg, start, len, rtype) {
        Ok((d, t, can)) => (d, t, can, false),
        Err(_) => {
            let raw = &c.msg[start..start + len];
            (Data::Other, generic(raw), raw.to_vec(), true)
        }
    };
    Ok(Read::Rr(Rr { owner, rtype, class, ttl: ttl & 0x7fff_ffff, data, text, canon, undecoded }))
}

fn edns_from(udp: u16, version: u8, dnssec_ok: bool, opts: Vec<u8>) -> Edns {
    let mut e = Edns { udp, version, dnssec_ok, ..Edns::default() };
    let mut i = 0;
    while i + 4 <= opts.len() {
        let code = u16::from_be_bytes([opts[i], opts[i + 1]]);
        let len = u16::from_be_bytes([opts[i + 2], opts[i + 3]]) as usize;
        let Some(v) = (i + 4).checked_add(len).and_then(|e| opts.get(i + 4..e)) else { break };
        match code {
            15 if len >= 2 => e.ede.push((u16::from_be_bytes([v[0], v[1]]), text::clean(&String::from_utf8_lossy(&v[2..]), 200))),
            3 => e.nsid = Some(if v.iter().all(|b| (0x20..0x7F).contains(b)) { String::from_utf8_lossy(v).to_string() } else { text::hex_lower(v) }),
            _ => {}
        }
        i += 4 + len;
    }
    e
}

/// RFC 3597's generic form: `\# 4 0A000001`.
pub fn generic(raw: &[u8]) -> String {
    if raw.is_empty() { "\\# 0".into() } else { format!("\\# {} {}", raw.len(), text::hex_upper(raw)) }
}

fn canon_name(out: &mut Vec<u8>, labels: &[Vec<u8>]) {
    for l in labels {
        out.push(l.len() as u8);
        out.extend(l.iter().map(u8::to_ascii_lowercase));
    }
    out.push(0);
}

/// The RDATA at `start..start+len` of type `t`: what it holds, its text and its canonical form.
/// Any length that does not add up exactly is an error (the caller falls back to `\#`).
pub fn rdata(msg: &[u8], start: usize, len: usize, t: u16) -> Result<(Data, String, Vec<u8>), String> {
    let end = start.checked_add(len).ok_or("past the end")?;
    let raw = msg.get(start..end).ok_or("past the end")?;
    let mut c = Cur { msg: &msg[..end], pos: start };
    let mut canon = Vec::new();
    let (data, text) = match t {
        1 => {
            let a: [u8; 4] = raw.try_into().map_err(|_| "an A record is 4 bytes")?;
            canon.extend_from_slice(raw);
            c.pos = end;
            (Data::A(Ipv4Addr::from(a)), Ipv4Addr::from(a).to_string())
        }
        28 => {
            let a: [u8; 16] = raw.try_into().map_err(|_| "an AAAA record is 16 bytes")?;
            canon.extend_from_slice(raw);
            c.pos = end;
            (Data::Aaaa(Ipv6Addr::from(a)), Ipv6Addr::from(a).to_string())
        }
        2 | 5 | 12 | 39 => {
            let n = c.name()?;
            canon_name(&mut canon, &n);
            let t = text::name(&n);
            (Data::Target(n), t)
        }
        15 => {
            let pref = c.u16()?;
            let n = c.name()?;
            canon.extend_from_slice(&pref.to_be_bytes());
            canon_name(&mut canon, &n);
            (Data::Other, format!("{pref} {}", text::name(&n)))
        }
        16 | 99 => {
            if raw.is_empty() {
                return Err("a TXT record holds at least one string".into());
            }
            let mut parts = Vec::new();
            while c.pos < end {
                let l = c.u8()? as usize;
                parts.push(text::char_string(c.take(l)?));
            }
            canon.extend_from_slice(raw);
            (Data::Other, parts.join(" "))
        }
        6 => {
            let m = c.name()?;
            let r = c.name()?;
            let v = [c.u32()?, c.u32()?, c.u32()?, c.u32()?, c.u32()?];
            canon_name(&mut canon, &m);
            canon_name(&mut canon, &r);
            for x in v {
                canon.extend_from_slice(&x.to_be_bytes());
            }
            (Data::Soa { minimum: v[4] }, format!("{} {} {} {} {} {} {}", text::name(&m), text::name(&r), v[0], v[1], v[2], v[3], v[4]))
        }
        33 => {
            let (p, w, port) = (c.u16()?, c.u16()?, c.u16()?);
            let n = c.name()?;
            canon.extend_from_slice(&raw[..6]);
            canon_name(&mut canon, &n);
            (Data::Other, format!("{p} {w} {port} {}", text::name(&n)))
        }
        257 => {
            let flags = c.u8()?;
            let tl = c.u8()? as usize;
            if tl == 0 {
                return Err("a CAA tag is at least one byte".into());
            }
            let tag = c.take(tl)?;
            let value = c.take(end - c.pos)?;
            canon.extend_from_slice(raw);
            (Data::Other, format!("{flags} {} {}", text::label(tag), text::char_string(value)))
        }
        64 | 65 => {
            let prio = c.u16()?;
            let target = c.name()?;
            canon.extend_from_slice(&prio.to_be_bytes());
            canon_name(&mut canon, &target);
            let mut s = format!("{prio} {}", text::name(&target));
            let mut last: Option<u16> = None;
            while c.pos < end {
                let key = c.u16()?;
                let vl = c.u16()? as usize;
                let v = c.take(vl)?;
                if last.is_some_and(|l| key <= l) {
                    return Err("SVCB keys must come in increasing order".into());
                }
                last = Some(key);
                s.push(' ');
                s.push_str(&svc_param(key, v)?);
                canon.extend_from_slice(&key.to_be_bytes());
                canon.extend_from_slice(&(vl as u16).to_be_bytes());
                canon.extend_from_slice(v);
            }
            (Data::Other, s)
        }
        43 | 59 => {
            let (tag, alg, dt) = (c.u16()?, c.u8()?, c.u8()?);
            let d = c.take(end - c.pos)?;
            canon.extend_from_slice(raw);
            (Data::Other, format!("{tag} {alg} {dt} {}", text::hex_upper(d)))
        }
        48 | 60 => {
            let (fl, proto, alg) = (c.u16()?, c.u8()?, c.u8()?);
            let k = c.take(end - c.pos)?;
            canon.extend_from_slice(raw);
            (Data::Other, format!("{fl} {proto} {alg} {}", text::base64(k)))
        }
        46 => {
            let covered = c.u16()?;
            let (alg, labels) = (c.u8()?, c.u8()?);
            let (ottl, exp, inc) = (c.u32()?, c.u32()?, c.u32()?);
            let tag = c.u16()?;
            let signer = c.name()?;
            let sig = c.take(end - c.pos)?;
            canon.extend_from_slice(&raw[..18]);
            canon_name(&mut canon, &signer);
            canon.extend_from_slice(sig);
            (
                Data::Other,
                format!("{} {alg} {labels} {ottl} {} {} {tag} {} {}", text::type_name(covered), text::utc_stamp(exp as u64), text::utc_stamp(inc as u64), text::name(&signer), text::base64(sig)),
            )
        }
        47 => {
            let next = c.name()?;
            let bitmap = c.take(end - c.pos)?;
            let types = type_bitmap(bitmap)?;
            canon_name(&mut canon, &next);
            canon.extend_from_slice(bitmap);
            (Data::Other, format!("{} {}", text::name(&next), types))
        }
        50 => {
            let (alg, fl) = (c.u8()?, c.u8()?);
            let it = c.u16()?;
            let sl = c.u8()? as usize;
            let salt = c.take(sl)?;
            let hl = c.u8()? as usize;
            let hash = c.take(hl)?;
            let types = type_bitmap(c.take(end - c.pos)?)?;
            canon.extend_from_slice(raw);
            let salt = if salt.is_empty() { "-".to_string() } else { text::hex_upper(salt) };
            (Data::Other, format!("{alg} {fl} {it} {salt} {} {types}", text::base32hex(hash)))
        }
        51 => {
            let (alg, fl) = (c.u8()?, c.u8()?);
            let it = c.u16()?;
            let sl = c.u8()? as usize;
            let salt = c.take(sl)?;
            canon.extend_from_slice(raw);
            let salt = if salt.is_empty() { "-".to_string() } else { text::hex_upper(salt) };
            (Data::Other, format!("{alg} {fl} {it} {salt}"))
        }
        _ => return Err("not a type this app reads".into()),
    };
    if c.pos != end {
        return Err(format!("{} bytes left over", end.saturating_sub(c.pos)));
    }
    Ok((data, text, canon))
}

/// The types `rdata` reads (the rest are shown in RFC 3597 form).
pub fn reads(t: u16) -> bool {
    matches!(t, 1 | 2 | 5 | 6 | 12 | 15 | 16 | 28 | 33 | 39 | 43 | 46 | 47 | 48 | 50 | 51 | 59 | 60 | 64 | 65 | 99 | 257)
}

/// NSEC/NSEC3 type bitmaps (RFC 4034 section 4.1.2): "A NS SOA RRSIG".
fn type_bitmap(b: &[u8]) -> Result<String, String> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut last_block: Option<u8> = None;
    while i < b.len() {
        let block = b[i];
        let len = *b.get(i + 1).ok_or("a type bitmap is cut off")? as usize;
        if len == 0 || len > 32 || last_block.is_some_and(|l| block <= l) {
            return Err("a type bitmap is malformed".into());
        }
        last_block = Some(block);
        let bits = (i + 2).checked_add(len).and_then(|e| b.get(i + 2..e)).ok_or("a type bitmap is cut off")?;
        for (j, byte) in bits.iter().enumerate() {
            for k in 0..8 {
                if byte & (0x80 >> k) != 0 {
                    out.push(text::type_name(block as u16 * 256 + (j * 8 + k) as u16));
                }
            }
        }
        i += 2 + len;
    }
    Ok(out.join(" "))
}

/// One SvcParam in RFC 9460's presentation: `alpn="h3,h2"`, `port=443`, `key65000="…"`.
fn svc_param(key: u16, v: &[u8]) -> Result<String, String> {
    let name = match key {
        0 => "mandatory",
        1 => "alpn",
        2 => "no-default-alpn",
        3 => "port",
        4 => "ipv4hint",
        5 => "ech",
        6 => "ipv6hint",
        7 => "dohpath",
        _ => "",
    };
    let generic = |k: u16| if v.is_empty() { format!("key{k}") } else { format!("key{k}={}", text::char_string(v)) };
    Ok(match key {
        0 => {
            if v.is_empty() || !v.len().is_multiple_of(2) {
                return Err("mandatory is a list of keys".into());
            }
            let keys: Vec<String> = v.chunks(2).map(|k| svc_key_name(u16::from_be_bytes([k[0], k[1]]))).collect();
            format!("{name}={}", keys.join(","))
        }
        1 => {
            let mut ids = Vec::new();
            let mut i = 0;
            while i < v.len() {
                let l = v[i] as usize;
                let id = (i + 1).checked_add(l).and_then(|e| v.get(i + 1..e)).filter(|s| !s.is_empty()).ok_or("an alpn id is cut off or empty")?;
                let s = text::char_string(id);
                ids.push(s[1..s.len() - 1].replace(',', "\\,"));
                i += 1 + l;
            }
            if ids.is_empty() {
                return Err("alpn is empty".into());
            }
            format!("{name}=\"{}\"", ids.join(","))
        }
        2 => {
            if !v.is_empty() {
                return Err("no-default-alpn has no value".into());
            }
            name.to_string()
        }
        3 => {
            let p: [u8; 2] = v.try_into().map_err(|_| "port is 2 bytes")?;
            format!("{name}={}", u16::from_be_bytes(p))
        }
        4 => {
            if v.is_empty() || !v.len().is_multiple_of(4) {
                return Err("ipv4hint is a list of addresses".into());
            }
            let a: Vec<String> = v.chunks(4).map(|x| Ipv4Addr::new(x[0], x[1], x[2], x[3]).to_string()).collect();
            format!("{name}={}", a.join(","))
        }
        5 => format!("{name}={}", text::base64(v)),
        6 => {
            if v.is_empty() || !v.len().is_multiple_of(16) {
                return Err("ipv6hint is a list of addresses".into());
            }
            let a: Vec<String> = v.chunks(16).map(|x| Ipv6Addr::from(<[u8; 16]>::try_from(x).unwrap_or([0; 16])).to_string()).collect();
            format!("{name}={}", a.join(","))
        }
        7 => format!("{name}={}", text::char_string(v)),
        k => generic(k),
    })
}

fn svc_key_name(k: u16) -> String {
    match k {
        0 => "mandatory".into(),
        1 => "alpn".into(),
        2 => "no-default-alpn".into(),
        3 => "port".into(),
        4 => "ipv4hint".into(),
        5 => "ech".into(),
        6 => "ipv6hint".into(),
        7 => "dohpath".into(),
        k => format!("key{k}"),
    }
}
