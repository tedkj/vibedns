//! Asking one server: UDP (2 s, one retry, TC=1 retried over TCP at once), TCP, DoT (RFC 7858)
//! and DoH (RFC 8484, HTTP/1.1, GET or POST) over rustls on ring, certificates checked by
//! Windows' own verifier. Stream connections are kept for 30 s per resolver. A reply counts only
//! when it answers the query (`query::check`); the rest are ignored and counted.

use crate::query::{self, Sent};
use crate::text;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// A stream connection is used again for this long after its last answer.
pub const KEEP: Duration = Duration::from_secs(30);
/// The largest DoH body read (a DNS message over TCP is at most 65 535 bytes).
pub const DOH_CAP: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Proto {
    #[default]
    Udp,
    Tcp,
    Dot,
    Doh,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Udp => "UDP",
            Proto::Tcp => "TCP",
            Proto::Dot => "DoT",
            Proto::Doh => "DoH",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Proto::Udp | Proto::Tcp => 53,
            Proto::Dot => 853,
            Proto::Doh => 443,
        }
    }

    pub const ALL: [Proto; 4] = [Proto::Udp, Proto::Tcp, Proto::Dot, Proto::Doh];
}

/// Where and how to ask.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Server {
    pub addr: SocketAddr,
    pub proto: Proto,
    /// DoT and DoH: the name the certificate must carry (sent as SNI too).
    pub tls_name: String,
    /// DoH: the URL's path and any fixed query ("/dns-query").
    pub path: String,
    /// DoH: the Host header ("dns.google", "dns.example:8443").
    pub host: String,
    /// DoH: POST instead of GET.
    pub post: bool,
}

impl Server {
    pub fn plain(addr: SocketAddr, proto: Proto) -> Server {
        Server { addr, proto, tls_name: String::new(), path: String::new(), host: String::new(), post: false }
    }

    /// "UDP", "DoH GET".
    pub fn via(&self) -> String {
        match self.proto {
            Proto::Doh => format!("DoH {}", if self.post { "POST" } else { "GET" }),
            p => p.name().into(),
        }
    }
}

/// A DoH URL template ("https://dns.google/dns-query{?dns}") as host, port and path.
pub fn doh_url(url: &str) -> Result<(String, u16, String), String> {
    let u = url.trim();
    let rest = u.strip_prefix("https://").ok_or_else(|| format!("A DoH URL starts with https:// (“{}”).", text::clean(u, 120)))?;
    let rest = rest.replace("{?dns}", "");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest.as_str(), "/dns-query".to_string()),
    };
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let (h, p) = r.split_once(']').ok_or("A DoH URL's IPv6 address needs its closing bracket.")?;
        (h.to_string(), p.strip_prefix(':').map(|p| p.parse::<u16>()).transpose().map_err(|_| "The DoH URL's port is not a number.")?)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), Some(p.parse::<u16>().map_err(|_| "The DoH URL's port is not a number.")?))
    } else {
        (authority.to_string(), None)
    };
    if host.is_empty() || host.chars().any(|c| c.is_whitespace() || text::invisible(c)) {
        return Err("The DoH URL has no usable host name.".into());
    }
    if path.chars().any(|c| c.is_whitespace() || text::invisible(c)) {
        return Err("The DoH URL's path has spaces or invisible characters in it.".into());
    }
    Ok((host, port.unwrap_or(443), path))
}

/// How long to wait.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    pub udp: Duration,
    pub udp_tries: u32,
    pub connect: Duration,
    pub io: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts { udp: Duration::from_secs(2), udp_tries: 2, connect: Duration::from_secs(3), io: Duration::from_secs(4) }
    }
}

/// One answered query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    pub reply: Vec<u8>,
    /// The query's round trip (from sending to the whole answer).
    pub rtt: Duration,
    /// Connect (and TLS handshake) time, when a connection was opened for this query.
    pub setup: Option<Duration>,
    /// "UDP", "UDP, truncated, retried over TCP", "DoT", "DoH GET".
    pub via: String,
    /// Replies that did not answer the query (another ID, question or address), ignored.
    pub ignored: u32,
    /// The connection was kept from an earlier query.
    pub reused: bool,
}

/// Asking servers: the system's network, or a fake in the window tests.
pub trait Net: Send + Sync {
    fn ask(&self, server: &Server, sent: &Sent) -> Result<Exchange, String>;
}

// ---------- TLS ----------

/// The TLS client configurations: ALPN "dot" for DoT, "http/1.1" for DoH.
pub struct Tls {
    dot: Arc<ClientConfig>,
    doh: Arc<ClientConfig>,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl Tls {
    /// Windows' verifier (its roots, corporate ones included, and its revocation checks).
    pub fn system() -> Result<Tls, String> {
        use rustls_platform_verifier::BuilderVerifierExt;
        let make = |alpn: &[u8]| -> Result<Arc<ClientConfig>, String> {
            let mut c = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_platform_verifier()
                .map_err(|e| e.to_string())?
                .with_no_client_auth();
            c.alpn_protocols = vec![alpn.to_vec()];
            Ok(Arc::new(c))
        };
        Ok(Tls { dot: make(b"dot")?, doh: make(b"http/1.1")? })
    }

    /// Only these roots (DER): the tests' own CA.
    pub fn with_roots(roots: &[&[u8]]) -> Tls {
        let mut store = rustls::RootCertStore::empty();
        for r in roots {
            let _ = store.add(rustls::pki_types::CertificateDer::from(r.to_vec()));
        }
        let make = |alpn: &[u8]| {
            let mut c = ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().expect("ring offers TLS 1.2 and 1.3").with_root_certificates(store.clone()).with_no_client_auth();
            c.alpn_protocols = vec![alpn.to_vec()];
            Arc::new(c)
        };
        Tls { dot: make(b"dot"), doh: make(b"http/1.1") }
    }
}

// ---------- connections ----------

/// A TCP stream whose reads stop at a deadline: one time limit for a whole answer (or TLS
/// handshake), however the server spreads its bytes. Every read gets only the time left, so a
/// server that trickles cannot stretch it (a per-read timeout restarts with every byte).
struct Sock {
    tcp: TcpStream,
    deadline: Option<Instant>,
}

impl Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(d) = self.deadline {
            let left = d.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "the time for the answer is up"));
            }
            self.tcp.set_read_timeout(Some(left.max(Duration::from_millis(1))))?;
        }
        self.tcp.read(buf)
    }
}

impl Write for Sock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tcp.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }
}

enum Conn {
    Tcp(Sock),
    Tls(Box<StreamOwned<ClientConnection, Sock>>),
}

impl Conn {
    /// Reads from now on stop at `d` (TLS records included: the limit is below TLS).
    fn deadline(&mut self, d: Instant) {
        match self {
            Conn::Tcp(s) => s.deadline = Some(d),
            Conn::Tls(s) => s.sock.deadline = Some(d),
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    addr: SocketAddr,
    proto: Proto,
    tls_name: String,
}

struct Idle {
    key: Key,
    conn: Conn,
    since: Instant,
}

/// The system's network.
pub struct System {
    /// Set up once it works; a failure is never kept (the next DoT/DoH query tries again).
    tls: OnceLock<Tls>,
    make_tls: Box<dyn Fn() -> Result<Tls, String> + Send + Sync>,
    timeouts: Timeouts,
    pool: Mutex<Vec<Idle>>,
}

impl System {
    pub fn new() -> System {
        System::with_timeouts(Timeouts::default())
    }

    /// With other timeouts (the trace: one try of 3 s), Windows' verifier.
    pub fn with_timeouts(timeouts: Timeouts) -> System {
        System::with_tls_from(Box::new(Tls::system), timeouts)
    }

    /// With other TLS roots and timeouts (tests).
    pub fn with(tls: Tls, timeouts: Timeouts) -> System {
        let s = System::with_timeouts(timeouts);
        let _ = s.tls.set(tls);
        s
    }

    /// TLS set up by `make` at the first DoT/DoH query that works (tests).
    pub fn with_tls_from(make: Box<dyn Fn() -> Result<Tls, String> + Send + Sync>, timeouts: Timeouts) -> System {
        System { tls: OnceLock::new(), make_tls: make, timeouts, pool: Mutex::new(Vec::new()) }
    }

    fn tls(&self) -> Result<&Tls, String> {
        if let Some(t) = self.tls.get() {
            return Ok(t);
        }
        let t = (self.make_tls)().map_err(|e| format!("TLS could not be set up: {e}"))?;
        let _ = self.tls.set(t); // another query may have set it first: either one serves
        Ok(self.tls.get().expect("set just now"))
    }

    fn take(&self, key: &Key) -> Option<Conn> {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        pool.retain(|i| i.since.elapsed() < KEEP);
        let i = pool.iter().position(|i| i.key == *key)?;
        Some(pool.swap_remove(i).conn)
    }

    fn put(&self, key: Key, conn: Conn) {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        pool.retain(|i| i.since.elapsed() < KEEP && i.key != key);
        pool.push(Idle { key, conn, since: Instant::now() });
    }

    /// Connections kept right now (tests).
    pub fn kept(&self) -> usize {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        pool.retain(|i| i.since.elapsed() < KEEP);
        pool.len()
    }

    fn udp(&self, server: &Server, sent: &Sent) -> Result<Exchange, String> {
        let bind: SocketAddr = if server.addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let sock = UdpSocket::bind(bind).map_err(|e| net_error(&e, server, "open a UDP socket"))?;
        let mut buf = vec![0u8; 65_535];
        let mut ignored = 0;
        for _ in 0..self.timeouts.udp_tries.max(1) {
            let start = Instant::now();
            sock.send_to(&sent.bytes, server.addr).map_err(|e| net_error(&e, server, "send"))?;
            loop {
                let left = self.timeouts.udp.saturating_sub(start.elapsed());
                if left.is_zero() {
                    break;
                }
                let _ = sock.set_read_timeout(Some(left.max(Duration::from_millis(1))));
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        if from.ip() != server.addr.ip() || from.port() != server.addr.port() {
                            ignored += 1;
                            continue;
                        }
                        if query::check(sent, &buf[..n]).is_err() {
                            ignored += 1;
                            continue;
                        }
                        return Ok(Exchange { reply: buf[..n].to_vec(), rtt: start.elapsed(), setup: None, via: "UDP".into(), ignored, reused: false });
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                    // ICMP port unreachable comes back as a reset on Windows.
                    Err(e) if e.raw_os_error() == Some(10054) => return Err(format!("{} answered “port unreachable”: nothing listens for DNS there.", server.addr)),
                    Err(e) => return Err(net_error(&e, server, "receive")),
                }
            }
        }
        let tries = self.timeouts.udp_tries.max(1);
        Err(format!("No answer from {} over UDP in {} ({} {}).", server.addr, secs(self.timeouts.udp), tries, if tries == 1 { "try" } else { "tries" }))
    }

    fn open(&self, server: &Server) -> Result<Conn, String> {
        let tcp = TcpStream::connect_timeout(&server.addr, self.timeouts.connect).map_err(|e| net_error(&e, server, "connect"))?;
        let _ = tcp.set_nodelay(true);
        let _ = tcp.set_read_timeout(Some(self.timeouts.io));
        let _ = tcp.set_write_timeout(Some(self.timeouts.io));
        // The handshake gets the answer's time limit too, as a whole.
        let mut sock = Sock { tcp, deadline: Some(Instant::now() + self.timeouts.io) };
        match server.proto {
            Proto::Udp | Proto::Tcp => Ok(Conn::Tcp(sock)),
            Proto::Dot | Proto::Doh => {
                let tls = self.tls()?;
                let cfg = if server.proto == Proto::Dot { tls.dot.clone() } else { tls.doh.clone() };
                let name = ServerName::try_from(server.tls_name.clone()).map_err(|_| format!("“{}” is not a name a certificate can be checked against.", text::clean(&server.tls_name, 120)))?;
                let mut conn = ClientConnection::new(cfg, name).map_err(|e| format!("TLS could not start: {e}"))?;
                while conn.is_handshaking() {
                    conn.complete_io(&mut sock).map_err(|e| tls_error(&e, server))?;
                }
                Ok(Conn::Tls(Box::new(StreamOwned::new(conn, sock))))
            }
        }
    }

    /// TCP, DoT, DoH: on a kept connection when there is one (one fresh try more if the server
    /// had closed it meanwhile), else on a new one whose setup time is reported.
    fn stream(&self, server: &Server, sent: &Sent) -> Result<Exchange, String> {
        let key = Key { addr: server.addr, proto: server.proto, tls_name: server.tls_name.clone() };
        for attempt in 0..2 {
            let kept = if attempt == 0 { self.take(&key) } else { None };
            let reused = kept.is_some();
            let (mut conn, setup) = match kept {
                Some(c) => (c, None),
                None => {
                    let t0 = Instant::now();
                    let c = self.open(server)?;
                    (c, Some(t0.elapsed()))
                }
            };
            let t0 = Instant::now();
            let r = if server.proto == Proto::Doh { self.doh_roundtrip(&mut conn, server, sent) } else { self.dns_roundtrip(&mut conn, server, sent) };
            match r {
                Ok((reply, ignored, keep)) => {
                    let rtt = t0.elapsed();
                    if keep {
                        self.put(key, conn);
                    }
                    return Ok(Exchange { reply, rtt, setup, via: server.via(), ignored, reused });
                }
                Err(Fail::Gone(_)) if reused => continue,
                Err(Fail::Gone(e)) | Err(Fail::Final(e)) => return Err(e),
            }
        }
        Err(format!("{} closed the connection.", server.addr))
    }

    /// TCP and DoT: two-byte length, the message; answers read until ours (others ignored).
    fn dns_roundtrip(&self, conn: &mut Conn, server: &Server, sent: &Sent) -> Result<(Vec<u8>, u32, bool), Fail> {
        let mut out = Vec::with_capacity(sent.bytes.len() + 2);
        out.extend_from_slice(&(sent.bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&sent.bytes);
        conn.write_all(&out).and_then(|_| conn.flush()).map_err(|e| Fail::Gone(io_text(&e, server, "send")))?;
        // One deadline for the answer, however its bytes arrive.
        let deadline = Instant::now() + self.timeouts.io;
        conn.deadline(deadline);
        let mut ignored = 0;
        let mut first = true;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Fail::Final(self.late(server)));
            }
            let mut len = [0u8; 2];
            if let Err(e) = conn.read_exact(&mut len) {
                let t = if timed_out(&e) { self.late(server) } else { io_text(&e, server, "read the answer") };
                // Nothing came back at all on a kept connection: it was closed under us.
                return Err(if first && e.kind() != std::io::ErrorKind::TimedOut && e.kind() != std::io::ErrorKind::WouldBlock { Fail::Gone(t) } else { Fail::Final(t) });
            }
            first = false;
            let n = u16::from_be_bytes(len) as usize;
            let mut msg = vec![0u8; n];
            conn.read_exact(&mut msg).map_err(|e| Fail::Final(if timed_out(&e) { self.late(server) } else { io_text(&e, server, "read the answer") }))?;
            if query::check(sent, &msg).is_ok() {
                return Ok((msg, ignored, true));
            }
            ignored += 1;
        }
    }

    /// The whole answer did not arrive in time (however much of it trickled in).
    fn late(&self, server: &Server) -> String {
        format!("No answer from {} over {} in {} (timed out).", server.addr, server.proto.name(), secs(self.timeouts.io))
    }

    /// DoH: one HTTP/1.1 request, one response (kept alive unless the server says close).
    fn doh_roundtrip(&self, conn: &mut Conn, server: &Server, sent: &Sent) -> Result<(Vec<u8>, u32, bool), Fail> {
        let sent = if server.post { sent.clone() } else { sent.with_id(0) };
        conn.write_all(&doh_request(server, &sent)).and_then(|_| conn.flush()).map_err(|e| Fail::Gone(io_text(&e, server, "send")))?;
        conn.deadline(Instant::now() + self.timeouts.io);
        let resp = match read_response(conn, DOH_CAP) {
            Ok(r) => r,
            Err(HttpError::Closed) => return Err(Fail::Gone(format!("{} closed the connection without an answer.", server.addr))),
            Err(HttpError::Io(e)) if timed_out(&e) => return Err(Fail::Final(self.late(server))),
            Err(HttpError::Io(e)) => return Err(Fail::Final(io_text(&e, server, "read the answer"))),
            Err(HttpError::Bad(t)) => return Err(Fail::Final(format!("{} sent a broken HTTP answer: {t}", server.addr))),
        };
        if resp.status != 200 {
            let mut t = format!("The DoH server answered HTTP {} {}", resp.status, text::clean(&resp.reason, 60));
            let snippet = text::clean(&String::from_utf8_lossy(&resp.body[..resp.body.len().min(160)]), 120);
            if resp.content_type.starts_with("text/") && !snippet.is_empty() {
                t.push_str(&format!(" (“{snippet}”)"));
            }
            t.push('.');
            return Err(Fail::Final(t));
        }
        if !resp.content_type.eq_ignore_ascii_case("application/dns-message") {
            let ct = if resp.content_type.is_empty() { "none".to_string() } else { text::clean(&resp.content_type, 60) };
            return Err(Fail::Final(format!("The DoH server answered with something that is not a DNS message (Content-Type: {ct}).")));
        }
        match query::check(&sent, &resp.body) {
            Ok(()) => Ok((resp.body, 0, !resp.close)),
            Err(_) => Err(Fail::Final("The DoH server's answer is not a DNS answer to this question.".into())),
        }
    }
}

impl Default for System {
    fn default() -> Self {
        System::new()
    }
}

enum Fail {
    /// The connection was gone before anything came back (worth one fresh try if it was kept).
    Gone(String),
    Final(String),
}

impl Net for System {
    fn ask(&self, server: &Server, sent: &Sent) -> Result<Exchange, String> {
        match server.proto {
            Proto::Udp => {
                let x = self.udp(server, sent)?;
                if !query::truncated(&x.reply) {
                    return Ok(x);
                }
                let tcp = Server { proto: Proto::Tcp, ..server.clone() };
                match self.stream(&tcp, sent) {
                    Ok(mut t) => {
                        t.via = "UDP, truncated, retried over TCP".into();
                        t.ignored += x.ignored;
                        Ok(t)
                    }
                    Err(e) => Err(format!("The UDP answer was truncated (TC), and the retry over TCP failed: {e}")),
                }
            }
            _ => self.stream(server, sent),
        }
    }
}

fn timed_out(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
}

fn secs(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s >= 1.0 && s.fract() == 0.0 { format!("{} s", s as u64) } else { format!("{:.1} s", s) }
}

/// A socket error in words, with what was being done.
pub fn net_error(e: &std::io::Error, server: &Server, doing: &str) -> String {
    let a = server.addr;
    match e.raw_os_error() {
        Some(10051) | Some(10065) if a.is_ipv6() => format!("No route to {} ({doing}): this PC has no working IPv6 connection.", a.ip()),
        Some(10051) | Some(10065) => format!("No route to {} ({doing}).", a.ip()),
        Some(10061) => format!("{} refused the connection: nothing listens on port {}.", a.ip(), a.port()),
        Some(10060) => format!("{} did not accept the connection in time ({doing}).", a),
        Some(10049) | Some(10047) if a.is_ipv6() => format!("Could not {doing} to {}: this PC has no IPv6 address to send from.", a.ip()),
        Some(10050) => format!("The network is down ({doing})."),
        _ => match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => format!("{} did not answer in time ({doing}).", a),
            std::io::ErrorKind::ConnectionRefused => format!("{} refused the connection: nothing listens on port {}.", a.ip(), a.port()),
            _ => format!("Could not {doing} ({a}): {}", text::clean(&e.to_string(), 160)),
        },
    }
}

fn io_text(e: &std::io::Error, server: &Server, doing: &str) -> String {
    if let Some(t) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        return tls_words(t, server);
    }
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof => format!("{} closed the connection ({doing}).", server.addr),
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => format!("{} reset the connection ({doing}).", server.addr),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => format!("No answer from {} over {} in time ({doing}).", server.addr, server.proto.name()),
        _ => net_error(e, server, doing),
    }
}

fn tls_error(e: &std::io::Error, server: &Server) -> String {
    match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        Some(t) => tls_words(t, server),
        None => io_text(e, server, "TLS handshake"),
    }
}

/// TLS failures in words: the name mismatch and an untrusted issuer said plainly.
pub fn tls_words(e: &rustls::Error, server: &Server) -> String {
    use rustls::CertificateError as C;
    let name = text::clean(&server.tls_name, 120);
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::NotValidForName | C::NotValidForNameContext { .. } => format!("The server's certificate is not valid for {name} (TLS name mismatch)."),
            C::UnknownIssuer => format!("The server's certificate for {name} is not trusted by Windows (unknown issuer)."),
            C::Expired | C::ExpiredContext { .. } => format!("The server's certificate for {name} has expired."),
            C::NotValidYet | C::NotValidYetContext { .. } => format!("The server's certificate for {name} is not valid yet."),
            C::Revoked => format!("The server's certificate for {name} has been revoked."),
            other => format!("The server's certificate for {name} was refused: {}", text::clean(&format!("{other:?}"), 160)),
        },
        rustls::Error::NoApplicationProtocol => format!("{} does not speak {} (no matching ALPN).", server.addr, if server.proto == Proto::Dot { "DoT" } else { "HTTP/1.1" }),
        other => format!("TLS with {} failed: {}", server.addr, text::clean(&other.to_string(), 160)),
    }
}

// ---------- HTTP/1.1 for DoH ----------

/// The request: GET with `?dns=` (base64url, no padding; the caller set ID 0), or POST with the
/// message as the body.
pub fn doh_request(server: &Server, sent: &Sent) -> Vec<u8> {
    let path = if server.path.is_empty() { "/dns-query" } else { server.path.as_str() };
    let common = format!("Host: {}\r\nAccept: application/dns-message\r\nUser-Agent: VibeDNS/{}\r\n", server.host, crate::VERSION);
    if server.post {
        let mut r = format!("POST {path} HTTP/1.1\r\n{common}Content-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", sent.bytes.len()).into_bytes();
        r.extend_from_slice(&sent.bytes);
        r
    } else {
        let sep = if path.contains('?') { '&' } else { '?' };
        format!("GET {path}{sep}dns={} HTTP/1.1\r\n{common}\r\n", text::base64url(&sent.bytes)).into_bytes()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Http {
    pub status: u16,
    pub reason: String,
    pub content_type: String,
    pub body: Vec<u8>,
    /// The server closes the connection after this response.
    pub close: bool,
}

#[derive(Debug)]
pub enum HttpError {
    /// The connection closed before a status line.
    Closed,
    Io(std::io::Error),
    Bad(String),
}

struct Buffered<'a, R: Read> {
    r: &'a mut R,
    buf: Vec<u8>,
    pos: usize,
    /// Bytes of status lines, headers and trailers read so far (at most HEAD_BYTES).
    head: usize,
}

/// At most this many bytes of status lines, headers and trailers in one response (interim
/// responses included), and at most this many trailer lines (IN-VibeDNS-1).
const HEAD_BYTES: usize = 64 << 10;
const MAX_TRAILERS: usize = 100;

impl<R: Read> Buffered<'_, R> {
    fn fill(&mut self) -> Result<bool, HttpError> {
        // Consumed bytes go before every read, so the buffer holds only what is still unread.
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut chunk = [0u8; 4096];
        match self.r.read(&mut chunk) {
            Ok(0) => Ok(false),
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            Err(e) => Err(HttpError::Io(e)),
        }
    }

    /// One line without its CRLF (at most `max` bytes).
    fn line(&mut self, max: usize) -> Result<Option<Vec<u8>>, HttpError> {
        loop {
            if let Some(i) = self.buf[self.pos..].windows(2).position(|w| w == b"\r\n") {
                let l = self.buf[self.pos..self.pos + i].to_vec();
                self.pos += i + 2;
                return Ok(Some(l));
            }
            if self.buf.len() - self.pos > max {
                return Err(HttpError::Bad("a header line is too long".into()));
            }
            if !self.fill()? {
                return Ok(None);
            }
        }
    }

    /// A status, header or trailer line (at most 8 KiB), counted against HEAD_BYTES.
    fn head_line(&mut self) -> Result<Option<Vec<u8>>, HttpError> {
        let l = self.line(8192)?;
        if let Some(l) = &l {
            self.head += l.len() + 2;
            if self.head > HEAD_BYTES {
                return Err(HttpError::Bad(format!("the headers are more than {} KiB", HEAD_BYTES / 1024)));
            }
        }
        Ok(l)
    }

    fn exact(&mut self, n: usize) -> Result<Vec<u8>, HttpError> {
        while self.buf.len() - self.pos < n {
            if !self.fill()? {
                return Err(HttpError::Bad("the body ends early".into()));
            }
        }
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }
}

/// One HTTP/1.1 response: status, headers (Content-Length, chunked, Connection, Content-Type),
/// the body (at most `cap` bytes, chunked decoded). A body without either length is read to the
/// close.
pub fn read_response<R: Read>(r: &mut R, cap: usize) -> Result<Http, HttpError> {
    let mut b = Buffered { r, buf: Vec::new(), pos: 0, head: 0 };
    // Interim responses (100 Continue, 103 Early Hints) come before the real one: skipped.
    let mut interim = 0;
    let (status, reason, length, chunked, mut close, ctype) = loop {
        let status_line = match b.head_line()? {
            Some(l) => l,
            None if interim == 0 && b.buf.is_empty() => return Err(HttpError::Closed),
            None => return Err(HttpError::Bad("the status line is cut off".into())),
        };
        let sl = String::from_utf8_lossy(&status_line).to_string();
        let mut parts = sl.splitn(3, ' ');
        let version = parts.next().unwrap_or("");
        if !version.starts_with("HTTP/1.") {
            return Err(HttpError::Bad(format!("not an HTTP/1.1 status line (“{}”)", text::clean(&sl, 60))));
        }
        let status: u16 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| HttpError::Bad("no status code".into()))?;
        let reason = parts.next().unwrap_or("").to_string();
        let (mut length, mut chunked, mut close, mut ctype) = (None::<usize>, false, version == "HTTP/1.0", String::new());
        let mut headers = 0;
        loop {
            let l = b.head_line()?.ok_or_else(|| HttpError::Bad("the headers are cut off".into()))?;
            if l.is_empty() {
                break;
            }
            headers += 1;
            if headers > 100 {
                return Err(HttpError::Bad("too many headers".into()));
            }
            let h = String::from_utf8_lossy(&l).to_string();
            let Some((k, v)) = h.split_once(':') else { continue };
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "content-length" => {
                    let n: usize = v.parse().map_err(|_| HttpError::Bad("Content-Length is not a number".into()))?;
                    if n > cap {
                        return Err(HttpError::Bad(format!("the body is {n} bytes, more than the {} KiB a DNS answer can be", cap / 1024)));
                    }
                    length = Some(n);
                }
                "transfer-encoding" => chunked = v.to_ascii_lowercase().split(',').any(|t| t.trim() == "chunked"),
                "connection" => {
                    let v = v.to_ascii_lowercase();
                    if v.split(',').any(|t| t.trim() == "close") {
                        close = true;
                    } else if v.split(',').any(|t| t.trim() == "keep-alive") {
                        close = false;
                    }
                }
                "content-type" => ctype = v.split(';').next().unwrap_or("").trim().to_string(),
                _ => {}
            }
        }
        // 101 Switching Protocols is final (the connection is no longer HTTP).
        if (100..200).contains(&status) && status != 101 {
            interim += 1;
            if interim > 4 {
                return Err(HttpError::Bad("more than 4 interim (1xx) responses".into()));
            }
            continue;
        }
        break (status, reason, length, chunked, close, ctype);
    };
    let too_big = || HttpError::Bad(format!("the body is more than the {} KiB a DNS answer can be", cap / 1024));
    let body = if chunked {
        let mut body = Vec::new();
        loop {
            let l = b.line(1024)?.ok_or_else(|| HttpError::Bad("a chunk is cut off".into()))?;
            let size_text = String::from_utf8_lossy(&l).split(';').next().unwrap_or("").trim().to_string();
            let size = usize::from_str_radix(&size_text, 16).map_err(|_| HttpError::Bad(format!("“{}” is not a chunk size", text::clean(&size_text, 20))))?;
            if size == 0 {
                // Trailers, up to the empty line: at most MAX_TRAILERS lines, within HEAD_BYTES.
                let mut trailers = 0;
                while let Some(t) = b.head_line()? {
                    if t.is_empty() {
                        break;
                    }
                    trailers += 1;
                    if trailers > MAX_TRAILERS {
                        return Err(HttpError::Bad(format!("more than {MAX_TRAILERS} trailer lines")));
                    }
                }
                break;
            }
            // body.len() <= cap here: the subtraction cannot wrap, and no declared size can.
            if size > cap - body.len() {
                return Err(too_big());
            }
            body.extend_from_slice(&b.exact(size)?);
            if b.exact(2)? != b"\r\n" {
                return Err(HttpError::Bad("a chunk does not end where its size says".into()));
            }
        }
        body
    } else if let Some(n) = length {
        b.exact(n)?
    } else if status == 204 || status == 304 || (100..200).contains(&status) {
        Vec::new()
    } else {
        close = true;
        let mut body = b.buf[b.pos..].to_vec();
        b.pos = b.buf.len();
        loop {
            if body.len() > cap {
                return Err(too_big());
            }
            if !b.fill()? {
                break;
            }
            body.extend_from_slice(&b.buf[b.pos..]);
            b.pos = b.buf.len();
        }
        body
    };
    Ok(Http { status, reason: reason.trim().to_string(), content_type: ctype, body, close })
}
