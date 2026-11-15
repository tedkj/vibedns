//! Who is asked: Windows, every adapter's configured DNS servers, the three public presets over
//! UDP, TCP, DoT or DoH (IPv4 or IPv6, connecting to the literal address, so no bootstrap
//! lookup), and the user's own servers. Each is a column; at most `MAX_COLUMNS`.

use crate::text;
use crate::transport::{Proto, Server, doh_url};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

pub const MAX_COLUMNS: usize = 8;
/// Adapter servers in the default set at most (so the three public ones still fit).
pub const MAX_ADAPTER_DEFAULT: usize = 4;
pub const MAX_CUSTOM: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preset {
    pub key: &'static str,
    pub name: &'static str,
    pub v4: Ipv4Addr,
    pub v6: Ipv6Addr,
    /// The TLS name, DoH's host.
    pub host: &'static str,
}

pub const PRESETS: [Preset; 3] = [
    Preset { key: "cloudflare", name: "Cloudflare", v4: Ipv4Addr::new(1, 1, 1, 1), v6: Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111), host: "cloudflare-dns.com" },
    Preset { key: "google", name: "Google", v4: Ipv4Addr::new(8, 8, 8, 8), v6: Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), host: "dns.google" },
    Preset { key: "quad9", name: "Quad9", v4: Ipv4Addr::new(9, 9, 9, 9), v6: Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe), host: "dns.quad9.net" },
];

pub fn proto_key(p: Proto) -> &'static str {
    match p {
        Proto::Udp => "udp",
        Proto::Tcp => "tcp",
        Proto::Dot => "dot",
        Proto::Doh => "doh",
    }
}

/// "cloudflare/udp/4".
pub fn preset_id(key: &str, proto: Proto, v6: bool) -> String {
    format!("{key}/{}/{}", proto_key(proto), if v6 { 6 } else { 4 })
}

/// The default public columns.
pub fn default_presets() -> Vec<String> {
    PRESETS.iter().map(|p| preset_id(p.key, Proto::Udp, false)).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Windows,
    Adapter,
    Preset,
    Custom,
}

/// One column: who is asked and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    /// Stable: "windows", "adapter/192.168.1.1", "cloudflare/udp/4", "custom/3".
    pub id: String,
    pub kind: Kind,
    /// "Windows", "Wi-Fi", "Cloudflare", "dns.example".
    pub label: String,
    /// "192.168.1.1 · UDP", "2606:4700:4700::1111 · DoH GET".
    pub detail: String,
    /// None for Windows, and for a custom server whose host name is resolved at its first query.
    pub server: Option<Server>,
    /// A custom server named by host name: resolved once via the system (and shown).
    pub resolve: Option<(String, u16)>,
}

impl Column {
    pub fn windows() -> Column {
        Column { id: "windows".into(), kind: Kind::Windows, label: "Windows".into(), detail: "DnsQueryEx · as apps see it".into(), server: None, resolve: None }
    }

    pub fn raw(&self) -> bool {
        self.kind != Kind::Windows
    }

    /// "Cloudflare DoT", "Wi-Fi 192.168.1.1" for the status line (an adapter can have several
    /// servers: its name alone would not say which one differs).
    pub fn short(&self) -> String {
        match (&self.kind, &self.server) {
            (Kind::Preset, Some(s)) => format!("{} {}{}", self.label, s.proto.name(), if s.addr.is_ipv6() { " (IPv6)" } else { "" }),
            (Kind::Adapter, Some(s)) => format!("{} {}", self.label, s.addr.ip()),
            _ => self.label.clone(),
        }
    }
}

fn addr_text(a: &SocketAddr, proto: Proto) -> String {
    let ip = match a {
        SocketAddr::V6(v6) if v6.scope_id() != 0 => format!("{}%{}", v6.ip(), v6.scope_id()),
        _ => a.ip().to_string(),
    };
    if a.port() == proto.default_port() { ip } else if a.is_ipv6() { format!("[{ip}]:{}", a.port()) } else { format!("{ip}:{}", a.port()) }
}

pub fn detail(server: &Server) -> String {
    format!("{} · {}", addr_text(&server.addr, server.proto), server.via())
}

/// The column of a preset id ("google/dot/6").
pub fn preset_column(id: &str) -> Option<Column> {
    let mut parts = id.split('/');
    let key = parts.next()?;
    let proto = match parts.next()? {
        "udp" => Proto::Udp,
        "tcp" => Proto::Tcp,
        "dot" => Proto::Dot,
        "doh" => Proto::Doh,
        _ => return None,
    };
    let v6 = match parts.next()? {
        "4" => false,
        "6" => true,
        _ => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    let p = PRESETS.iter().find(|p| p.key == key)?;
    let ip: IpAddr = if v6 { p.v6.into() } else { p.v4.into() };
    let mut s = Server::plain(SocketAddr::new(ip, proto.default_port()), proto);
    if matches!(proto, Proto::Dot | Proto::Doh) {
        s.tls_name = p.host.into();
    }
    if proto == Proto::Doh {
        s.host = p.host.into();
        s.path = "/dns-query".into();
    }
    Some(Column { id: id.into(), kind: Kind::Preset, label: p.name.into(), detail: detail(&s), server: Some(s), resolve: None })
}

/// A server of the user's own (prefs.json keeps them).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Custom {
    pub id: u32,
    /// An IP address or a host name (resolved once via the system). For DoH it may be empty:
    /// the URL's host is used.
    pub address: String,
    /// 0: the transport's own (53, 853, 443).
    pub port: u16,
    pub proto: Proto,
    /// DoT: the name the certificate must carry (empty: the address, when it is a name).
    pub tls_name: String,
    /// DoH: the URL template ("https://dns.example/dns-query{?dns}").
    pub url: String,
    /// DoH: POST instead of GET.
    pub post: bool,
}

fn bad(s: &str) -> bool {
    s.chars().any(|c| c.is_whitespace() || text::invisible(c))
}

/// An address as typed: an IP literal (brackets and a zone allowed), or a host name.
fn host_or_ip(s: &str) -> Result<Result<IpAddr, String>, String> {
    let s = s.trim();
    let bare = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(s);
    if bare.is_empty() {
        return Err("Type the server's address or host name.".into());
    }
    if bad(bare) {
        return Err(format!("“{}” has spaces or invisible characters in it.", text::clean(bare, 80)));
    }
    if let Ok(ip) = bare.split('%').next().unwrap_or(bare).parse::<IpAddr>() {
        return Ok(Ok(ip));
    }
    let n = crate::query::parse_input(bare, 1).map_err(|e| e.to_string())?;
    if n.ptr_of.is_some() || n.labels.is_empty() {
        return Err(format!("“{}” is not a host name.", text::clean(bare, 80)));
    }
    Ok(Err(bare.trim_end_matches('.').to_string()))
}

impl Custom {
    /// Checked and tidied, or what is wrong in words.
    pub fn validated(mut self) -> Result<Custom, String> {
        self.address = self.address.trim().to_string();
        self.tls_name = self.tls_name.trim().trim_end_matches('.').to_string();
        self.url = self.url.trim().to_string();
        if bad(&self.tls_name) {
            return Err("The TLS name has spaces or invisible characters in it.".into());
        }
        match self.proto {
            Proto::Doh => {
                doh_url(&self.url)?;
                if !self.address.is_empty() {
                    let _ = host_or_ip(&self.address)?;
                }
            }
            Proto::Dot => {
                let a = host_or_ip(&self.address)?;
                if self.tls_name.is_empty() {
                    match a {
                        Err(name) => self.tls_name = name,
                        Ok(_) => return Err("DoT checks the server's certificate: type the name it carries (TLS name).".into()),
                    }
                }
            }
            Proto::Udp | Proto::Tcp => {
                let _ = host_or_ip(&self.address)?;
            }
        }
        Ok(self)
    }

    pub fn column_id(&self) -> String {
        format!("custom/{}", self.id)
    }

    /// Its column: the server at once for an IP literal, or the host name to resolve.
    pub fn column(&self) -> Result<Column, String> {
        let c = self.clone().validated()?;
        let (host, url_port, path) = if c.proto == Proto::Doh { doh_url(&c.url)? } else { (String::new(), 0, String::new()) };
        let target = if c.proto == Proto::Doh && c.address.is_empty() { host.clone() } else { c.address.clone() };
        let port = if c.port != 0 { c.port } else if c.proto == Proto::Doh { url_port } else { c.proto.default_port() };
        let tls_name = if c.proto == Proto::Doh { host.clone() } else { c.tls_name.clone() };
        let host_header = if url_port == 443 { host.clone() } else if host.contains(':') { format!("[{host}]:{url_port}") } else { format!("{host}:{url_port}") };
        let label = text::clean(&target, 80);
        let make = |addr: SocketAddr| Server { addr, proto: c.proto, tls_name: tls_name.clone(), path: path.clone(), host: host_header.clone(), post: c.post };
        match host_or_ip(&target)? {
            Ok(ip) => {
                let s = make(scoped(ip, port, &target));
                Ok(Column { id: c.column_id(), kind: Kind::Custom, label, detail: detail(&s), server: Some(s), resolve: None })
            }
            Err(name) => {
                let s = make(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port));
                Ok(Column { id: c.column_id(), kind: Kind::Custom, label, detail: format!("{} · {}", text::clean(&name, 80), s.via()), server: Some(s), resolve: Some((name, port)) })
            }
        }
    }
}

/// An IPv6 literal with its zone ("fe80::1%12") keeps the zone as its scope id.
fn scoped(ip: IpAddr, port: u16, typed: &str) -> SocketAddr {
    match ip {
        IpAddr::V6(v6) => {
            let scope = typed.split('%').nth(1).and_then(|z| z.trim_end_matches(']').parse().ok()).unwrap_or(0);
            SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope))
        }
        v4 => SocketAddr::new(v4, port),
    }
}

// ---------- adapters ----------

/// An adapter that is up, with its DNS servers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adapter {
    pub index: u32,
    /// "Wi-Fi" (the name Windows shows).
    pub name: String,
    /// The interface GUID ("{...}"), for its DoH settings.
    pub guid: String,
    /// Its DNS servers, port 53, link-local ones with their scope.
    pub dns: Vec<SocketAddr>,
    /// Its connection-specific DNS suffix.
    pub suffix: String,
    /// It has a global IPv6 address (2000::/3).
    pub global_v6: bool,
}

/// One column per adapter DNS server (an address on two adapters once, named by both),
/// skipping Windows' fec0:0:0:ffff::1..3 placeholders.
pub fn adapter_columns(adapters: &[Adapter]) -> Vec<Column> {
    let mut out: Vec<Column> = Vec::new();
    for a in adapters {
        for d in &a.dns {
            if placeholder(d.ip()) {
                continue;
            }
            let id = format!("adapter/{}", d.ip());
            if let Some(c) = out.iter_mut().find(|c| c.id == id) {
                if !c.label.split(" + ").any(|l| l == a.name) {
                    c.label = format!("{} + {}", c.label, a.name);
                }
                continue;
            }
            let s = Server::plain(*d, Proto::Udp);
            out.push(Column { id, kind: Kind::Adapter, label: if a.name.is_empty() { "Adapter".into() } else { a.name.clone() }, detail: detail(&s), server: Some(s), resolve: None });
        }
    }
    out
}

pub fn placeholder(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[..7] == [0xfec0, 0, 0, 0xffff, 0, 0, 0] && (1..=3).contains(&v6.segments()[7]))
}

/// What the user picked (prefs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    /// Preset and custom ids that are on, in the order they were switched on.
    pub on: Vec<String>,
    /// Adapter server addresses the user switched off.
    pub adapters_off: Vec<String>,
    pub customs: Vec<Custom>,
}

/// The columns: Windows, the adapters' servers (minus the ones switched off), then the presets
/// and custom servers that are on, in their fixed order. At most `MAX_COLUMNS`; the count left
/// out is returned (an adapter list longer than expected).
pub fn columns(adapters: &[Column], sel: &Selection) -> (Vec<Column>, usize) {
    let mut all = vec![Column::windows()];
    all.extend(adapters.iter().filter(|c| !sel.adapters_off.iter().any(|o| c.id == format!("adapter/{o}"))).cloned());
    for p in PRESETS {
        for v6 in [false, true] {
            for proto in Proto::ALL {
                let id = preset_id(p.key, proto, v6);
                if sel.on.contains(&id) {
                    all.extend(preset_column(&id));
                }
            }
        }
    }
    for c in &sel.customs {
        if sel.on.contains(&c.column_id())
            && let Ok(col) = c.column()
        {
            all.push(col);
        }
    }
    let left_out = all.len().saturating_sub(MAX_COLUMNS);
    all.truncate(MAX_COLUMNS);
    (all, left_out)
}

/// The adapters Windows lists (GetAdaptersAddresses): up, not loopback, with their DNS servers.
pub fn system_adapters() -> Result<Vec<Adapter>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64>;
    let mut tries = 0;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: an 8-byte aligned buffer of `size` bytes; the API fills a linked list inside it.
        let r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr().cast(), &mut size) };
        match r {
            0 => break,
            111 if tries < 4 => tries += 1, // ERROR_BUFFER_OVERFLOW: `size` now says how much
            232 => return Ok(Vec::new()),  // ERROR_NO_DATA: no adapters at all
            e => return Err(format!("Windows did not list the network adapters (error {e}).")),
        }
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        // SAFETY: a node of the list GetAdaptersAddresses wrote into `buf`, which outlives this loop.
        let a = unsafe { &*p };
        p = a.Next;
        if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        // SAFETY: the union's index member; the strings are NUL-terminated (wide, or ANSI for
        // AdapterName).
        let (index, name, guid, suffix) = unsafe {
            (
                a.Anonymous1.Anonymous.IfIndex,
                text::clean(&wide_str(a.FriendlyName), 80),
                if a.AdapterName.is_null() { String::new() } else { String::from_utf8_lossy(std::ffi::CStr::from_ptr(a.AdapterName.cast()).to_bytes()).to_string() },
                text::clean(&wide_str(a.DnsSuffix), 255),
            )
        };
        let mut dns = Vec::new();
        let mut d = a.FirstDnsServerAddress;
        while !d.is_null() {
            // SAFETY: as above.
            let da = unsafe { &*d };
            if let Some(sa) = unsafe { sockaddr(da.Address.lpSockaddr, 53) }
                && !dns.contains(&sa)
            {
                dns.push(sa);
            }
            d = da.Next;
        }
        let mut global_v6 = false;
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            // SAFETY: as above.
            let ua = unsafe { &*u };
            if let Some(SocketAddr::V6(v6)) = unsafe { sockaddr(ua.Address.lpSockaddr, 0) } {
                global_v6 |= v6.ip().segments()[0] & 0xe000 == 0x2000;
            }
            u = ua.Next;
        }
        out.push(Adapter { index, name, guid, dns, suffix, global_v6 });
    }
    Ok(out)
}

unsafe fn wide_str(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller hands a NUL-terminated string.
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// A SOCKADDR as an address with `port`; an IPv6 one keeps its scope id (fe80::1%12).
unsafe fn sockaddr(sa: *const windows_sys::Win32::Networking::WinSock::SOCKADDR, port: u16) -> Option<SocketAddr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};
    if sa.is_null() {
        return None;
    }
    // SAFETY: a sockaddr of the family it says.
    unsafe {
        match (*sa).sa_family {
            AF_INET => Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from((*(sa as *const SOCKADDR_IN)).sin_addr.S_un.S_addr.to_ne_bytes())), port)),
            AF_INET6 => {
                let s6 = &*(sa as *const SOCKADDR_IN6);
                let ip = Ipv6Addr::from(s6.sin6_addr.u.Byte);
                let scope = if ip.segments()[0] & 0xffc0 == 0xfe80 { s6.Anonymous.sin6_scope_id } else { 0 };
                Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
            }
            _ => None,
        }
    }
}
