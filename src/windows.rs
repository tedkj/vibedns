//! What Windows itself answers, and why it may differ: `DnsQueryEx` (standard options, so the
//! cache, the hosts file, NRPT, search suffixes and Windows' DoH all apply, as for any app),
//! the cache flush, the hosts file, NRPT rules and the per-interface DoH settings. Matching is
//! plain Rust (tested); the reads are Win32, on workers.

use crate::query::{self, Data, Rr};
use crate::text;
use std::net::IpAddr;
use std::path::PathBuf;

/// What DnsQueryEx gave.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WinAnswer {
    /// The status DnsQueryEx returned (0, 9003 NXDOMAIN, 9501 no records, ...).
    pub status: u32,
    /// Answer-section records (Windows marks the section of each).
    pub answer: Vec<Rr>,
    /// Authority and additional records Windows passed on.
    pub other: Vec<Rr>,
    /// Records of a type Windows returned without data we could rebuild.
    pub not_decoded: usize,
}

/// A status as an RCODE where it is one: an answer to compare. Anything else (a timeout, no
/// server, a refused query Windows could not attribute) is no answer.
pub fn status_rcode(status: u32) -> Option<u16> {
    match status {
        0 | 9501 => Some(0),
        9001 => Some(1),
        9002 => Some(2),
        9003 => Some(3),
        9004 => Some(4),
        9005 => Some(5),
        _ => None,
    }
}

/// A status in words.
pub fn status_text(status: u32) -> String {
    match status {
        0 => "NOERROR".into(),
        9501 => "NOERROR (no records of this type)".into(),
        9001 => "FORMERR".into(),
        9002 => "SERVFAIL".into(),
        9003 => "NXDOMAIN".into(),
        9004 => "NOTIMP".into(),
        9005 => "REFUSED".into(),
        1460 => "Windows got no answer in time (ERROR_TIMEOUT).".into(),
        9852 => "No DNS servers are configured (DNS_ERROR_NO_DNS_SERVERS).".into(),
        11001..=11004 => format!("Windows could not look it up ({}).", std::io::Error::from_raw_os_error(status as i32)),
        s => format!("Windows could not look it up: {} (error {s}).", text::clean(&std::io::Error::from_raw_os_error(s as i32).to_string(), 160)),
    }
}

/// DnsQueryEx, version 1 request, standard options, synchronous. `name` exactly as an app would
/// hand it (suffix search applies to a single label without a trailing dot).
pub fn query(name: &str, qtype: u16) -> WinAnswer {
    use windows_sys::Win32::NetworkManagement::Dns::*;
    let w = crate::host::wide(name);
    let req = DNS_QUERY_REQUEST {
        Version: DNS_QUERY_REQUEST_VERSION1,
        QueryName: w.as_ptr(),
        QueryType: qtype,
        QueryOptions: DNS_QUERY_STANDARD as u64,
        pDnsServerList: std::ptr::null_mut(),
        InterfaceIndex: 0,
        pQueryCompletionCallback: None,
        pQueryContext: std::ptr::null_mut(),
    };
    let mut res = DNS_QUERY_RESULT { Version: DNS_QUERY_REQUEST_VERSION1, ..Default::default() };
    // SAFETY: a version-1 request with a NUL-terminated name and no callback (synchronous); the
    // result's record list is ours to free with DnsFree.
    let r = unsafe { DnsQueryEx(&req, &mut res, std::ptr::null_mut()) };
    let status = if r != 0 { r as u32 } else { res.QueryStatus as u32 };
    let mut out = WinAnswer { status, ..WinAnswer::default() };
    let list = res.pQueryRecords as *const DNS_RECORDW;
    let mut p = list;
    while !p.is_null() {
        // SAFETY: a record of the list DnsQueryEx returned (wide records), valid until DnsFree.
        let rec = unsafe { &*p };
        // SAFETY: the record's own fields, read as its type says.
        match unsafe { record(rec) } {
            Some(rr) => {
                // SAFETY: the flags are a plain DWORD in the union. Section 1 is the answer;
                // records Windows makes itself (localhost, the hosts file) carry 0.
                let section = unsafe { rec.Flags.DW } & 0x3;
                if section <= 1 { out.answer.push(rr) } else { out.other.push(rr) }
            }
            None => out.not_decoded += 1,
        }
        p = rec.pNext;
    }
    if !list.is_null() {
        // SAFETY: the list DnsQueryEx returned, freed once.
        unsafe { DnsFree(list as *const _, DnsFreeRecordList) };
    }
    out
}

/// A wide string from Windows (lossy only where Windows itself had no text).
unsafe fn wstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller hands a NUL-terminated string.
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// A name as Windows writes it ("www.example.com", maybe with its dot) as wire labels.
pub fn name_labels(s: &str) -> query::Labels {
    s.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).map(|l| l.as_bytes().iter().take(63).copied().collect()).collect()
}

fn put_name(out: &mut Vec<u8>, s: &str) {
    for l in name_labels(s) {
        out.push(l.len() as u8);
        out.extend_from_slice(&l);
    }
    out.push(0);
}

/// One record DnsQueryEx returned, rebuilt as wire RDATA and read by the same parser as every
/// other column (so texts and comparisons are alike). None when Windows gave nothing usable.
unsafe fn record(rec: &windows_sys::Win32::NetworkManagement::Dns::DNS_RECORDW) -> Option<Rr> {
    use windows_sys::Win32::NetworkManagement::Dns::DNS_RECORDW_1;
    // SAFETY (whole function): `rec` is a record DnsQueryEx returned; each union member read is
    // the one its type uses, and arrays are read for the counts Windows wrote.
    unsafe {
        let d = &rec.Data;
        let t = rec.wType;
        let mut raw = Vec::new();
        match t {
            1 => raw.extend_from_slice(&d.A.IpAddress.to_ne_bytes()),
            28 => raw.extend_from_slice(&d.AAAA.Ip6Address.IP6Byte),
            2 | 5 | 12 | 39 => put_name(&mut raw, &wstr(d.PTR.pNameHost)),
            15 => {
                raw.extend_from_slice(&d.MX.wPreference.to_be_bytes());
                put_name(&mut raw, &wstr(d.MX.pNameExchange));
            }
            16 => {
                let txt = &d.TXT;
                let strings = std::slice::from_raw_parts(txt.pStringArray.as_ptr(), txt.dwStringCount as usize);
                for &sp in strings {
                    let s = wstr(sp);
                    let b = s.as_bytes();
                    for chunk in if b.is_empty() { vec![b] } else { b.chunks(255).collect() } {
                        raw.push(chunk.len() as u8);
                        raw.extend_from_slice(chunk);
                    }
                }
            }
            6 => {
                let s = &d.SOA;
                put_name(&mut raw, &wstr(s.pNamePrimaryServer));
                put_name(&mut raw, &wstr(s.pNameAdministrator));
                for v in [s.dwSerialNo, s.dwRefresh, s.dwRetry, s.dwExpire, s.dwDefaultTtl] {
                    raw.extend_from_slice(&v.to_be_bytes());
                }
            }
            33 => {
                let s = &d.SRV;
                for v in [s.wPriority, s.wWeight, s.wPort] {
                    raw.extend_from_slice(&v.to_be_bytes());
                }
                put_name(&mut raw, &wstr(s.pNameTarget));
            }
            43 => {
                let s = &d.DS;
                raw.extend_from_slice(&s.wKeyTag.to_be_bytes());
                raw.push(s.chAlgorithm);
                raw.push(s.chDigestType);
                let n = (s.wDigestLength as usize).min((rec.wDataLength as usize).saturating_sub(8));
                raw.extend_from_slice(std::slice::from_raw_parts(s.Digest.as_ptr(), n));
            }
            48 => {
                let k = &d.DNSKEY;
                raw.extend_from_slice(&k.wFlags.to_be_bytes());
                raw.push(k.chProtocol);
                raw.push(k.chAlgorithm);
                let n = (k.wKeyLength as usize).min((rec.wDataLength as usize).saturating_sub(8));
                raw.extend_from_slice(std::slice::from_raw_parts(k.Key.as_ptr(), n));
            }
            _ => {
                // Types Windows has no structure for (HTTPS, SVCB, CAA, ...) come as their raw
                // RDATA, wDataLength bytes from the start of Data (seen on Windows 11 26200;
                // DECISIONS.md). Never read as pointers.
                raw.extend_from_slice(std::slice::from_raw_parts((d as *const DNS_RECORDW_1).cast::<u8>(), rec.wDataLength as usize));
            }
        }
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&raw);
        let (data, text, canon, undecoded) = match query::rdata(&msg, 12, raw.len(), t) {
            Ok((d, s, c)) => (d, s, c, false),
            // A type we read that does not read: not what Windows was taken to hand over.
            Err(_) if raw.is_empty() || query::reads(t) => return None,
            Err(_) => (Data::Other, query::generic(&raw), raw.clone(), true),
        };
        Some(Rr { owner: name_labels(&wstr(rec.pName)), rtype: t, class: 1, ttl: rec.dwTtl, data, text, canon, undecoded })
    }
}

/// Windows' DNS cache flushed (`DnsFlushResolverCache`: undocumented, stable since NT, what
/// `ipconfig /flushdns` calls; no admin rights needed).
pub fn flush() -> Result<(), String> {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
    let lib = crate::host::wide("dnsapi.dll");
    // System32 only, whatever the process's default DLL folders (SUP-2): never a dnsapi.dll beside
    // the exe or in the current folder.
    // SAFETY: a NUL-terminated name; dnsapi.dll is a system DLL that stays loaded.
    let h = unsafe { LoadLibraryExW(lib.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if h.is_null() {
        return Err("Windows' DNS library could not be loaded.".into());
    }
    // SAFETY: a NUL-terminated ANSI name.
    let f = unsafe { GetProcAddress(h, c"DnsFlushResolverCache".as_ptr().cast()) };
    let Some(f) = f else { return Err("This Windows has no DnsFlushResolverCache.".into()) };
    // SAFETY: BOOL WINAPI DnsFlushResolverCache(void), as ipconfig calls it.
    let f: unsafe extern "system" fn() -> i32 = unsafe { std::mem::transmute(f) };
    if unsafe { f() } != 0 { Ok(()) } else { Err(format!("Windows did not flush its DNS cache: {}", std::io::Error::last_os_error())) }
}

// ---------- registry ----------

const HKLM: windows_sys::Win32::System::Registry::HKEY = windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;

/// A string value (REG_SZ, REG_EXPAND_SZ expanded): Ok(None) when the key or value is not there,
/// Err when it could not be read (access denied: unknown, never "none").
fn reg_string(key: &str, value: &str) -> Result<Option<String>, String> {
    reg_value(key, value, windows_sys::Win32::System::Registry::RRF_RT_REG_SZ | windows_sys::Win32::System::Registry::RRF_RT_REG_EXPAND_SZ).map(|v| v.map(|w| from_wide_z(&w)))
}

/// A REG_MULTI_SZ value as its strings.
fn reg_multi(key: &str, value: &str) -> Result<Option<Vec<String>>, String> {
    reg_value(key, value, windows_sys::Win32::System::Registry::RRF_RT_REG_MULTI_SZ | windows_sys::Win32::System::Registry::RRF_RT_REG_SZ)
        .map(|v| v.map(|w| w.split(|&c| c == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect()))
}

fn from_wide_z(w: &[u16]) -> String {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..n])
}

fn reg_value(key: &str, value: &str, flags: u32) -> Result<Option<Vec<u16>>, String> {
    use windows_sys::Win32::System::Registry::RegGetValueW;
    let k = crate::host::wide(key);
    let v = crate::host::wide(value);
    let mut size: u32 = 0;
    // SAFETY: NUL-terminated names; a size query first.
    let r = unsafe { RegGetValueW(HKLM, k.as_ptr(), v.as_ptr(), flags, std::ptr::null_mut(), std::ptr::null_mut(), &mut size) };
    match r {
        0 => {}
        2 | 3 => return Ok(None), // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
        e => return Err(format!("{key}\\{value} could not be read ({}).", std::io::Error::from_raw_os_error(e as i32))),
    }
    let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: a buffer of `size` bytes.
    let r = unsafe { RegGetValueW(HKLM, k.as_ptr(), v.as_ptr(), flags, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size) };
    match r {
        0 => {
            buf.truncate((size as usize).div_ceil(2));
            Ok(Some(buf))
        }
        2 | 3 => Ok(None),
        e => Err(format!("{key}\\{value} could not be read ({}).", std::io::Error::from_raw_os_error(e as i32))),
    }
}

/// The subkeys of a key: Ok(empty) when the key is not there, Err when it cannot be read.
fn reg_subkeys(key: &str) -> Result<Vec<String>, String> {
    use windows_sys::Win32::System::Registry::{HKEY, KEY_READ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW};
    let k = crate::host::wide(key);
    let mut h: HKEY = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path; the handle is closed below.
    let r = unsafe { RegOpenKeyExW(HKLM, k.as_ptr(), 0, KEY_READ, &mut h) };
    match r {
        0 => {}
        2 | 3 => return Ok(Vec::new()),
        e => return Err(format!("{key} could not be read ({}).", std::io::Error::from_raw_os_error(e as i32))),
    }
    let mut out = Vec::new();
    let mut i = 0;
    let res = loop {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: a buffer of `len` units.
        let r = unsafe { RegEnumKeyExW(h, i, name.as_mut_ptr(), &mut len, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
        match r {
            0 => out.push(String::from_utf16_lossy(&name[..len as usize])),
            259 => break Ok(out), // ERROR_NO_MORE_ITEMS
            e => break Err(format!("{key} could not be listed ({}).", std::io::Error::from_raw_os_error(e as i32))),
        }
        i += 1;
        if i > 4096 {
            break Ok(out);
        }
    };
    // SAFETY: the handle opened above.
    unsafe { RegCloseKey(h) };
    res
}

// ---------- hosts ----------

/// One line of the hosts file that names something.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostsLine {
    /// 1-based.
    pub number: usize,
    pub ip: IpAddr,
    pub names: Vec<String>,
    /// The line as written (cleaned for display, comment kept).
    pub text: String,
}

/// The hosts file's lines: address, then names; `#` starts a comment; blank and broken lines
/// skipped. IPv6 lines and zone ids (`fe80::1%12`) included.
pub fn parse_hosts(text: &str) -> Vec<HostsLine> {
    let mut out = Vec::new();
    for (i, line) in text.trim_start_matches('\u{FEFF}').lines().enumerate() {
        let body = line.split('#').next().unwrap_or("");
        let mut f = body.split_whitespace();
        let Some(addr) = f.next() else { continue };
        let Ok(ip) = addr.split('%').next().unwrap_or(addr).parse::<IpAddr>() else { continue };
        let names: Vec<String> = f.map(|n| n.trim_end_matches('.').to_ascii_lowercase()).filter(|n| !n.is_empty()).collect();
        if names.is_empty() {
            continue;
        }
        out.push(HostsLine { number: i + 1, ip, names, text: text::clean(&line.replace('\t', " "), 200) });
    }
    out
}

/// The hosts lines Windows answers this question from: the name (any case, no trailing dot)
/// for A and AAAA, the address for a PTR question. Other types never come from the hosts file.
pub fn hosts_match<'a>(lines: &'a [HostsLine], name: &str, qtype: u16, ptr_of: Option<IpAddr>) -> Vec<&'a HostsLine> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    match qtype {
        query::A | query::AAAA => lines.iter().filter(|l| l.names.contains(&n)).collect(),
        query::PTR => ptr_of.map(|ip| lines.iter().filter(|l| l.ip == ip).collect()).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The hosts file's path: `DataBasePath` (expanded) or `%SystemRoot%\System32\drivers\etc`.
pub fn hosts_path() -> Result<PathBuf, String> {
    use windows_sys::Win32::System::Registry::{RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ};
    // The path from its exact UTF-16 units (never through a lossy string: family rule RR-7).
    let dir = reg_value("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "DataBasePath", RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ)?;
    let dir = dir.map(|w| {
        let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
        w[..n].to_vec()
    });
    let dir = match dir.filter(|d| d.iter().any(|&c| c != b' ' as u16)) {
        Some(d) => crate::host::path_from_wide(&d),
        None => PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32").join("drivers").join("etc"),
    };
    Ok(dir.join("hosts"))
}

/// The hosts file read (at most 4 MiB): Ok(None) when there is none, Err when it is there but
/// cannot be read (the reason is then unknown, never "not in the hosts file").
pub fn read_hosts() -> Result<Option<(PathBuf, Vec<HostsLine>)>, String> {
    use std::io::Read;
    let path = hosts_path()?;
    let f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("The hosts file could not be read ({e}).")),
    };
    let mut b = Vec::new();
    f.take(4 << 20).read_to_end(&mut b).map_err(|e| format!("The hosts file could not be read ({e})."))?;
    Ok(Some((path, parse_hosts(&String::from_utf8_lossy(&b)))))
}

// ---------- NRPT ----------

/// One Name Resolution Policy Table rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NrptRule {
    /// The rule's key ("{GUID}" or a name).
    pub key: String,
    /// Namespaces: ".corp.example" (a suffix), "host.example" (one name), "." (everything).
    pub names: Vec<String>,
    /// `GenericDNSServers` ("10.0.0.1;10.0.0.2"), empty when the rule names none.
    pub servers: String,
}

/// The rule that applies to `name`: the longest matching namespace wins. A suffix rule
/// (".corp.example") covers the name itself and everything below; "." covers every name.
pub fn nrpt_match<'a>(rules: &'a [NrptRule], name: &str) -> Option<(&'a NrptRule, &'a str)> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let mut best: Option<(&NrptRule, &str, usize)> = None;
    for r in rules {
        for ns in &r.names {
            let s = ns.trim().to_ascii_lowercase();
            let len = s.trim_matches('.').len();
            let hit = if s == "." {
                true
            } else if let Some(suffix) = s.strip_prefix('.') {
                let suffix = suffix.trim_end_matches('.');
                !suffix.is_empty() && (n == suffix || n.ends_with(&format!(".{suffix}")))
            } else {
                n == s.trim_end_matches('.')
            };
            if hit && best.is_none_or(|(_, _, l)| len > l) {
                best = Some((r, ns.as_str(), len));
            }
        }
    }
    best.map(|(r, ns, _)| (r, ns))
}

const NRPT_KEYS: [&str; 2] = ["SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig", "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig"];

/// Every NRPT rule (group policy's and local ones). Err when a key cannot be read: the reason
/// is then unknown, never "no rule".
pub fn read_nrpt() -> Result<Vec<NrptRule>, String> {
    let mut out = Vec::new();
    for base in NRPT_KEYS {
        for sub in reg_subkeys(base)? {
            let path = format!("{base}\\{sub}");
            let names = reg_multi(&path, "Name")?.unwrap_or_default();
            let servers = reg_string(&path, "GenericDNSServers")?.unwrap_or_default();
            out.push(NrptRule { key: text::clean(&sub, 80), names: names.iter().map(|n| text::clean(n, 255)).collect(), servers: text::clean(&servers, 200) });
        }
    }
    Ok(out)
}

// ---------- Windows' DoH ----------

/// DoH templates Windows uses for a server address (per interface, `GetInterfaceDnsSettings`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DohSetting {
    pub server: IpAddr,
    pub template: String,
}

/// The DoH templates of an interface (its GUID as "{...}"). Err when the call fails.
pub fn doh_settings(guid_text: &str) -> Result<Vec<DohSetting>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    let guid = parse_guid(guid_text).ok_or("not an interface GUID")?;
    let mut s = DNS_INTERFACE_SETTINGS3 { Version: DNS_INTERFACE_SETTINGS_VERSION3, ..Default::default() };
    // SAFETY: a version-3 settings struct (the version field says which); freed below.
    let r = unsafe { GetInterfaceDnsSettings(guid, (&mut s as *mut DNS_INTERFACE_SETTINGS3).cast()) };
    if r != 0 {
        return Err(format!("Windows' DNS settings could not be read ({}).", std::io::Error::from_raw_os_error(r as i32)));
    }
    let mut out = Vec::new();
    // SAFETY: the strings and the property array GetInterfaceDnsSettings filled in.
    unsafe {
        let servers: Vec<IpAddr> = wstr(s.NameServer).split([',', ' ', ';']).filter_map(|x| x.trim().parse().ok()).collect();
        if !s.ServerProperties.is_null() {
            for p in std::slice::from_raw_parts(s.ServerProperties, s.cServerProperties as usize) {
                if p.Type == DnsServerDohProperty && !p.Property.DohSettings.is_null() {
                    let t = wstr((*p.Property.DohSettings).Template);
                    if let Some(ip) = servers.get(p.ServerIndex as usize)
                        && !t.is_empty()
                    {
                        out.push(DohSetting { server: *ip, template: text::clean(&t, 200) });
                    }
                }
            }
        }
        FreeInterfaceDnsSettings((&mut s as *mut DNS_INTERFACE_SETTINGS3).cast());
    }
    Ok(out)
}

/// "{6B29FC40-CA47-1067-B31D-00DD010662DA}" as a GUID.
pub fn parse_guid(s: &str) -> Option<windows_sys::core::GUID> {
    let h: String = s.trim().trim_start_matches('{').trim_end_matches('}').chars().filter(|c| *c != '-').collect();
    if h.len() != 32 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let b = |i: usize, n: usize| u64::from_str_radix(&h[i..i + n], 16).ok();
    let mut d4 = [0u8; 8];
    for (k, x) in d4.iter_mut().enumerate() {
        *x = b(16 + 2 * k, 2)? as u8;
    }
    Some(windows_sys::core::GUID { data1: b(0, 8)? as u32, data2: b(8, 4)? as u16, data3: b(12, 4)? as u16, data4: d4 })
}

// ---------- why Windows differs ----------

/// What the app knows about Windows' side, read once per query (on a worker).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    /// The hosts file: Ok(None) none, Err unreadable.
    pub hosts: Result<Option<(PathBuf, Vec<HostsLine>)>, String>,
    pub nrpt: Result<Vec<NrptRule>, String>,
    pub doh: Result<Vec<DohSetting>, String>,
    /// The search suffixes Windows adds to a single label (adapters' and global).
    pub suffixes: Vec<String>,
}

impl Default for Context {
    fn default() -> Self {
        Context { hosts: Ok(None), nrpt: Ok(Vec::new()), doh: Ok(Vec::new()), suffixes: Vec::new() }
    }
}

/// The reason Windows' answer differs, when knowable; in this order: the hosts file, an NRPT
/// rule, suffix search, Windows' DoH. A source that could not be read makes the reason unknown
/// (said so), never "no rule".
pub fn reason(ctx: &Context, q: &query::Question) -> String {
    let name = q.windows_name().unwrap_or_else(|| q.name_text());
    let mut unknown = Vec::new();
    match &ctx.hosts {
        Ok(Some((path, lines))) => {
            if let Some(l) = hosts_match(lines, &name, q.qtype, q.ptr_of).first() {
                return format!("hosts file: line {} of {}: {}", l.number, text::shown_path(path), l.text);
            }
        }
        Ok(None) => {}
        Err(_) => unknown.push("the hosts file"),
    }
    match &ctx.nrpt {
        Ok(rules) => {
            if let Some((r, ns)) = nrpt_match(rules, &name) {
                let servers = if r.servers.is_empty() { "no DNS servers of its own".to_string() } else { format!("DNS servers {}", r.servers) };
                return format!("NRPT: rule {} for “{ns}” sends this name to {servers}", r.key);
            }
        }
        Err(_) => unknown.push("the NRPT rules"),
    }
    if q.single_label {
        let s = if ctx.suffixes.is_empty() { String::new() } else { format!(" ({})", ctx.suffixes.join(", ")) };
        return format!("suffix search: a single label, so Windows asked it with its search suffixes{s}");
    }
    match &ctx.doh {
        Ok(d) if !d.is_empty() => {
            let list: Vec<String> = d.iter().map(|x| format!("{} over {}", x.server, x.template)).collect();
            return format!("Windows DoH: Windows asks {}", list.join(", "));
        }
        Ok(_) => {}
        Err(_) => unknown.push("Windows' DoH settings"),
    }
    if unknown.is_empty() {
        "reason not known (Windows may have used another adapter's server or its cache)".into()
    } else {
        format!("reason unknown ({} could not be read)", unknown.join(" and "))
    }
}

/// The search suffixes: the global SearchList, else each adapter's own suffix.
pub fn search_list() -> Vec<String> {
    let global = reg_string("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "SearchList").ok().flatten().unwrap_or_default();
    global.split([',', ' ']).filter(|s| !s.is_empty()).map(|s| text::clean(s, 255)).collect()
}
