//! How DNS data is written down: dig's presentation format (names escaped so a hostile label can
//! never pass for another name), the encodings DNSSEC data uses (hex, base64, base32hex), times,
//! and the cleaner for any other text from outside (adapter names, HTTP reasons, server errors).

/// Characters that change how the text around them reads without showing themselves: controls,
/// bidirectional embeddings, overrides, isolates and marks, zero-width spaces and line
/// separators, the soft hyphen and the Unicode tag characters (U+E0000..U+E007F); the template's
/// set. The joiners U+200C (ZWNJ) and U+200D (ZWJ) are not among them: emoji sequences and
/// Persian, Arabic and Indic names need them (family rule, 2026-10-20).
pub fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}')
}

/// Text from outside (an adapter's name, an HTTP reason phrase, a hosts line) as it may be
/// shown: no controls, no bidi or invisible characters, at most `max` characters, trimmed.
pub fn clean(s: &str, max: usize) -> String {
    let t: String = s.chars().filter(|c| !invisible(*c)).take(max).collect();
    t.trim().to_string()
}

/// Outside text as it may be shown: invisible characters gone, runs of whitespace (a newline
/// or tab included) one space, trimmed, at most `max` characters (an ellipsis marks a cut). The
/// template's `text::clean_max`, for About's install check (a signer's name, a reason).
pub fn clean_max(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max * 4));
    let mut space = false;
    let mut n = 0usize;
    let mut cut = false;
    for c in s.chars() {
        if c.is_whitespace() || c == '\u{2028}' || c == '\u{2029}' {
            space = !out.is_empty();
            continue;
        }
        if invisible(c) {
            continue;
        }
        if space {
            if n + 1 >= max {
                cut = true;
                break;
            }
            out.push(' ');
            n += 1;
            space = false;
        }
        if n >= max {
            cut = true;
            break;
        }
        out.push(c);
        n += 1;
    }
    if cut {
        // Room for the ellipsis: drop the last character (never a byte: chars only).
        out.pop();
        out.push('…');
    }
    out
}

/// UTF-16 from Windows as shown text: a lone surrogate becomes U+FFFD, then cleaned.
pub fn clean_wide(w: &[u16], max: usize) -> String {
    clean_max(&String::from_utf16_lossy(w), max)
}

/// A path as shown: a lone surrogate becomes U+FFFD, invisible characters go (the raw path is
/// what Windows gets).
pub fn shown_path(p: &std::path::Path) -> String {
    clean(&p.to_string_lossy(), 2048)
}

/// One label as dig writes it: printable ASCII as is, dig's special characters behind a
/// backslash (`.` `\` `"` `(` `)` `;` `@` `$`), every other byte (space, controls, UTF-8) as
/// `\DDD`. A label with a dot or a bidi override inside can never read as another name.
pub fn label(l: &[u8]) -> String {
    let mut s = String::with_capacity(l.len());
    for &b in l {
        match b {
            b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$' => {
                s.push('\\');
                s.push(b as char);
            }
            0x21..=0x7E => s.push(b as char),
            _ => s.push_str(&format!("\\{b:03}")),
        }
    }
    s
}

/// A name as dig writes it: absolute, with the trailing dot ("." for the root).
pub fn name(labels: &[Vec<u8>]) -> String {
    if labels.is_empty() {
        return ".".into();
    }
    let mut s = String::new();
    for l in labels {
        s.push_str(&label(l));
        s.push('.');
    }
    s
}

/// A character-string (TXT, CAA value) in quotes: `"` and `\` behind a backslash, readable
/// UTF-8 as itself, and every byte that would hide, reorder or break the line (controls, bidi
/// controls, zero-width characters, invalid UTF-8, DEL) as `\DDD`, so it is seen, never obeyed.
pub fn char_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() + 2);
    s.push('"');
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x80 {
            match b {
                b'"' | b'\\' => {
                    s.push('\\');
                    s.push(b as char);
                }
                0x20..=0x7E => s.push(b as char),
                _ => s.push_str(&format!("\\{b:03}")),
            }
            i += 1;
            continue;
        }
        // A UTF-8 sequence: shown when it decodes to a visible character.
        let n = match b {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => 1,
        };
        let seq = &bytes[i..(i + n).min(bytes.len())];
        match std::str::from_utf8(seq).ok().and_then(|t| t.chars().next()) {
            Some(c) if seq.len() == n && !invisible(c) => {
                s.push(c);
                i += n;
            }
            _ => {
                s.push_str(&format!("\\{b:03}"));
                i += 1;
            }
        }
    }
    s.push('"');
    s
}

pub fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

pub fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_with(data: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.len();
        let v = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            if k <= n {
                out.push(table[(v >> (18 - 6 * k) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Base64 (RFC 4648 section 4, padded): DNSKEY keys, RRSIG signatures, ECH configs.
pub fn base64(data: &[u8]) -> String {
    b64_with(data, B64, true)
}

/// Base64url without padding (RFC 8484 section 4.1): the `dns` parameter of a DoH GET.
pub fn base64url(data: &[u8]) -> String {
    b64_with(data, B64URL, false)
}

/// Base32 with the extended hex alphabet, no padding (RFC 4648 section 7, RFC 5155): NSEC3's
/// next hashed owner.
pub fn base32hex(data: &[u8]) -> String {
    const T: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(T[(acc >> bits & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(T[(acc << (5 - bits) & 31) as usize] as char);
    }
    out
}

/// The mnemonic of a record type, `TYPE<n>` for the rest (RFC 3597).
pub fn type_name(t: u16) -> String {
    let n = match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        25 => "KEY",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        37 => "CERT",
        39 => "DNAME",
        41 => "OPT",
        43 => "DS",
        44 => "SSHFP",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        108 => "EUI48",
        109 => "EUI64",
        256 => "URI",
        257 => "CAA",
        _ => return format!("TYPE{t}"),
    };
    n.to_string()
}

/// A record type from its mnemonic (or `TYPE<n>`), any case.
pub fn type_code(name: &str) -> Option<u16> {
    let up = name.trim().to_ascii_uppercase();
    if let Some(n) = up.strip_prefix("TYPE") {
        return n.parse().ok();
    }
    KNOWN_TYPES.iter().copied().find(|t| type_name(*t) == up)
}

const KNOWN_TYPES: [u16; 39] = [1, 2, 5, 6, 12, 13, 15, 16, 17, 18, 25, 28, 29, 33, 35, 37, 39, 41, 43, 44, 46, 47, 48, 50, 51, 52, 53, 59, 60, 61, 62, 63, 64, 65, 99, 108, 109, 256, 257];

pub fn class_name(c: u16) -> String {
    match c {
        1 => "IN".into(),
        3 => "CH".into(),
        4 => "HS".into(),
        254 => "NONE".into(),
        255 => "ANY".into(),
        _ => format!("CLASS{c}"),
    }
}

/// An RCODE by name (extended ones too), `RCODE<n>` for the rest.
pub fn rcode_name(r: u16) -> String {
    let n = match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADVERS",
        23 => "BADCOOKIE",
        _ => return format!("RCODE{r}"),
    };
    n.to_string()
}

/// Extended DNS Error info codes (RFC 8914 and its registry).
pub fn ede_name(code: u16) -> String {
    let n = match code {
        0 => "Other",
        1 => "Unsupported DNSKEY Algorithm",
        2 => "Unsupported DS Digest Type",
        3 => "Stale Answer",
        4 => "Forged Answer",
        5 => "DNSSEC Indeterminate",
        6 => "DNSSEC Bogus",
        7 => "Signature Expired",
        8 => "Signature Not Yet Valid",
        9 => "DNSKEY Missing",
        10 => "RRSIGs Missing",
        11 => "No Zone Key Bit Set",
        12 => "NSEC Missing",
        13 => "Cached Error",
        14 => "Not Ready",
        15 => "Blocked",
        16 => "Censored",
        17 => "Filtered",
        18 => "Prohibited",
        19 => "Stale NXDOMAIN Answer",
        20 => "Not Authoritative",
        21 => "Not Supported",
        22 => "No Reachable Authority",
        23 => "Network Error",
        24 => "Invalid Data",
        25 => "Signature Expired before Valid",
        26 => "Too Early",
        27 => "Unsupported NSEC3 Iterations Value",
        28 => "Unable to conform to policy",
        29 => "Synthesized",
        30 => "Invalid Query Type",
        _ => return format!("EDE {code}"),
    };
    n.to_string()
}

/// Unix seconds as UTC "YYYYMMDDHHMMSS" (RRSIG's inception and expiration).
pub fn utc_stamp(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}")
}

/// Unix seconds to (year, month, day, hour, minute, second), UTC (Howard Hinnant's algorithm).
pub fn civil(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d, (rem / 3600) as u32, (rem / 60 % 60) as u32, (rem % 60) as u32)
}

/// A round trip: "8.4 ms" (one decimal under 10 ms), "23 ms", "1 204 ms" is "1204 ms".
pub fn ms(v: f64) -> String {
    let tenths = (v * 10.0).round() / 10.0;
    if tenths < 10.0 { format!("{tenths:.1} ms") } else { format!("{:.0} ms", v.round()) }
}

/// A TTL as dig writes it (seconds), and in words for a tooltip ("1 h 5 min").
pub fn ttl_words(s: u32) -> String {
    let (d, h, m, sec) = (s / 86_400, s / 3600 % 24, s / 60 % 60, s % 60);
    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d} d"));
    }
    if h > 0 {
        parts.push(format!("{h} h"));
    }
    if m > 0 {
        parts.push(format!("{m} min"));
    }
    if sec > 0 || parts.is_empty() {
        parts.push(format!("{sec} s"));
    }
    parts.join(" ")
}

/// "1 answer", "3 answers".
pub fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}
