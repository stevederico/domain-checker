//! POST `/api/check` — domain availability across the 12 supported TLDs.
//!
//! Port of the Hono handler in `backend/server.ts`: WHOIS on port 43, RDAP
//! over HTTPS for `.dev`/`.app`, DNS fallback. Bounded per-IP sliding window
//! (30 / 60s). Zero crates: `TcpStream` for WHOIS, system `curl` for RDAP
//! (already in the runtime image), UDP DNS to the system resolver for A/AAAA/NS.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use crate::http::{Request, Response};
use crate::json::{self, Json};
use crate::stores::evict_oldest_entries;

/// Sliding window for `/api/check`.
const CHECK_RATE_LIMIT: usize = 30;
const CHECK_RATE_WINDOW_MS: i64 = 60 * 1000;
const CHECK_RATE_MAX_ENTRIES: usize = 10_000;

const WHOIS_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-query budget for the DNS fallback. Three record types run in parallel.
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_NS: u16 = 2;
const DNS_QTYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;

/// WHOIS host per TLD. `.dev`/`.app` have none (RDAP only).
const WHOIS_SERVERS: &[(&str, &str)] = &[
    ("com", "whois.verisign-grs.com"),
    ("net", "whois.verisign-grs.com"),
    ("org", "whois.pir.org"),
    ("io", "whois.nic.io"),
    ("co", "whois.registry.co"),
    ("xyz", "whois.nic.xyz"),
    ("ai", "whois.nic.ai"),
    ("shop", "whois.nic.shop"),
    ("site", "whois.nic.site"),
    ("tech", "whois.nic.tech"),
];

/// RDAP base URL per TLD (Google registry). Path is the FQDN.
const RDAP_SERVERS: &[(&str, &str)] = &[
    ("dev", "https://pubapi.registry.google/rdap/domain/"),
    ("app", "https://pubapi.registry.google/rdap/domain/"),
];

const SUPPORTED_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "app", "co", "xyz", "ai", "shop", "site", "tech",
];

const WHOIS_AVAILABLE: &[&str] = &[
    "no match",
    "not found",
    "no data found",
    "no entries found",
    "no object found",
    "status: free",
    "status: available",
    "is available",
    "domain not found",
];

const WHOIS_TAKEN: &[&str] = &[
    "domain name:",
    "registrar:",
    "creation date:",
    "registry domain",
    "registered on:",
    "nserver:",
    "name server:",
];

/// Per-IP sliding window for `/api/check`.
#[derive(Default)]
pub struct CheckRateStore {
    inner: Mutex<HashMap<String, Vec<i64>>>,
}

impl CheckRateStore {
    /// Empty store.
    pub fn new() -> CheckRateStore {
        CheckRateStore {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Record one request. `limited` means this one is refused and not stored.
    pub fn check_and_record(&self, ip: &str, now_ms: i64) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let window_start = now_ms - CHECK_RATE_WINDOW_MS;
        if !map.contains_key(ip) && map.len() >= CHECK_RATE_MAX_ENTRIES {
            evict_oldest_entries(&mut map, CHECK_RATE_MAX_ENTRIES.saturating_sub(1), |times| {
                times.first().copied().unwrap_or(0)
            });
        }
        let times = map.entry(ip.to_string()).or_default();
        times.retain(|&t| t > window_start);
        if times.len() >= CHECK_RATE_LIMIT {
            return true;
        }
        times.push(now_ms);
        false
    }
}

/// Dispatch POST `/api/check`.
pub fn handle(req: &Request, ip: &str, rate: &CheckRateStore) -> Response {
    let name = match parse_domain_name(req) {
        Ok(n) => n,
        Err(res) => return res,
    };
    if rate.check_and_record(ip, crate::config::now_ms()) {
        return err_json(429, "Rate limit exceeded. Try again shortly.");
    }
    let mut results = check_all(&name);
    results.sort_by_key(|r| match r.available {
        Some(true) => 0,
        Some(false) => 1,
        None => 2,
    });
    json_res(200, &Json::Arr(results.into_iter().map(CheckResult::to_json).collect()))
        .set_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
        .set_header("Pragma", "no-cache")
}

fn parse_domain_name(req: &Request) -> Result<String, Response> {
    let body = json::parse(&req.body).map_err(|_| err_json(400, "Invalid JSON body"))?;
    let Some(raw) = body.get_str("domain").filter(|s| !s.is_empty()) else {
        return Err(err_json(400, "Missing domain in request body"));
    };
    let name = raw.to_ascii_lowercase().replace(|c: char| c.is_ascii_whitespace(), "");
    if !valid_label(&name) {
        return Err(err_json(
            400,
            "Invalid domain name. Use alphanumeric characters and hyphens only.",
        ));
    }
    Ok(name)
}

fn valid_label(name: &str) -> bool {
    let n = name.len();
    if n == 0 || n > 63 {
        return false;
    }
    let b = name.as_bytes();
    b[0].is_ascii_alphanumeric()
        && b[n - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

struct CheckResult {
    tld: String,
    domain: String,
    available: Option<bool>,
    status: String,
    method: String,
}

impl CheckResult {
    fn to_json(self) -> Json {
        json::obj([
            ("tld", json::s(self.tld)),
            ("domain", json::s(self.domain)),
            (
                "available",
                match self.available {
                    Some(v) => Json::Bool(v),
                    None => Json::Null,
                },
            ),
            ("status", json::s(self.status)),
            ("method", json::s(self.method)),
        ])
    }
}

fn check_all(name: &str) -> Vec<CheckResult> {
    thread::scope(|s| {
        let handles: Vec<_> = SUPPORTED_TLDS
            .iter()
            .map(|tld| s.spawn(|| check_one(tld, name)))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| CheckResult {
                    tld: "unknown".into(),
                    domain: String::new(),
                    available: None,
                    status: "error".into(),
                    method: "none".into(),
                })
            })
            .collect()
    })
}

fn check_one(tld: &str, name: &str) -> CheckResult {
    let fqdn = format!("{name}.{tld}");
    if let Some(base) = rdap_base(tld) {
        if let Some(out) = check_rdap(base, &fqdn) {
            return out.into_result(tld, &fqdn);
        }
    }
    if let Some(server) = whois_server(tld) {
        if let Some(out) = check_whois(server, &fqdn) {
            return out.into_result(tld, &fqdn);
        }
    }
    check_dns(&fqdn).into_result(tld, &fqdn)
}

struct Outcome {
    available: Option<bool>,
    status: &'static str,
    method: &'static str,
}

impl Outcome {
    fn into_result(self, tld: &str, fqdn: &str) -> CheckResult {
        CheckResult {
            tld: tld.to_string(),
            domain: fqdn.to_string(),
            available: self.available,
            status: self.status.to_string(),
            method: self.method.to_string(),
        }
    }
}

fn whois_server(tld: &str) -> Option<&'static str> {
    WHOIS_SERVERS.iter().find(|(k, _)| *k == tld).map(|(_, s)| *s)
}

fn rdap_base(tld: &str) -> Option<&'static str> {
    RDAP_SERVERS.iter().find(|(k, _)| *k == tld).map(|(_, s)| *s)
}

fn parse_whois(body: &str) -> Outcome {
    let lower = body.to_ascii_lowercase();
    if WHOIS_TAKEN.iter().any(|p| lower.contains(p)) {
        return Outcome {
            available: Some(false),
            status: "taken",
            method: "whois",
        };
    }
    if WHOIS_AVAILABLE.iter().any(|p| lower.contains(p)) {
        return Outcome {
            available: Some(true),
            status: "available",
            method: "whois",
        };
    }
    Outcome {
        available: None,
        status: "whois-unclear",
        method: "whois",
    }
}

fn check_whois(server: &str, fqdn: &str) -> Option<Outcome> {
    let addr = (server, 43u16).to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&addr, WHOIS_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(WHOIS_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(WHOIS_TIMEOUT)).ok()?;
    write!(stream, "{fqdn}\r\n").ok()?;
    let mut body = String::new();
    stream.read_to_string(&mut body).ok()?;
    Some(parse_whois(&body))
}

fn check_rdap(base: &str, fqdn: &str) -> Option<Outcome> {
    let url = format!("{base}{fqdn}");
    let output = Command::new("curl")
        .args([
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-m",
            "5",
            "--max-redirs",
            "0",
            "-H",
            "Accept: application/rdap+json",
            "-A",
            "Domain-Checker/1.0",
            &url,
        ])
        .output()
        .ok()?;
    let code: u16 = std::str::from_utf8(&output.stdout).ok()?.parse().ok()?;
    match code {
        404 => Some(Outcome {
            available: Some(true),
            status: "available",
            method: "rdap",
        }),
        200 => Some(Outcome {
            available: Some(false),
            status: "taken",
            method: "rdap",
        }),
        _ => None,
    }
}

/// One DNS answer class. Maps the Node `dns.promises.resolve` outcomes the
/// Hono fallback treated as records, nonexistence, or inconclusive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DnsKind {
    Found,
    NxDomain,
    NoData,
    ServFail,
    Refused,
    Other,
}

/// Collapse A, AAAA, and NS outcomes the way the Hono handler behaved.
///
/// Any answer section means taken, including NS-only names. `NXDOMAIN`
/// (`ENOTFOUND`) means likely available. Empty answers are `ENODATA` in Node,
/// and the old set listed `NODATA`, so those stayed inconclusive rather than
/// free. A dead resolver stays inconclusive for the same reason.
fn dns_outcome(kinds: [DnsKind; 3]) -> Outcome {
    if kinds.iter().any(|kind| *kind == DnsKind::Found) {
        return Outcome {
            available: Some(false),
            status: "taken",
            method: "dns",
        };
    }
    if kinds.iter().any(|kind| *kind == DnsKind::NxDomain) {
        return Outcome {
            available: Some(true),
            status: "available",
            method: "dns",
        };
    }
    Outcome {
        available: None,
        status: "dns-inconclusive",
        method: "dns",
    }
}

fn dns_error() -> Outcome {
    Outcome {
        available: None,
        status: "dns-error",
        method: "dns",
    }
}

fn classify_reply(rcode: u8, ancount: u16) -> DnsKind {
    match rcode {
        0 if ancount > 0 => DnsKind::Found,
        0 => DnsKind::NoData,
        2 => DnsKind::ServFail,
        3 => DnsKind::NxDomain,
        5 => DnsKind::Refused,
        _ => DnsKind::Other,
    }
}

/// First `nameserver` in a resolv.conf body.
fn first_nameserver(text: &str) -> Option<&str> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let ip = parts.next()?;
        if !ip.is_empty() {
            return Some(ip);
        }
    }
    None
}

fn system_nameserver() -> Option<String> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    first_nameserver(&text).map(str::to_string)
}

fn parse_nameserver(ns: &str) -> Option<SocketAddr> {
    let host = ns.trim();
    if host.is_empty() {
        return None;
    }
    if host.contains(':') {
        let bracketed = if host.starts_with('[') {
            host.to_string()
        } else {
            format!("[{host}]")
        };
        return format!("{bracketed}:53").parse().ok();
    }
    format!("{host}:53").parse().ok()
}

fn encode_qname(fqdn: &str, out: &mut Vec<u8>) -> bool {
    if fqdn.is_empty() || fqdn.len() > 253 {
        return false;
    }
    for label in fqdn.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        // Length is at most 63, which fits in the DNS label-length byte.
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    true
}

fn build_query(id: u16, fqdn: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    if !encode_qname(fqdn, &mut query) {
        return None;
    }
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Some(query)
}

struct DnsHeader {
    rcode: u8,
    ancount: u16,
    truncated: bool,
}

fn parse_dns_header(buf: &[u8], expect_id: u16) -> Option<DnsHeader> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expect_id {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    Some(DnsHeader {
        rcode: (flags & 0x000F) as u8,
        ancount: u16::from_be_bytes([buf[6], buf[7]]),
        truncated: flags & 0x0200 != 0,
    })
}

fn query_id(fqdn: &str, qtype: u16) -> u16 {
    let mut hash: u16 = 0x9E37;
    for byte in fqdn.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u16::from(byte));
    }
    hash ^ qtype ^ (crate::config::now_ms() as u16)
}

fn bind_dns_socket(addr: SocketAddr) -> Option<UdpSocket> {
    let local = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = UdpSocket::bind(local).ok()?;
    sock.set_read_timeout(Some(DNS_TIMEOUT)).ok()?;
    sock.connect(addr).ok()?;
    Some(sock)
}

fn query_record(addr: SocketAddr, fqdn: &str, qtype: u16) -> DnsKind {
    let id = query_id(fqdn, qtype);
    let packet = match build_query(id, fqdn, qtype) {
        Some(packet) => packet,
        None => return DnsKind::Other,
    };
    let sock = match bind_dns_socket(addr) {
        Some(sock) => sock,
        None => return DnsKind::Other,
    };
    if sock.send(&packet).is_err() {
        return DnsKind::Other;
    }
    let mut buf = [0u8; 512];
    let size = match sock.recv(&mut buf) {
        Ok(size) => size,
        Err(_) => return DnsKind::Other,
    };
    match parse_dns_header(&buf[..size], id) {
        Some(header) if header.truncated => DnsKind::Other,
        Some(header) => classify_reply(header.rcode, header.ancount),
        None => DnsKind::Other,
    }
}

fn check_dns(fqdn: &str) -> Outcome {
    let Some(server) = system_nameserver() else {
        return dns_error();
    };
    let Some(addr) = parse_nameserver(&server) else {
        return dns_error();
    };
    let kinds = thread::scope(|scope| {
        let mut joins = Vec::with_capacity(3);
        for qtype in [DNS_QTYPE_A, DNS_QTYPE_AAAA, DNS_QTYPE_NS] {
            let name = fqdn.to_string();
            joins.push(scope.spawn(move || query_record(addr, &name, qtype)));
        }
        let mut out = [DnsKind::Other; 3];
        for (index, join) in joins.into_iter().enumerate() {
            out[index] = join.join().unwrap_or(DnsKind::Other);
        }
        out
    });
    dns_outcome(kinds)
}

fn json_res(status: u16, v: &Json) -> Response {
    Response::json(status, &json::stringify(v))
}

fn err_json(status: u16, msg: &str) -> Response {
    json_res(status, &json::obj([("error", json::s(msg))]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_label_accepts_simple_names() {
        assert!(valid_label("a"));
        assert!(valid_label("example"));
        assert!(valid_label("my-app"));
    }

    #[test]
    fn valid_label_rejects_junk() {
        assert!(!valid_label(""));
        assert!(!valid_label("-a"));
        assert!(!valid_label("a-"));
        assert!(!valid_label(&"a".repeat(64)));
        assert!(!valid_label("ex ample"));
    }

    #[test]
    fn whois_taken_beats_available_disclaimer() {
        let body = "Domain Name: EXAMPLE.COM\nRegistrar: Example\nThis domain is available through...";
        let out = parse_whois(body);
        assert_eq!(out.available, Some(false));
        assert_eq!(out.status, "taken");
    }

    #[test]
    fn whois_no_match_is_available() {
        let out = parse_whois("No match for domain \"foo.com\".");
        assert_eq!(out.available, Some(true));
        assert_eq!(out.status, "available");
    }

    #[test]
    fn rate_store_trips_at_thirty() {
        let store = CheckRateStore::new();
        for _ in 0..30 {
            assert!(!store.check_and_record("1.1.1.1", 1_000));
        }
        assert!(store.check_and_record("1.1.1.1", 1_000));
        assert!(!store.check_and_record("2.2.2.2", 1_000));
    }

    #[test]
    fn missing_domain_is_400() {
        let rate = CheckRateStore::new();
        let mut req = Request::for_test("POST", "/api/check");
        req.set_test_body(br#"{"nope":true}"#.to_vec());
        let res = handle(&req, "0.0.0.0", &rate);
        assert_eq!(res.status, 400);
    }

    #[test]
    fn invalid_json_is_400() {
        let rate = CheckRateStore::new();
        let mut req = Request::for_test("POST", "/api/check");
        req.set_test_body(b"not-json".to_vec());
        let res = handle(&req, "0.0.0.0", &rate);
        assert_eq!(res.status, 400);
    }

    #[test]
    fn dns_records_are_taken() {
        let out = dns_outcome([DnsKind::NoData, DnsKind::NoData, DnsKind::Found]);
        assert_eq!(out.available, Some(false));
        assert_eq!(out.status, "taken");
    }

    #[test]
    fn dns_nxdomain_is_available() {
        let out = dns_outcome([DnsKind::NxDomain, DnsKind::Other, DnsKind::ServFail]);
        assert_eq!(out.available, Some(true));
        assert_eq!(out.status, "available");
    }

    #[test]
    fn dns_all_nodata_is_inconclusive() {
        let out = dns_outcome([DnsKind::NoData, DnsKind::NoData, DnsKind::NoData]);
        assert_eq!(out.available, None);
        assert_eq!(out.status, "dns-inconclusive");
    }

    #[test]
    fn dns_mixed_failure_is_inconclusive() {
        let out = dns_outcome([DnsKind::NoData, DnsKind::Other, DnsKind::Refused]);
        assert_eq!(out.available, None);
        assert_eq!(out.status, "dns-inconclusive");
    }

    #[test]
    fn nameserver_skips_comments() {
        let text = "# comment\noptions timeout:1\nnameserver 127.0.0.53\n";
        assert_eq!(first_nameserver(text), Some("127.0.0.53"));
    }

    #[test]
    fn dns_header_nxdomain_with_no_answers() {
        let mut buf = vec![0x12, 0x34, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
        let header = parse_dns_header(&buf, 0x1234).unwrap();
        assert!(header.rcode == 3 && header.ancount == 0 && !header.truncated);
        assert_eq!(classify_reply(header.rcode, header.ancount), DnsKind::NxDomain);
        buf[2] = 0x01;
        assert!(parse_dns_header(&buf, 0x1234).is_none());
    }

    #[test]
    fn build_query_rejects_empty_labels() {
        assert!(build_query(1, "example.com", DNS_QTYPE_A).is_some());
        assert!(build_query(1, "foo..com", DNS_QTYPE_NS).is_none());
    }
}
