//! POST `/api/check` — domain availability across the 12 supported TLDs.
//!
//! Port of the Hono handler in `backend/server.ts`: WHOIS on port 43, RDAP
//! over HTTPS for `.dev`/`.app`, DNS fallback. Bounded per-IP sliding window
//! (30 / 60s). Zero crates: `TcpStream` for WHOIS, system `curl` for RDAP
//! (already in the runtime image), `ToSocketAddrs` for DNS.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
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

fn check_dns(fqdn: &str) -> Outcome {
    let taken = (fqdn, 80u16)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .is_some();
    if taken {
        Outcome {
            available: Some(false),
            status: "taken",
            method: "dns",
        }
    } else {
        Outcome {
            available: Some(true),
            status: "available",
            method: "dns",
        }
    }
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
}
