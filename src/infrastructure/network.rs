use crate::domain::route::PROXY_VARS;
use crate::infrastructure::platform;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Explicit routing for one request. `Direct` ignores ambient proxy variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Direct,
    Proxy(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    ToolMissing,
    Refused,
    Timeout,
    Dns,
    Tls,
    EmptyReply,
    Other(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub outcome: std::result::Result<Response, NetError>,
    pub elapsed_ms: u128,
}

/// What an HTTP status means to the caller. Used to word results, never to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpClass {
    Success,
    Authentication,
    RateLimited,
    NotFound,
    Server,
    Other,
}

pub fn classify_status(status: u16) -> HttpClass {
    match status {
        200..=299 => HttpClass::Success,
        401 | 403 => HttpClass::Authentication,
        429 => HttpClass::RateLimited,
        404 => HttpClass::NotFound,
        500..=599 => HttpClass::Server,
        _ => HttpClass::Other,
    }
}

/// Maps curl exit codes to typed failures. HTTP status codes are returned as responses.
pub fn classify_exit(code: i32) -> NetError {
    match code {
        6 => NetError::Dns,
        7 => NetError::Refused,
        28 => NetError::Timeout,
        35 | 51 | 58 | 60 | 77 => NetError::Tls,
        52 | 56 => NetError::EmptyReply,
        other => NetError::Other(other),
    }
}

/// Splits curl output written as `<body>\n<http_code>`.
pub fn parse_output(stdout: &str) -> Option<Response> {
    let (body, code) = stdout.rsplit_once('\n')?;
    let status = code.trim().parse::<u16>().ok()?;
    Some(Response {
        status,
        body: body.to_string(),
    })
}

pub fn fetch(route: &Route, url: &str, timeout_secs: u64) -> Probe {
    let started = Instant::now();
    let timeout = timeout_secs.to_string();
    let mut cmd = Command::new(platform::curl_program());
    // -q must come first: it stops a user's .curlrc from weakening TLS or adding a proxy.
    cmd.args([
        "-q",
        "-sS",
        "--max-time",
        &timeout,
        "--connect-timeout",
        &timeout,
    ])
    .args(["-w", "\n%{http_code}"]);
    match route {
        Route::Direct => {
            cmd.args(["--noproxy", "*"]);
        }
        Route::Proxy(proxy) => {
            cmd.args(["-x", proxy.as_str()]);
        }
    }
    cmd.arg(url).stdin(Stdio::null());
    for name in PROXY_VARS {
        cmd.env_remove(name);
    }
    let outcome = match cmd.output() {
        Err(_) => Err(NetError::ToolMissing),
        Ok(out) if out.status.success() => {
            parse_output(&String::from_utf8_lossy(&out.stdout)).ok_or(NetError::EmptyReply)
        }
        Ok(out) => Err(classify_exit(out.status.code().unwrap_or(-1))),
    };
    let elapsed_ms = started.elapsed().as_millis();
    Probe {
        outcome,
        elapsed_ms,
    }
}

/// Functional check of a Tor SOCKS5 port: the listener must answer a SOCKS5 greeting.
/// A bound port that does not answer SOCKS5 is reported as not functional.
pub fn socks5_greeting(addr: &str) -> std::result::Result<(), String> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| format!("invalid address {addr}"))?;
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(5))
        .map_err(|e| format!("connection failed: {}", e.kind()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("write failed: {}", e.kind()))?;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .map_err(|e| format!("no SOCKS5 reply: {}", e.kind()))?;
    if reply == [0x05, 0x00] {
        Ok(())
    } else {
        Err("listener did not answer as SOCKS5".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// Serves one request with a fixed status line and body, on the given bind address.
    fn serve_on(bind: &str, status_line: &'static str, body: &'static str) -> Option<u16> {
        let listener = TcpListener::bind(bind).ok()?;
        let port = listener.local_addr().ok()?.port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Some(port)
    }

    fn serve(status_line: &'static str, body: &'static str) -> u16 {
        serve_on("127.0.0.1:0", status_line, body).expect("bind loopback")
    }

    #[test]
    fn exit_codes_map_to_typed_failures() {
        assert_eq!(classify_exit(7), NetError::Refused);
        assert_eq!(classify_exit(28), NetError::Timeout);
        assert_eq!(classify_exit(60), NetError::Tls);
        assert_eq!(classify_exit(6), NetError::Dns);
        assert_eq!(classify_exit(52), NetError::EmptyReply);
        assert_eq!(classify_exit(3), NetError::Other(3));
    }

    #[test]
    fn status_classes_are_named_without_retry_advice() {
        assert_eq!(classify_status(200), HttpClass::Success);
        assert_eq!(classify_status(401), HttpClass::Authentication);
        assert_eq!(classify_status(403), HttpClass::Authentication);
        assert_eq!(classify_status(429), HttpClass::RateLimited);
        assert_eq!(classify_status(404), HttpClass::NotFound);
        assert_eq!(classify_status(500), HttpClass::Server);
        assert_eq!(classify_status(302), HttpClass::Other);
    }

    #[test]
    fn output_splits_body_and_status() {
        let r = parse_output("{\"IsTor\":true}\n200").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "{\"IsTor\":true}");
        assert!(parse_output("no newline").is_none());
    }

    #[test]
    fn direct_request_reaches_local_server() {
        let port = serve("200 OK", "1.2.3.4");
        let probe = fetch(&Route::Direct, &format!("http://127.0.0.1:{port}/ip"), 5);
        assert_eq!(
            probe.outcome.unwrap(),
            Response {
                status: 200,
                body: "1.2.3.4".into()
            }
        );
    }

    #[test]
    fn direct_request_works_over_ipv6_loopback_when_available() {
        let Some(port) = serve_on("[::1]:0", "200 OK", "v6") else {
            return;
        };
        let probe = fetch(&Route::Direct, &format!("http://[::1]:{port}/ip"), 5);
        assert_eq!(probe.outcome.unwrap().body, "v6");
    }

    #[test]
    fn proxied_request_goes_through_the_proxy_endpoint() {
        let port = serve("200 OK", "{\"IsTor\":true}");
        let route = Route::Proxy(format!("http://127.0.0.1:{port}"));
        let probe = fetch(&route, "http://check.example/api/ip", 5);
        assert_eq!(probe.outcome.unwrap().body, "{\"IsTor\":true}");
    }

    #[test]
    fn rate_limit_status_is_returned_not_turned_into_a_network_error() {
        let port = serve("429 Too Many Requests", "rate limit");
        let probe = fetch(&Route::Direct, &format!("http://127.0.0.1:{port}/"), 5);
        assert_eq!(probe.outcome.unwrap().status, 429);
    }

    #[test]
    fn authentication_failure_status_is_returned_as_a_response() {
        let port = serve("401 Unauthorized", "no key");
        let probe = fetch(&Route::Direct, &format!("http://127.0.0.1:{port}/"), 5);
        assert_eq!(probe.outcome.unwrap().status, 401);
    }

    #[test]
    fn forbidden_status_is_returned_as_a_response() {
        let port = serve("403 Forbidden", "denied");
        let probe = fetch(&Route::Direct, &format!("http://127.0.0.1:{port}/"), 5);
        assert_eq!(probe.outcome.unwrap().status, 403);
    }

    #[test]
    fn proxy_authentication_required_is_returned_as_a_response() {
        let port = serve("407 Proxy Authentication Required", "");
        let route = Route::Proxy(format!("http://127.0.0.1:{port}"));
        let probe = fetch(&route, "http://check.example/api/ip", 5);
        assert_eq!(probe.outcome.unwrap().status, 407);
    }

    #[test]
    fn server_error_status_is_returned_as_a_response() {
        let port = serve("500 Internal Server Error", "oops");
        let probe = fetch(&Route::Direct, &format!("http://127.0.0.1:{port}/"), 5);
        assert_eq!(probe.outcome.unwrap().status, 500);
    }

    #[test]
    fn plain_http_server_fails_tls_verification_for_https_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let probe = fetch(&Route::Direct, &format!("https://127.0.0.1:{port}/"), 5);
        assert_eq!(probe.outcome, Err(NetError::Tls));
    }

    #[test]
    fn silent_server_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                thread::sleep(Duration::from_secs(4));
                drop(stream);
            }
        });
        let probe = fetch(&Route::Direct, &format!("http://127.0.0.1:{port}/"), 1);
        assert_eq!(probe.outcome, Err(NetError::Timeout));
    }

    #[test]
    fn closed_proxy_port_is_reported_as_refused() {
        let probe = fetch(
            &Route::Proxy("http://127.0.0.1:1".into()),
            "http://check.example/",
            5,
        );
        assert_eq!(probe.outcome, Err(NetError::Refused));
    }

    #[test]
    fn socks5_greeting_accepts_a_socks5_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut greeting = [0u8; 3];
                let _ = stream.read_exact(&mut greeting);
                let _ = stream.write_all(&[0x05, 0x00]);
            }
        });
        assert!(socks5_greeting(&addr).is_ok());
    }

    #[test]
    fn socks5_greeting_rejects_a_non_socks_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut greeting = [0u8; 3];
                let _ = stream.read_exact(&mut greeting);
                let _ = stream.write_all(b"HT");
            }
        });
        assert!(socks5_greeting(&addr).is_err());
    }

    #[test]
    fn socks5_greeting_reports_a_closed_port() {
        assert!(socks5_greeting("127.0.0.1:1").is_err());
    }
}
