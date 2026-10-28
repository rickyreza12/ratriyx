//! Opt-in HTTP/1.1 proxy forwarding exclusively through an existing Tor SOCKS5
//! listener. This is a transport adapter, NOT OS-enforced network isolation.
use crate::domain::error::{Error, Result};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const HEADER_LIMIT: usize = 32 * 1024;
const MAX_CLIENTS: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(120);

pub struct EmbeddedProxy {
    address: SocketAddr,
    running: Arc<AtomicBool>,
    listener_thread: Option<JoinHandle<()>>,
}

impl EmbeddedProxy {
    pub fn start(socks: SocketAddr) -> Result<Self> {
        Self::start_on(socks, 0)
    }

    /// Bind a fixed loopback port for an explicitly managed desktop proxy.
    /// Port 0 retains the ephemeral per-process routing behavior.
    pub fn start_on(socks: SocketAddr, port: u16) -> Result<Self> {
        if !socks.ip().is_loopback() || socks.port() == 0 {
            return Err(Error::Config(
                "embedded proxy requires a loopback Tor SOCKS5 endpoint".into(),
            ));
        }
        // Port zero avoids colliding with an existing Privoxy instance on 8118.
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| Error::Io(format!("cannot bind embedded proxy: {e}")))?;
        let address = listener
            .local_addr()
            .map_err(|e| Error::Io(e.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::Io(e.to_string()))?;
        let running = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&running);
        let listener_thread = thread::Builder::new()
            .name("ratriyx-http-proxy".into())
            .spawn(move || serve(listener, socks, flag))
            .map_err(|e| Error::Io(format!("cannot start embedded proxy: {e}")))?;
        Ok(Self {
            address,
            running,
            listener_thread: Some(listener_thread),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for EmbeddedProxy {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(thread) = self.listener_thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(listener: TcpListener, socks: SocketAddr, running: Arc<AtomicBool>) {
    let active = Arc::new(AtomicUsize::new(0));
    while running.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut client, _)) => {
                // Accepted sockets can inherit listener nonblocking mode on
                // Windows. Tunnel copies require blocking sockets with timeouts.
                if client.set_nonblocking(false).is_err() {
                    continue;
                }
                if active.fetch_add(1, Ordering::AcqRel) >= MAX_CLIENTS {
                    active.fetch_sub(1, Ordering::AcqRel);
                    let _ = respond(&mut client, 503, "Proxy capacity exceeded");
                    continue;
                }
                let counter = Arc::clone(&active);
                if thread::Builder::new()
                    .name("ratriyx-proxy-client".into())
                    .spawn(move || {
                        let _ = handle(&mut client, socks);
                        counter.fetch_sub(1, Ordering::AcqRel);
                    })
                    .is_err()
                {
                    active.fetch_sub(1, Ordering::AcqRel);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25))
            }
            Err(_) => break,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Destination {
    host: String,
    port: u16,
}

fn destination(authority: &str, default_port: u16) -> io::Result<Destination> {
    if authority.is_empty()
        || authority.contains(['/', '@', '\\', '#', '?'])
        || authority
            .chars()
            .any(|c| c.is_ascii_control() || c.is_whitespace())
    {
        return Err(invalid("invalid HTTP authority"));
    }
    let (host, port_str) = if authority.starts_with('[') {
        let (host, after) = authority
            .split_once(']')
            .ok_or_else(|| invalid("invalid IPv6 authority"))?;
        let host = &host[1..];
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid("invalid IPv6 address"));
        }
        let port = after
            .strip_prefix(':')
            .or(if after.is_empty() { Some("") } else { None })
            .ok_or_else(|| invalid("invalid IPv6 port"))?;
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, port),
            _ => (authority, ""),
        }
    };
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.contains(['[', ']', '%', ':']) && host.parse::<std::net::Ipv6Addr>().is_err()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:".contains(&b))
    {
        return Err(invalid("unsupported destination hostname"));
    }
    let port = if port_str.is_empty() {
        default_port
    } else {
        port_str
            .parse::<u16>()
            .map_err(|_| invalid("invalid destination port"))?
    };
    if port == 0 {
        return Err(invalid("destination port must not be zero"));
    }
    Ok(Destination {
        host: host.into(),
        port,
    })
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn absolute_http_target(target: &str) -> io::Result<(Destination, String)> {
    let rest = target
        .strip_prefix("http://")
        .ok_or_else(|| invalid("only http:// absolute URLs are supported"))?;
    let cut = rest.find(['/', '?']).unwrap_or(rest.len());
    let dest = destination(&rest[..cut], 80)?;
    let path = if cut == rest.len() {
        "/".to_string()
    } else if rest.as_bytes()[cut] == b'?' {
        format!("/{}", &rest[cut..])
    } else {
        rest[cut..].to_string()
    };
    if path.contains('#') || path.contains('\r') || path.contains('\n') {
        return Err(invalid("invalid HTTP path"));
    }
    Ok((dest, path))
}

fn socks_connect(socks: SocketAddr, destination: &Destination) -> io::Result<TcpStream> {
    // There is intentionally no `ToSocketAddrs` for the destination: its name
    // goes into the SOCKS5 request so Tor performs remote DNS resolution.
    let mut conn = TcpStream::connect_timeout(&socks, CONNECT_TIMEOUT)?;
    conn.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    conn.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    conn.write_all(&[5, 1, 0])?;
    let mut greeting = [0; 2];
    conn.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Err(invalid("Tor SOCKS5 rejected no-auth method"));
    }
    let mut request = vec![5, 1, 0];
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend(ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend(ip.octets());
        }
        Err(_) => {
            let bytes = destination.host.as_bytes();
            if bytes.len() > 255 {
                return Err(invalid("SOCKS5 hostname too long"));
            }
            request.extend([3, bytes.len() as u8]);
            request.extend(bytes);
        }
    }
    request.extend(destination.port.to_be_bytes());
    conn.write_all(&request)?;
    let mut header = [0; 4];
    conn.read_exact(&mut header)?;
    if header[0] != 5 || header[1] != 0 || header[2] != 0 {
        return Err(invalid("Tor SOCKS5 connection refused"));
    }
    let length = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0];
            conn.read_exact(&mut len)?;
            len[0] as usize
        }
        _ => return Err(invalid("invalid SOCKS5 reply address type")),
    };
    let mut bound = vec![0; length + 2];
    conn.read_exact(&mut bound)?;
    conn.set_read_timeout(Some(IO_TIMEOUT))?;
    conn.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(conn)
}

fn read_request(client: &mut TcpStream) -> io::Result<(String, Vec<u8>)> {
    let mut data = Vec::with_capacity(1024);
    loop {
        if let Some(index) = data.windows(4).position(|s| s == b"\r\n\r\n") {
            if index + 4 > HEADER_LIMIT {
                return Err(invalid("HTTP headers too large"));
            }
            let header = std::str::from_utf8(&data[..index + 4])
                .map_err(|_| invalid("invalid HTTP header encoding"))?
                .to_string();
            return Ok((header, data[index + 4..].to_vec()));
        }
        if data.len() >= HEADER_LIMIT {
            return Err(invalid("HTTP headers too large"));
        }
        let mut chunk = [0; 2048];
        let count = client.read(&mut chunk)?;
        if count == 0 {
            return Err(invalid("HTTP request ended before headers"));
        }
        data.extend_from_slice(&chunk[..count]);
    }
}

fn respond(client: &mut TcpStream, code: u16, description: &str) -> io::Result<()> {
    write!(
        client,
        "HTTP/1.1 {code} {description}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

fn handle(client: &mut TcpStream, socks: SocketAddr) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(15)))?;
    client.set_write_timeout(Some(IO_TIMEOUT))?;
    let (head, prefetched) = match read_request(client) {
        Ok(v) => v,
        Err(e) => {
            let _ = respond(client, 400, "Bad Request");
            return Err(e);
        }
    };
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut first_parts = first.split(' ');
    let (Some(method), Some(target), Some(version), None) = (
        first_parts.next(),
        first_parts.next(),
        first_parts.next(),
        first_parts.next(),
    ) else {
        return respond(client, 400, "Bad Request");
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return respond(client, 505, "HTTP Version Not Supported");
    }
    if !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return respond(client, 400, "Bad Request");
    }

    let is_connect = method == "CONNECT";
    let parsed = if is_connect {
        destination(target, 443).map(|d| (d, String::new()))
    } else {
        absolute_http_target(target)
    };
    let (dest, path) = match parsed {
        Ok(pair) => pair,
        Err(_) => return respond(client, 400, "Bad Request"),
    };
    let mut length: Option<u64> = None;
    let mut forwarded = Vec::new();
    for line in lines.take_while(|s| !s.is_empty()) {
        if line.starts_with([' ', '\t']) {
            return respond(client, 400, "Bad Request");
        }
        let Some((name, value)) = line.split_once(':') else {
            return respond(client, 400, "Bad Request");
        };
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') || value.contains('\0') {
            return respond(client, 400, "Bad Request");
        }
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "content-length" => {
                if length.is_some() {
                    return respond(client, 400, "Bad Request");
                }
                length = Some(match value.trim().parse() {
                    Ok(n) => n,
                    Err(_) => return respond(client, 400, "Bad Request"),
                });
                forwarded.push(format!("Content-Length: {}\r\n", length.unwrap()));
            }
            "transfer-encoding" => return respond(client, 501, "Transfer Encoding Not Supported"),
            "expect" => return respond(client, 417, "Expectation Failed"),
            "host"
            | "connection"
            | "proxy-connection"
            | "proxy-authorization"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade" => {}
            _ => forwarded.push(format!("{name}:{value}\r\n")),
        }
    }
    let mut upstream = match socks_connect(socks, &dest) {
        Ok(stream) => stream,
        Err(e) => {
            let _ = respond(client, 502, "Bad Gateway");
            return Err(e);
        }
    };
    client.set_read_timeout(Some(IO_TIMEOUT))?;
    if is_connect {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        if !prefetched.is_empty() {
            upstream.write_all(&prefetched)?;
        }
        let mut to_upstream = upstream.try_clone()?;
        let mut from_client = client.try_clone()?;
        let upload = thread::spawn(move || {
            let _ = io::copy(&mut from_client, &mut to_upstream);
            let _ = to_upstream.shutdown(Shutdown::Write);
        });
        let result = io::copy(&mut upstream, client);
        let _ = client.shutdown(Shutdown::Read);
        let _ = upload.join();
        return result.map(|_| ());
    }
    let host = if dest.host.contains(':') {
        format!("[{}]", dest.host)
    } else {
        dest.host.clone()
    };
    let host = if dest.port == 80 {
        host
    } else {
        format!("{host}:{}", dest.port)
    };
    write!(upstream, "{method} {path} {version}\r\nHost: {host}\r\n")?;
    for header in forwarded {
        upstream.write_all(header.as_bytes())?;
    }
    upstream.write_all(b"Connection: close\r\n\r\n")?;
    let total = length.unwrap_or(0);
    let initial = prefetched.len().min(total.min(usize::MAX as u64) as usize);
    upstream.write_all(&prefetched[..initial])?;
    let remaining = total - initial as u64;
    if remaining > 0 {
        let copied = io::copy(&mut client.take(remaining), &mut upstream)?;
        if copied != remaining {
            return Err(invalid("incomplete HTTP request body"));
        }
    }
    let _ = upstream.shutdown(Shutdown::Write);
    io::copy(&mut upstream, client).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    type FakeSocksResult = (u8, String, u16, Vec<u8>);

    fn fake_socks(reply: &'static [u8]) -> (SocketAddr, JoinHandle<FakeSocksResult>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let task = thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut greeting = [0; 3];
            peer.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            peer.write_all(&[5, 0]).unwrap();
            let mut header = [0; 4];
            peer.read_exact(&mut header).unwrap();
            assert_eq!(&header[..3], &[5, 1, 0]);
            let size = match header[3] {
                1 => 4,
                4 => 16,
                3 => {
                    let mut b = [0];
                    peer.read_exact(&mut b).unwrap();
                    b[0] as usize
                }
                _ => panic!("bad atyp"),
            };
            let mut host = vec![0; size];
            peer.read_exact(&mut host).unwrap();
            let mut port = [0; 2];
            peer.read_exact(&mut port).unwrap();
            peer.write_all(reply).unwrap();
            let mut data = Vec::new();
            if reply[1] == 0 {
                if u16::from_be_bytes(port) == 80 {
                    peer.read_to_end(&mut data).unwrap();
                } else {
                    let mut b = [0; 2048];
                    let n = peer.read(&mut b).unwrap_or(0);
                    data.extend_from_slice(&b[..n]);
                }
                peer.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                )
                .unwrap();
            }
            (
                header[3],
                String::from_utf8_lossy(&host).to_string(),
                u16::from_be_bytes(port),
                data,
            )
        });
        (addr, task)
    }

    const SOCKS_OK: &[u8] = &[5, 0, 0, 1, 127, 0, 0, 1, 0, 80];
    const SOCKS_FAIL: &[u8] = &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0];

    #[test]
    fn request_get_uses_remote_socks_dns_and_rewrites_absolute_path() {
        let (socks, task) = fake_socks(SOCKS_OK);
        let proxy = EmbeddedProxy::start(socks).unwrap();
        let mut client = TcpStream::connect(proxy.address()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client.write_all(b"GET http://example.org/hello HTTP/1.1\r\nHost: ignored.test\r\nProxy-Connection: keep-alive\r\n\r\n").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(
            String::from_utf8_lossy(&response).contains("200 OK"),
            "response: {:?}",
            String::from_utf8_lossy(&response)
        );
        let (atyp, host, port, request) = task.join().unwrap();
        assert_eq!((atyp, host.as_str(), port), (3, "example.org", 80));
        let text = String::from_utf8_lossy(&request);
        assert!(text.starts_with("GET /hello HTTP/1.1\r\nHost: example.org\r\n"));
        assert!(!text.contains("ignored.test"));
    }

    #[test]
    fn request_post_forwards_body_with_content_length() {
        let (socks, task) = fake_socks(SOCKS_OK);
        let proxy = EmbeddedProxy::start(socks).unwrap();
        let mut client = TcpStream::connect(proxy.address()).unwrap();
        client.write_all(b"POST http://example.org/submit HTTP/1.1\r\nHost: example.org\r\nContent-Length: 5\r\n\r\nhello").unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.contains("200 OK"));
        let (_, _, _, request) = task.join().unwrap();
        let text = String::from_utf8_lossy(&request);
        assert!(text.starts_with("POST /submit HTTP/1.1\r\nHost: example.org\r\n"));
        assert!(text.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn unsupported_upload_fails_before_attempting_socks() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = EmbeddedProxy::start(listener.local_addr().unwrap()).unwrap();
        let mut client = TcpStream::connect(proxy.address()).unwrap();
        client
            .write_all(b"POST http://example.org/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 501"));
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn connect_tunnel_uses_socks_and_transfers_bytes() {
        let (socks, task) = fake_socks(SOCKS_OK);
        let proxy = EmbeddedProxy::start(socks).unwrap();
        let mut client = TcpStream::connect(proxy.address()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nTEST")
            .unwrap();
        let mut response = [0; 256];
        let n = client.read(&mut response).unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("200 Connection Established"));
        let (atyp, host, port, data) = task.join().unwrap();
        assert_eq!((atyp, host.as_str(), port), (3, "example.com", 443));
        assert_eq!(data, b"TEST");
    }

    #[test]
    fn upstream_refusal_is_502_not_direct_fallback() {
        let (socks, task) = fake_socks(SOCKS_FAIL);
        let proxy = EmbeddedProxy::start(socks).unwrap();
        let mut client = TcpStream::connect(proxy.address()).unwrap();
        client
            .write_all(b"CONNECT sample.org:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 502"));
        task.join().unwrap();
    }

    #[test]
    fn rejects_invalid_authorities_and_untrusted_socks_listener() {
        for value in [
            "user@host:80",
            "example.com:0",
            "a/b:443",
            "[::1",
            "foo:abc",
        ] {
            assert!(destination(value, 443).is_err(), "{value}");
        }
        assert!(EmbeddedProxy::start("192.0.2.1:9050".parse().unwrap()).is_err());
    }

    #[test]
    #[ignore = "live: requires a running Tor SOCKS5 server and internet access"]
    fn live_tor_tls_through_embedded_http_connect() {
        let proxy = EmbeddedProxy::start("127.0.0.1:9050".parse().unwrap()).unwrap();
        let out = std::process::Command::new(crate::infrastructure::platform::curl_program())
            .args([
                "-q",
                "-v",
                "--max-time",
                "30",
                "--proxy",
                &format!("http://{}", proxy.address()),
                "https://check.torproject.org/api/ip",
            ])
            .output()
            .unwrap();
        eprintln!("curl stdout: {}", String::from_utf8_lossy(&out.stdout));
        eprintln!("curl stderr: {}", String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("\"IsTor\":true"));
    }
}
