use crate::domain::error::{Error, Result};
use crate::infrastructure::config::Config;
use crate::infrastructure::fsutil::{atomic_write, io_err};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

pub const COOLDOWN_SECS: u64 = 10;
const COOKIE_LEN: usize = 32;

/// Reads the Tor control cookie. The value is never printed or logged.
pub fn read_cookie(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).map_err(|e| {
        Error::Config(format!(
            "cannot read Tor cookie file {}: {}",
            path.display(),
            e.kind()
        ))
    })?;
    if bytes.len() != COOKIE_LEN {
        return Err(Error::Config(
            "Tor cookie file must be exactly 32 bytes".into(),
        ));
    }
    Ok(bytes)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads one control reply: continuation lines use `NNN-`, the final line uses `NNN `.
fn read_reply<R: BufRead>(reader: &mut R) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(io_err)?;
        if n == 0 {
            return Err(Error::Io("Tor closed the control connection".into()));
        }
        let line = line.trim_end().to_string();
        let done = line.len() >= 4 && line.as_bytes()[3] == b' ';
        lines.push(line);
        if done {
            return Ok(lines);
        }
    }
}

fn expect_ok(lines: &[String], step: &str) -> Result<()> {
    let last = lines.last().map(String::as_str).unwrap_or("");
    if last.starts_with("250") {
        Ok(())
    } else {
        let code = last.get(..3).unwrap_or("???");
        Err(Error::Io(format!("{step}: Tor replied {code}")))
    }
}

/// Authenticate, then send one NEWNYM. Works on any stream so tests can use an in-memory transport.
pub fn newnym_over<S: Read + Write>(stream: &mut S, cookie_hex: &str) -> Result<()> {
    let mut reader = BufReader::new(&mut *stream);
    reader
        .get_mut()
        .write_all(format!("AUTHENTICATE {cookie_hex}\r\n").as_bytes())
        .map_err(io_err)?;
    let reply = read_reply(&mut reader)?;
    expect_ok(&reply, "authentication")?;
    reader
        .get_mut()
        .write_all(b"SIGNAL NEWNYM\r\n")
        .map_err(io_err)?;
    let reply = read_reply(&mut reader)?;
    expect_ok(&reply, "NEWNYM")?;
    let _ = reader.get_mut().write_all(b"QUIT\r\n");
    Ok(())
}

pub fn newnym(addr: &str, cookie: &[u8]) -> Result<()> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| Error::Config(format!("invalid Tor control address {addr}")))?;
    if !socket.ip().is_loopback() {
        return Err(Error::Config(
            "the Tor control address must be loopback".into(),
        ));
    }
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(5)).map_err(|e| {
        Error::Io(format!(
            "cannot reach the Tor control port {addr}: {}",
            e.kind()
        ))
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(io_err)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(io_err)?;
    newnym_over(&mut stream, &hex(cookie))
}

/// Same exchange over a Tor `ControlSocket` (a Unix domain socket), which needs no TCP listener.
#[cfg(unix)]
pub fn newnym_socket(path: &str, cookie: &[u8]) -> Result<()> {
    let mut stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| {
        Error::Io(format!(
            "cannot reach the Tor control socket {path}: {}",
            e.kind()
        ))
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(io_err)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(io_err)?;
    newnym_over(&mut stream, &hex(cookie))
}

#[cfg(not(unix))]
pub fn newnym_socket(_path: &str, _cookie: &[u8]) -> Result<()> {
    Err(Error::Config(
        "the Tor control socket is only supported on Linux".into(),
    ))
}

pub fn cooldown_remaining(last: Option<u64>, now: u64) -> u64 {
    match last {
        Some(t) if now.saturating_sub(t) < COOLDOWN_SECS => COOLDOWN_SECS - now.saturating_sub(t),
        _ => 0,
    }
}

/// `rotate` requests one new circuit set. It never restarts Tor and makes no IP promise.
///
/// Concurrency: a `<state>.lock` file serializes concurrent `rotate` calls.
/// The timestamp is reserved before the network exchange, so a failed write
/// cannot cause an immediate second NEWNYM and a failed NEWNYM still respects
/// the cooldown instead of hammering Tor.
pub fn rotate(config: &Config, state_file: &Path, now: u64, yes: bool) -> Result<String> {
    if !config.tor_control_enabled {
        return Err(Error::Config(
            "Tor control is disabled; set tor.control_enabled = true and tor.cookie_path in the config".into(),
        ));
    }
    check_cooldown(state_file, now)?;
    if !yes {
        return Err(Error::Approval(
            "rotate sends SIGNAL NEWNYM to your Tor. It does not promise a new exit IP or any provider quota relief. Re-run with --yes".into(),
        ));
    }
    let _lock = acquire_rotate_lock(state_file, now)?;
    // Re-check under the lock: another process may have reserved since our read.
    check_cooldown(state_file, now)?;
    let cookie = read_cookie(Path::new(&config.tor_cookie_path))?;
    // Reserve the timestamp first: a NEWNYM failure or a later state-write
    // failure must not allow an immediate retry loop against Tor.
    if let Some(parent) = state_file.parent() {
        fs::create_dir_all(parent).map_err(io_err)?;
    }
    atomic_write(state_file, now.to_string().as_bytes(), true)?;
    if config.tor_control_socket.is_empty() {
        newnym(&config.tor_control_addr(), &cookie)?;
    } else {
        newnym_socket(&config.tor_control_socket, &cookie)?;
    }
    Ok("NEWNYM accepted. Check the exit with `ratriyx ip`. The exit may stay the same, and circuits already in use can keep working.".into())
}

/// Refuses while the last recorded NEWNYM is still inside the cooldown window.
fn check_cooldown(state_file: &Path, now: u64) -> Result<()> {
    let last = fs::read_to_string(state_file)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    let wait = cooldown_remaining(last, now);
    if wait > 0 {
        return Err(Error::Io(format!(
            "NEWNYM cooldown: wait {wait} more seconds"
        )));
    }
    Ok(())
}

/// Exclusive rotate lock held for the whole read-signal-record sequence.
/// Stale locks (older than 60 s) are reclaimed; fresh locks refuse the call.
fn acquire_rotate_lock(state_file: &Path, now: u64) -> Result<RotateLock> {
    let lock_path = state_file.with_extension("lock");
    if let Some(parent) = lock_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(io_err)?;
        }
    }
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(mut file) => {
            use std::io::Write as _;
            let _ = file.write_all(format!("{} {now}", std::process::id()).as_bytes());
            Ok(RotateLock { path: lock_path })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let stale = fs::read_to_string(&lock_path)
                .ok()
                .and_then(|s| s.split_whitespace().last()?.parse::<u64>().ok())
                .map(|taken| now.saturating_sub(taken) > 60)
                .unwrap_or(false);
            if stale {
                let _ = fs::remove_file(&lock_path);
                return acquire_rotate_lock(state_file, now);
            }
            Err(Error::Io(
                "another rotate is already in progress; wait for it to finish".into(),
            ))
        }
        Err(e) => Err(io_err(e)),
    }
}

struct RotateLock {
    path: std::path::PathBuf,
}

impl Drop for RotateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Mock {
        input: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Mock {
        fn with_replies(replies: &str) -> Self {
            Mock {
                input: Cursor::new(replies.as_bytes().to_vec()),
                written: Vec::new(),
            }
        }
    }

    impl Read for Mock {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Mock {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn successful_exchange_authenticates_then_signals_newnym() {
        let mut mock = Mock::with_replies("250 OK\r\n250 OK\r\n");
        newnym_over(&mut mock, "abcd").unwrap();
        let sent = String::from_utf8(mock.written).unwrap();
        assert!(sent.starts_with("AUTHENTICATE abcd\r\nSIGNAL NEWNYM\r\n"));
    }

    #[test]
    fn denied_authentication_stops_before_signal() {
        let mut mock = Mock::with_replies("515 Authentication failed\r\n");
        let err = newnym_over(&mut mock, "abcd").unwrap_err();
        assert!(err.to_string().contains("authentication"));
        let sent = String::from_utf8(mock.written).unwrap();
        assert!(!sent.contains("SIGNAL"));
    }

    #[test]
    fn multiline_reply_is_read_to_its_final_line() {
        let mut mock = Mock::with_replies("250-version=0.4.9\r\n250 OK\r\n250 OK\r\n");
        assert!(newnym_over(&mut mock, "ab").is_ok());
    }

    #[test]
    fn malformed_reply_without_final_line_is_an_error() {
        let mut mock = Mock::with_replies("garbage\r\n");
        assert!(newnym_over(&mut mock, "ab").is_err());
    }

    #[test]
    fn rejected_newnym_is_reported_with_code_only() {
        let mut mock = Mock::with_replies("250 OK\r\n550 Unrecognized\r\n");
        let err = newnym_over(&mut mock, "ab").unwrap_err();
        assert_eq!(err.to_string(), "NEWNYM: Tor replied 550");
    }

    #[test]
    fn cooldown_counts_down_for_ten_seconds() {
        assert_eq!(cooldown_remaining(None, 100), 0);
        assert_eq!(cooldown_remaining(Some(100), 104), 6);
        assert_eq!(cooldown_remaining(Some(100), 110), 0);
    }

    #[test]
    fn cookie_must_be_exactly_32_bytes() {
        let dir = std::env::temp_dir().join(format!("ratriyx-cookie-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cookie");
        fs::write(&path, [0u8; 31]).unwrap();
        assert!(read_cookie(&path).is_err());
        fs::write(&path, [7u8; 32]).unwrap();
        assert_eq!(read_cookie(&path).unwrap().len(), 32);
    }

    #[test]
    fn authentication_error_never_contains_the_cookie() {
        let mut mock = Mock::with_replies("515 Authentication failed\r\n");
        let err = newnym_over(&mut mock, "deadbeef").unwrap_err();
        assert!(!err.to_string().contains("deadbeef"));
    }

    #[test]
    fn unreachable_control_port_is_an_io_error() {
        let err = newnym("127.0.0.1:1", &[0u8; 32]).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn non_loopback_control_address_is_refused() {
        let err = newnym("192.0.2.1:9051", &[0u8; 32]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn rotate_is_refused_when_control_is_disabled() {
        let cfg = Config::default();
        let err = rotate(&cfg, Path::new("/nonexistent/rotate.last"), 0, true).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn rotate_against_a_mock_control_port_makes_no_ip_promise_and_honors_cooldown() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut seen = String::new();
            for _ in 0..2 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                seen.push_str(&line);
                stream.write_all(b"250 OK\r\n").unwrap();
            }
            seen
        });
        let dir = std::env::temp_dir().join(format!("ratriyx-rotate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cookie = dir.join("cookie");
        fs::write(&cookie, [7u8; 32]).unwrap();
        let state = dir.join("rotate.last");
        let cfg = Config {
            tor_control_enabled: true,
            tor_control_port: port,
            tor_cookie_path: cookie.to_string_lossy().to_string(),
            ..Config::default()
        };
        let msg = rotate(&cfg, &state, 1000, true).unwrap();
        assert!(msg.contains("may stay the same"));
        let seen = server.join().unwrap();
        assert!(seen.starts_with("AUTHENTICATE "));
        assert!(seen.contains("SIGNAL NEWNYM"));
        let err = rotate(&cfg, &state, 1003, true).unwrap_err();
        assert!(err.to_string().contains("cooldown"));
    }

    #[cfg(unix)]
    #[test]
    fn rotate_over_a_mock_control_socket() {
        let dir = std::env::temp_dir().join(format!("ratriyx-rsock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut seen = String::new();
            for _ in 0..2 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                seen.push_str(&line);
                stream.write_all(b"250 OK\r\n").unwrap();
            }
            seen
        });
        let cookie = dir.join("cookie");
        fs::write(&cookie, [9u8; 32]).unwrap();
        let cfg = Config {
            tor_control_enabled: true,
            tor_control_socket: sock.to_string_lossy().to_string(),
            tor_cookie_path: cookie.to_string_lossy().to_string(),
            ..Config::default()
        };
        rotate(&cfg, &dir.join("rotate.last"), 500, true).unwrap();
        let seen = server.join().unwrap();
        assert!(seen.starts_with("AUTHENTICATE "));
        assert!(seen.contains("SIGNAL NEWNYM"));
    }

    #[test]
    fn relative_control_socket_path_is_refused() {
        assert!(Config::parse("[tor]\ncontrol_socket = \"run/tor/control\"\n").is_err());
        assert!(Config::parse("[tor]\ncontrol_socket = \"/run/tor/control\"\n").is_ok());
    }

    #[test]
    fn concurrent_rotate_is_serialized_by_the_lock() {
        let dir = std::env::temp_dir().join(format!("ratriyx-rlock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let state = dir.join("rotate.last");
        // A fresh lock file blocks a second acquisition.
        let _held = acquire_rotate_lock(&state, 1000).unwrap();
        assert!(acquire_rotate_lock(&state, 1001).is_err());
    }

    #[test]
    fn rotate_without_yes_is_an_approval_error() {
        let cfg = Config {
            tor_control_enabled: true,
            ..Config::default()
        };
        let err = rotate(&cfg, Path::new("/nonexistent/rotate.last"), 0, false).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }
}
