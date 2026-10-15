use super::Listener;
use std::process::Command;

pub fn listening() -> Option<Vec<Listener>> {
    if cfg!(windows) {
        netstat_listeners().or_else(ss_listeners)
    } else {
        ss_listeners()
    }
}

/// Split an `ss` local-address field into address and port. Handles
/// `127.0.0.1:9050`, `[::1]:8118`, and `*:port`.
fn split_addr_port(field: &str) -> Option<(String, u16)> {
    let (addr, port) = field.rsplit_once(':')?;
    Some((addr.to_string(), port.parse().ok()?))
}

/// Extract a process name from an `ss -ltnp` auxiliary column, if present.
/// Example: `users:(("tor",pid=258,fd=9))` yields `tor`.
fn parse_ss_process(aux: &str) -> Option<String> {
    let start = aux.find("((")? + 2;
    let rest = aux.get(start..)?.trim_start_matches('"');
    let end = rest.find([',', '"'])?;
    let name = rest[..end].trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Parses `ss -ltn` output and returns bound listeners with addresses.
/// The process column of `ss -ltnp` is captured when present.
fn parse_ss(text: &str) -> Vec<Listener> {
    text.lines()
        .filter(|line| line.starts_with("LISTEN"))
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            cols.next()?;
            cols.next()?;
            cols.next()?;
            let local = cols.next()?;
            let (addr, port) = split_addr_port(local)?;
            let rest: Vec<&str> = cols.collect();
            let process = rest.iter().find_map(|c| parse_ss_process(c));
            Some(Listener {
                addr,
                port,
                process,
            })
        })
        .collect()
}

/// Parse Windows `netstat -ano` TCP lines into listeners. The process owner
/// is the PID; name resolution is left to the caller.
fn parse_netstat_ano(text: &str) -> Vec<Listener> {
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 || cols[0] != "TCP" || cols[3] != "LISTENING" {
                return None;
            }
            let (addr, port) = split_addr_port(cols[1])?;
            Some(Listener {
                addr,
                port,
                process: cols.get(4).map(|s| format!("pid {s}")),
            })
        })
        .collect()
}

fn ss_listeners() -> Option<Vec<Listener>> {
    // `-p` adds process ownership where permissions allow; without it the
    // process field is simply absent.
    if let Ok(out) = Command::new("ss").args(["-ltnp"]).output() {
        if out.status.success() {
            let parsed = parse_ss(&String::from_utf8_lossy(&out.stdout));
            if !parsed.is_empty() {
                return Some(parsed);
            }
        }
    }
    let out = Command::new("ss").arg("-ltn").output().ok()?;
    out.status
        .success()
        .then(|| parse_ss(&String::from_utf8_lossy(&out.stdout)))
}

fn netstat_listeners() -> Option<Vec<Listener>> {
    let out = Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| parse_netstat_ano(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::service::is_wildcard_addr;

    #[test]
    fn ss_output_keeps_bind_addresses() {
        let text = "State Recv-Q Send-Q Local Address:Port Peer\n\
                    LISTEN 0 4096 127.0.0.1:9050 0.0.0.0:*\n\
                    LISTEN 0 128 [::1]:8118 [::]:*\n";
        let parsed = parse_ss(text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].port, 9050);
        assert!(parsed[0].is_loopback());
        assert!(parsed[1].is_loopback());
    }

    #[test]
    fn wildcard_binds_are_not_loopback() {
        let text = "State Recv-Q Send-Q Local Address:Port Peer\n\
                    LISTEN 0 4096 0.0.0.0:8118 0.0.0.0:*\n";
        let parsed = parse_ss(text);
        assert_eq!(parsed.len(), 1);
        assert!(!parsed[0].is_loopback());
        assert!(is_wildcard_addr(&parsed[0].addr));
    }

    #[test]
    fn ss_process_column_is_captured_when_present() {
        let text = "State Recv-Q Send-Q Local Address:Port Peer Process\n\
                    LISTEN 0 4096 127.0.0.1:9050 0.0.0.0:* users:((\"tor\",pid=258,fd=9))\n";
        let parsed = parse_ss(text);
        assert_eq!(parsed[0].process.as_deref(), Some("tor"));
    }

    #[test]
    fn netstat_listening_lines_parse() {
        let text = "  TCP    127.0.0.1:8118    0.0.0.0:0    LISTENING    1234\n";
        let parsed = parse_netstat_ano(text);
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].is_loopback());
        assert_eq!(parsed[0].process.as_deref(), Some("pid 1234"));
    }
}
