const SENSITIVE_MARKERS: [&str; 5] = ["TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH"];

pub fn is_sensitive_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SENSITIVE_MARKERS
        .iter()
        .any(|marker| upper.contains(marker))
}

pub fn mask_value(name: &str, value: &str) -> String {
    if is_sensitive_name(name) {
        "***".to_string()
    } else {
        redact_text(value)
    }
}

pub fn redact_text(input: &str) -> String {
    // Stray bearer tokens first, then header values (credential token only).
    mask_auth_headers(&mask_bearer_ci(&redact_url(input)))
}

pub fn redact_url(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("://") {
        let (head, tail) = rest.split_at(pos + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c == '/' || c.is_whitespace())
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(at) => {
                out.push_str("***");
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Case-insensitive `Bearer <token>` masking.
fn mask_bearer_ci(input: &str) -> String {
    const MARKER_LEN: usize = 7; // len("Bearer ")
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let lower = rest.to_ascii_lowercase();
        let Some(pos) = lower.find("bearer ") else {
            break;
        };
        let start = pos + MARKER_LEN;
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail.find(char::is_whitespace).unwrap_or(tail.len());
        if end > 0 {
            out.push_str("***");
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Masks `Authorization: ...` and `Proxy-Authorization: ...` header values,
/// case-insensitively, keeping only the scheme name.
fn mask_auth_headers(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let lower_len = trimmed.to_ascii_lowercase();
        let header_len = if lower_len.starts_with("proxy-authorization:") {
            "proxy-authorization:".len()
        } else if lower_len.starts_with("authorization:") {
            "authorization:".len()
        } else {
            0
        };
        if header_len == 0 {
            out.push_str(line);
            continue;
        }
        let prefix_len = line.len() - trimmed.len() + header_len;
        let (head, tail) = (&line[..prefix_len], &line[prefix_len..]);
        let value = tail.trim();
        let words: Vec<&str> = value.split_whitespace().collect();
        // Mask the credential token (first word after the scheme). When the
        // credential was already masked upstream, trailing prose is kept;
        // when it was a real secret, the rest of the header value goes with it.
        let masked = match words.as_slice() {
            [] => "***".to_string(),
            [scheme] => format!("{scheme} ***"),
            [scheme, credential, prose @ ..] => {
                if *credential == "***" {
                    let kept: Vec<&str> = prose.iter().copied().filter(|w| *w != "***").collect();
                    if kept.is_empty() {
                        format!("{scheme} ***")
                    } else {
                        format!("{scheme} *** {}", kept.join(" "))
                    }
                } else {
                    format!("{scheme} ***")
                }
            }
        };
        out.push_str(head);
        out.push(' ');
        out.push_str(&masked);
        if line.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userinfo_in_proxy_url_is_masked() {
        assert_eq!(
            redact_url("http://user:pw@127.0.0.1:8118"),
            "http://***@127.0.0.1:8118"
        );
    }

    #[test]
    fn url_without_userinfo_is_unchanged() {
        assert_eq!(
            redact_url("http://127.0.0.1:8118/x"),
            "http://127.0.0.1:8118/x"
        );
    }

    #[test]
    fn bearer_tokens_are_masked() {
        assert_eq!(
            redact_text("Authorization: Bearer abc.def ok"),
            "Authorization: Bearer *** ok"
        );
    }

    #[test]
    fn bearer_and_basic_headers_masked_case_insensitively() {
        assert!(redact_text("authorization: bearer abc123").contains("***"));
        assert!(!redact_text("authorization: bearer abc123").contains("abc123"));
        let basic = redact_text("Proxy-Authorization: Basic dXNlcjpwYXNz");
        assert!(basic.contains("Basic ***"));
        assert!(!basic.contains("dXNlcjpwYXNz"));
    }

    #[test]
    fn sensitive_names_mask_whole_value() {
        assert!(is_sensitive_name("OPENAI_API_KEY"));
        assert!(is_sensitive_name("https_proxy_auth"));
        assert!(!is_sensitive_name("HTTP_PROXY"));
        assert_eq!(mask_value("MY_TOKEN", "abc"), "***");
    }
}
