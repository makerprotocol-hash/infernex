//! Pure networking primitives shared by the CLI and future native network engines.
//!
//! This module intentionally contains no network side effects. Active operations
//! remain in the command layer until their APIs and authorization contracts are
//! extracted and tested independently.

use std::net::IpAddr;

pub(crate) const MAX_SCAN_PORTS: u16 = 256;

pub(crate) fn parse_tcp_port(value: &str) -> Option<u16> {
    let port = value.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

pub(crate) fn parse_scan_range(start_text: &str, end_text: &str) -> Option<(u16, u16)> {
    let start = parse_tcp_port(start_text)?;
    let end = parse_tcp_port(end_text)?;
    if end < start || end - start + 1 > MAX_SCAN_PORTS {
        return None;
    }
    Some((start, end))
}

/// Classify a service only from observed response bytes, never from port number alone.
pub(crate) fn classify_service_banner(port: u16, banner: &[u8]) -> &'static str {
    let text = String::from_utf8_lossy(banner).trim_start().to_ascii_uppercase();
    if text.starts_with("SSH-") { "SSH" }
    else if text.starts_with("HTTP/") || text.starts_with("HTTP ") { "HTTP" }
    else if text.starts_with("+OK") { "POP3" }
    else if text.starts_with("* OK") { "IMAP" }
    else if text.starts_with("+PONG") || text.starts_with("-NOAUTH") || text.starts_with("-ERR") {
        "Redis-compatible RESP"
    }
    else if text.starts_with("220") && (port == 21 || text.contains("FTP")) { "FTP" }
    else if text.starts_with("220") && (port == 25 || port == 465 || port == 587 || text.contains("SMTP") || text.contains("ESMTP")) { "SMTP" }
    else if text.starts_with("220") { "Unclassified 220 greeting" }
    else { "Unknown / no recognizable banner" }
}

pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => (address.segments()[0] & 0xfe00) == 0xfc00,
    }
}

pub(crate) fn is_link_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => (address.segments()[0] & 0xffc0) == 0xfe80,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_range_parser_enforces_bounds_and_limit() {
        assert_eq!(parse_scan_range("1", "1"), Some((1, 1)));
        assert_eq!(parse_scan_range("20", "120"), Some((20, 120)));
        assert_eq!(parse_scan_range("1", "256"), Some((1, 256)));
        assert_eq!(parse_scan_range("1", "257"), None);
        assert_eq!(parse_scan_range("100", "99"), None);
        assert_eq!(parse_scan_range("0", "10"), None);
        assert_eq!(parse_scan_range("1", "65536"), None);
    }

    #[test]
    fn tcp_port_parser_accepts_valid_ports_and_rejects_invalid_values() {
        assert_eq!(parse_tcp_port("1"), Some(1));
        assert_eq!(parse_tcp_port("443"), Some(443));
        assert_eq!(parse_tcp_port("65535"), Some(65535));
        assert_eq!(parse_tcp_port("0"), None);
        assert_eq!(parse_tcp_port("65536"), None);
        assert_eq!(parse_tcp_port("-1"), None);
        assert_eq!(parse_tcp_port("https"), None);
        assert_eq!(parse_tcp_port("443/tcp"), None);
    }

    #[test]
    fn service_fingerprinting_uses_banner_not_port_number() {
        assert_eq!(classify_service_banner(443, b"SSH-2.0-OpenSSH_9.0\\r\\n"), "SSH");
        assert_eq!(classify_service_banner(22, b"HTTP/1.1 200 OK\\r\\n"), "HTTP");
        assert_eq!(classify_service_banner(12345, b"+OK POP3 ready\\r\\n"), "POP3");
        assert_eq!(classify_service_banner(25, b"220 mail.example ESMTP ready\\r\\n"), "SMTP");
        assert_eq!(classify_service_banner(9999, b"opaque response"), "Unknown / no recognizable banner");
    }

    #[test]
    fn classifies_ipv4_and_ipv6_address_ranges() {
        let private: IpAddr = "192.168.1.10".parse().unwrap();
        let public_example: IpAddr = "203.0.113.10".parse().unwrap();
        let unique_local: IpAddr = "fd00::1".parse().unwrap();
        let v4_link_local: IpAddr = "169.254.10.20".parse().unwrap();
        let v6_link_local: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_ip(private));
        assert!(!is_private_ip(public_example));
        assert!(is_private_ip(unique_local));
        assert!(is_link_local_ip(v4_link_local));
        assert!(is_link_local_ip(v6_link_local));
        assert!(!is_link_local_ip(unique_local));
    }
}
