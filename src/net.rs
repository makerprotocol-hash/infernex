//! Pure networking primitives shared by the CLI and future native network engines.
//!
//! Pure networking primitives and bounded native operations shared by the CLI.
//!
//! Active-operation APIs do not perform authorization themselves: the CLI must
//! verify explicit target scope before invoking any network side effect.

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


/// Resolve a hostname using the operating system's configured resolver.
pub(crate) fn resolve_hostname(hostname: &str) -> std::io::Result<Vec<IpAddr>> {
    use std::collections::BTreeSet;
    use std::net::ToSocketAddrs;
    if hostname.is_empty() || hostname.contains('/') || hostname.contains('\\') {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "provide a hostname, not a URL or path"));
    }
    let addresses = (hostname, 0).to_socket_addrs()?;
    let unique: BTreeSet<IpAddr> = addresses.map(|address| address.ip()).collect();
    Ok(unique.into_iter().collect())
}

/// Attempt one bounded TCP connection to an already-authorized socket address.
pub(crate) fn tcp_connect(address: &std::net::SocketAddr, timeout: std::time::Duration) -> std::io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect_timeout(address, timeout)
}

/// Send one caller-supplied UDP datagram and wait for a bounded reply.
/// The caller must check authorization scope before invoking this function.
pub(crate) fn udp_exchange(destination: std::net::SocketAddr, payload: &[u8], timeout: std::time::Duration, max_response_bytes: usize) -> std::io::Result<Vec<u8>> {
    use std::net::UdpSocket;
    let bind_address = if destination.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind_address)?;
    socket.connect(destination)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.send(payload)?;
    let mut response = vec![0u8; max_response_bytes];
    let count = socket.recv(&mut response)?;
    response.truncate(count);
    Ok(response)
}



/// Connect to one explicitly authorized endpoint and collect a bounded service banner.
/// On conventional cleartext HTTP ports, send one minimal HEAD request first.
pub(crate) fn identify_service_banner(
    address: std::net::SocketAddr,
    port: u16,
    timeout: std::time::Duration,
    max_banner_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    if matches!(port, 80 | 8000 | 8008 | 8080 | 8081 | 8888) {
        let request = format!(
            "HEAD / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            address.ip()
        );
        stream.write_all(request.as_bytes())?;
    }

    let mut banner = vec![0u8; max_banner_bytes];
    match stream.read(&mut banner) {
        Ok(count) => banner.truncate(count),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            || error.kind() == std::io::ErrorKind::TimedOut => banner.clear(),
        Err(error) => return Err(error),
    }
    Ok(banner)
}



/// One address assigned to a local network interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InterfaceAddress {
    pub name: String,
    pub ip: IpAddr,
    pub netmask: IpAddr,
    pub prefix_len: u8,
    pub broadcast: Option<IpAddr>,
    pub loopback: bool,
    pub link_local: bool,
}

/// Read-only snapshot of local IPv4/IPv6 interface addresses using native OS APIs.
pub(crate) fn list_interfaces() -> std::io::Result<Vec<InterfaceAddress>> {
    let mut entries = if_addrs::get_if_addrs()?
        .into_iter()
        .map(|interface| {
            let loopback = interface.is_loopback();
            let link_local = interface.addr.is_link_local();
            let (ip, netmask, prefix_len, broadcast) = match interface.addr {
                if_addrs::IfAddr::V4(address) => (
                    IpAddr::V4(address.ip),
                    IpAddr::V4(address.netmask),
                    address.prefixlen,
                    address.broadcast.map(IpAddr::V4),
                ),
                if_addrs::IfAddr::V6(address) => (
                    IpAddr::V6(address.ip),
                    IpAddr::V6(address.netmask),
                    address.prefixlen,
                    address.broadcast.map(IpAddr::V6),
                ),
            };
            InterfaceAddress {
                name: interface.name,
                ip,
                netmask,
                prefix_len,
                broadcast,
                loopback,
                link_local,
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.name.cmp(&right.name).then_with(|| left.ip.cmp(&right.ip)));
    entries.dedup();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;




    #[test]
    fn local_interface_inventory_contains_loopback_address() {
        let interfaces = list_interfaces().expect("system interface enumeration should succeed");
        assert!(!interfaces.is_empty(), "at least loopback should be present");
        assert!(interfaces.iter().any(|entry| entry.loopback && entry.ip.is_loopback()));
        for entry in interfaces {
            assert!(entry.prefix_len <= if entry.ip.is_ipv4() { 32 } else { 128 });
            assert_eq!(entry.ip.is_ipv4(), entry.netmask.is_ipv4());
            assert_eq!(entry.ip.is_ipv4(), entry.broadcast.map(|ip| ip.is_ipv4()).unwrap_or(entry.ip.is_ipv4()));
        }
    }

    #[test]
    fn service_identification_reads_loopback_banner_with_limit() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"SSH-2.0-INFERNEX-TEST\r\n").unwrap();
        });
        let banner = identify_service_banner(address, address.port(), Duration::from_secs(1), 12).unwrap();
        worker.join().unwrap();
        assert_eq!(banner, b"SSH-2.0-INFE");
        assert_eq!(classify_service_banner(address.port(), &banner), "SSH");
    }

    #[test]
    fn service_identification_http_probe_is_bounded_and_non_destructive() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 256];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("HEAD / HTTP/1.0\r\n"));
            stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        });
        let banner = identify_service_banner(address, 80, Duration::from_secs(1), 64).unwrap();
        worker.join().unwrap();
        assert!(banner.starts_with(b"HTTP/1.0 200 OK"));
    }

    #[test]
    fn tcp_connect_works_with_loopback_listener() {
        use std::net::TcpListener;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stream = tcp_connect(&address, Duration::from_secs(1)).unwrap();
        assert_eq!(stream.peer_addr().unwrap(), address);
    }

    #[test]
    fn udp_exchange_round_trips_with_loopback_echo_server() {
        use std::net::UdpSocket;
        use std::thread;
        use std::time::Duration;
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut request = [0u8; 32];
            let (count, peer) = server.recv_from(&mut request).unwrap();
            server.send_to(&request[..count], peer).unwrap();
        });
        let response = udp_exchange(address, b"infernex-test", Duration::from_secs(1), 64).unwrap();
        worker.join().unwrap();
        assert_eq!(response, b"infernex-test");
    }

    #[test]
    fn resolver_rejects_url_and_path_inputs() {
        assert_eq!(resolve_hostname("https://example.com").unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(resolve_hostname("../etc/hosts").unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

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
        assert_eq!(classify_service_banner(443, b"SSH-2.0-OpenSSH_9.0\r\n"), "SSH");
        assert_eq!(classify_service_banner(22, b"HTTP/1.1 200 OK\r\n"), "HTTP");
        assert_eq!(classify_service_banner(12345, b"+OK POP3 ready\r\n"), "POP3");
        assert_eq!(classify_service_banner(25, b"220 mail.example ESMTP ready\r\n"), "SMTP");
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
