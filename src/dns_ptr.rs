//! Minimal UDP DNS client for reverse lookups (PTR records).
//!
//! Deliberately dependency-free: one hand-written query builder and response
//! parser, used by `neton device` to fetch a LAN device's hostname without
//! shelling out to `nslookup`. Only PTR is supported — forward DNS uses the
//! system resolver via `std::net::ToSocketAddrs`.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

/// Reverse-DNS name for an IPv4 address, e.g. `1.168.192.in-addr.arpa`.
pub fn ptr_name(ip: &Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Encode a minimal PTR query for `name` (ID 0 is fine for our one-shot use).
fn build_query(name: &str) -> Vec<u8> {
    // 12-byte header: ID=0, flags RD=1 (0x0100), QDCOUNT=1.
    let mut out = vec![0u8, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&12u16.to_be_bytes()); // QTYPE = PTR
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    out
}

/// Decode all names starting at `pos`, following compression pointers.
fn decode_name(packet: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = pos;
    let mut jumped = false;
    let mut next = pos;
    for _ in 0..64 {
        let len = *packet.get(pos)? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    if !jumped {
                        next = pos + 1;
                    }
                    break;
                }
                let end = pos + 1 + len;
                let raw = packet.get(pos + 1..end)?;
                labels.push(String::from_utf8_lossy(raw).into_owned());
                pos = end;
            }
            0xC0 => {
                let offset = ((len & 0x3F) << 8) | (*packet.get(pos + 1)? as usize);
                if !jumped {
                    next = pos + 2;
                    jumped = true;
                }
                pos = offset;
            }
            _ => return None,
        }
    }
    (!labels.is_empty() || !jumped).then(|| (labels.join("."), next))
}

/// Parse a PTR response and return the first PTR record's target name.
fn parse_response(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 || (packet[2] & 0x80) == 0 || (packet[3] & 0x0F) != 0 {
        return None; // truncated / not a response (QR bit clear) / non-zero RCODE
    }
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    if answers == 0 {
        return None;
    }
    // Skip header + question section.
    let mut pos = 12;
    let _qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    for _ in 0.._qdcount {
        let (_, next) = decode_name(packet, pos)?;
        pos = next + 4; // QTYPE + QCLASS
    }
    for _ in 0..answers {
        let (_, next) = decode_name(packet, pos)?;
        pos = next;
        let rtype = u16::from_be_bytes([*packet.get(pos)?, *packet.get(pos + 1)?]);
        let rdlength = u16::from_be_bytes([*packet.get(pos + 8)?, *packet.get(pos + 9)?]) as usize;
        pos += 10;
        let rdata = packet.get(pos..pos + rdlength)?;
        if rtype == 12 {
            let (name, _) = decode_name(packet, pos)?;
            return Some(name.trim_end_matches('.').to_string());
        }
        pos += rdlength;
        let _ = rdata;
    }
    None
}

/// Ask `server` for the PTR of `ip`. Returns the hostname when a PTR record
/// exists; `None` on timeouts, NXDOMAIN or malformed answers.
pub fn resolve_ptr(ip: &IpAddr, server: IpAddr, timeout: Duration) -> Option<String> {
    let v4 = match ip {
        IpAddr::V4(v4) => *v4,
        // PTR for IPv6 (ip6.arpa nibbles) is out of scope for LAN use.
        IpAddr::V6(_) => return None,
    };
    let query_name = ptr_name(&v4);
    let query = build_query(&query_name);

    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;
    let target = std::net::SocketAddr::new(server, 53);
    socket.send_to(&query, target).ok()?;
    let mut buf = [0u8; 512];
    let len = socket.recv(&mut buf).ok()?;
    parse_response(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_name_reverses_octets() {
        assert_eq!(
            ptr_name(&Ipv4Addr::new(192, 168, 1, 10)),
            "10.1.168.192.in-addr.arpa"
        );
    }

    #[test]
    fn query_encodes_labels_and_ptr_type() {
        let query = build_query("10.1.168.192.in-addr.arpa");
        assert_eq!(&query[2..4], &[0x01, 0x00]); // flags: RD=1 (big-endian 0x0100)
        assert_eq!(&query[4..6], &[0, 1]); // QDCOUNT = 1
        assert!(query.ends_with(&[0, 12, 0, 1]));
    }

    #[test]
    fn parses_ptr_answer_with_compression() {
        // Hand-crafted response: header + question (name by pointer to its own
        // answer encoding is overkill here, so inline labels) + one answer
        // whose RDATA uses a compression pointer back to a label.
        let mut packet = vec![0u8, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        let question_start = packet.len();
        packet.extend_from_slice(b"\x0210\x011\x011\x03192\x07in-addr\x04arpa\x00");
        packet.extend_from_slice(&12u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        // Answer: pointer to question name, type PTR, class IN, TTL, RDLEN
        packet.extend_from_slice(&[0xC0, question_start as u8]);
        packet.extend_from_slice(&12u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 60]); // TTL
                                                  // RDATA: my-router.local (2 labels)
        packet.extend_from_slice(&[0, 15]);
        packet.extend_from_slice(b"\x09my-router\x05local\x00");
        let name = parse_response(&packet).expect("parsed name");
        assert_eq!(name, "my-router.local");
    }

    #[test]
    fn parses_nxdomain_as_none() {
        let packet = [0u8, 0, 0x81, 0x83, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_response(&packet).is_none());
    }

    #[test]
    fn ipv6_is_out_of_scope() {
        assert_eq!(
            resolve_ptr(
                &"::1".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                Duration::from_millis(50)
            ),
            None
        );
    }
}
