//! NyaTerm Plus: `hysteria2://`, `hy2://` and `trojan://` share links.
//!
//! Deliberately not built on a URL parser: real links often carry unescaped `@`, `/` or `#`
//! in the password, which a URL parser either rejects or splits in the wrong place. Fields
//! that cannot be parsed are left empty so the user can fix them in the form instead of losing
//! the whole link.

use crate::models::ProxyNodeOptions;

const DEFAULT_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProxyLink {
    /// `hysteria2` or `trojan`, the stored proxy protocol.
    pub protocol: &'static str,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub password: String,
    pub node: ProxyNodeOptions,
}

/// Proxy protocols that run through a local sing-box.
pub fn is_node_protocol(protocol: &str) -> bool {
    matches!(protocol, "hysteria2" | "trojan")
}

pub fn parse_proxy_link(text: &str) -> Option<ParsedProxyLink> {
    let trimmed = text.trim();
    let (scheme, rest) = trimmed.split_once("://")?;
    let protocol = match scheme.to_ascii_lowercase().as_str() {
        "hysteria2" | "hy2" => "hysteria2",
        "trojan" => "trojan",
        _ => return None,
    };

    // Strip the fragment before the query so a `?` inside the name is not taken as a query.
    let (rest, name) = match rest.split_once('#') {
        Some((rest, name)) => (rest, decode(name)),
        None => (rest, String::new()),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((rest, query)) => (rest, parse_query(query)),
        None => (rest, Vec::new()),
    };
    let rest = rest.trim_end_matches('/');

    // Split on the last `@`: passwords often contain unescaped `@`, host names never do.
    let (user_info, address) = match rest.rfind('@') {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => ("", rest),
    };
    let (host, port, hop_in_host) = split_host_port(address);
    if host.is_empty() {
        return None;
    }

    // Hysteria2 allows `user:pass`; the part after the colon is the auth password.
    let raw_password = match (protocol, user_info.split_once(':')) {
        ("hysteria2", Some((_, password))) => password,
        _ => user_info,
    };

    let lookup = |keys: &[&str]| {
        keys.iter().find_map(|key| {
            query
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        })
    };
    let mut node = ProxyNodeOptions {
        sni: lookup(&["sni", "peer"]),
        allow_insecure: lookup(&["insecure", "allowinsecure"]).is_some_and(|value| is_true(&value)),
        ..ProxyNodeOptions::default()
    };
    if protocol == "hysteria2" {
        node.obfs_password = lookup(&["obfs-password", "obfs_password"]).map(Into::into);
        // The `mport` query (official client / NekoBox) wins over a range in the port slot.
        let hop_ports = lookup(&["mport", "ports"])
            .map(|raw| normalize_hop_ports(&raw))
            .unwrap_or(hop_in_host);
        node.hop_ports = (!hop_ports.is_empty()).then_some(hop_ports);
        node.up_mbps = lookup(&["upmbps", "up"]).and_then(|value| positive_int(&value));
        node.down_mbps = lookup(&["downmbps", "down"]).and_then(|value| positive_int(&value));
    }

    Some(ParsedProxyLink {
        protocol,
        name,
        host,
        port,
        password: decode(raw_password),
        node,
    })
}

/// Normalizes hop port ranges to `a-b,c`; returns an empty string when nothing is valid.
pub fn normalize_hop_ports(raw: &str) -> String {
    raw.split(',')
        .filter_map(|segment| {
            let segment = segment.trim().replace(':', "-");
            let bounds = segment.split('-').collect::<Vec<_>>();
            match bounds.as_slice() {
                [single] => parse_port(single).map(|port| port.to_string()),
                [start, end] => match (parse_port(start), parse_port(end)) {
                    (Some(start), Some(end)) if start <= end => Some(format!("{start}-{end}")),
                    _ => None,
                },
                _ => None,
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Splits `host:port`; a range in the port slot (`20000-50000`) means port hopping, and its
/// first port becomes the fixed port.
fn split_host_port(value: &str) -> (String, u16, String) {
    // IPv6 literals are written as `[::1]:443`.
    if let Some(inner) = value.strip_prefix('[')
        && let Some((host, after)) = inner.split_once(']')
    {
        let (port, hop) = port_from_token(after.trim_start_matches(':'));
        return (host.to_string(), port, hop);
    }
    match value.rsplit_once(':') {
        Some((host, token)) => {
            let (port, hop) = port_from_token(token);
            (host.to_string(), port, hop)
        }
        None => (value.to_string(), DEFAULT_PORT, String::new()),
    }
}

fn port_from_token(token: &str) -> (u16, String) {
    let token = token.trim();
    if token.chars().all(|ch| ch.is_ascii_digit())
        && let Some(port) = parse_port(token)
    {
        return (port, String::new());
    }
    let hop = normalize_hop_ports(token);
    let first = hop
        .split([',', '-'])
        .next()
        .and_then(parse_port)
        .unwrap_or(DEFAULT_PORT);
    (first, hop)
}

fn parse_port(value: &str) -> Option<u16> {
    positive_int(value).and_then(|port| u16::try_from(port).ok())
}

fn positive_int(value: &str) -> Option<u32> {
    let value = value.trim();
    if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    value.parse::<u32>().ok().filter(|value| *value > 0)
}

/// Lower-cased keys in order; empty values are dropped and the first occurrence wins.
fn parse_query(query: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = key.to_ascii_lowercase();
        let value = decode(value);
        if !key.is_empty() && !value.is_empty() && !pairs.iter().any(|(name, _)| *name == key) {
            pairs.push((key, value));
        }
    }
    pairs
}

fn is_true(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

/// Percent-decodes; `+` stays literal because base64-style passwords contain it unescaped.
/// Text that is not valid UTF-8 after decoding is returned as it was.
fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let Some(hex) = value.get(index + 1..index + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use crate::proxy_link::{normalize_hop_ports, parse_proxy_link};

    #[test]
    fn parses_hysteria2_link_with_options() {
        let link = parse_proxy_link(
            "hy2://p%40ss@203.0.113.7:20000-50000/?sni=cdn.example.com&insecure=1\
             &obfs=salamander&obfs-password=ob%2Bfs&upmbps=50#My%20node",
        )
        .unwrap();
        assert_eq!(link.protocol, "hysteria2");
        assert_eq!(link.name, "My node");
        assert_eq!(link.host, "203.0.113.7");
        assert_eq!(link.port, 20000);
        assert_eq!(link.password, "p@ss");
        assert_eq!(link.node.sni.as_deref(), Some("cdn.example.com"));
        assert!(link.node.allow_insecure);
        assert_eq!(
            link.node
                .obfs_password
                .as_ref()
                .map(|value| value.expose_secret()),
            Some("ob+fs")
        );
        assert_eq!(link.node.hop_ports.as_deref(), Some("20000-50000"));
        assert_eq!(link.node.up_mbps, Some(50));
        assert_eq!(link.node.down_mbps, None);
    }

    #[test]
    fn mport_query_wins_and_user_prefix_is_dropped() {
        let link =
            parse_proxy_link("hysteria2://user:secret@[2001:db8::1]:443?mport=30000:40000,443")
                .unwrap();
        assert_eq!(link.host, "2001:db8::1");
        assert_eq!(link.port, 443);
        assert_eq!(link.password, "secret");
        assert_eq!(link.node.hop_ports.as_deref(), Some("30000-40000,443"));
    }

    #[test]
    fn parses_trojan_link_without_hysteria_fields() {
        let link =
            parse_proxy_link("trojan://pa@ss@node.example.com?peer=sni.example.com&mport=1-2")
                .unwrap();
        assert_eq!(link.protocol, "trojan");
        assert_eq!(link.password, "pa@ss");
        assert_eq!(link.port, 443);
        assert_eq!(link.node.sni.as_deref(), Some("sni.example.com"));
        assert_eq!(link.node.hop_ports, None);
    }

    #[test]
    fn rejects_other_schemes_and_empty_hosts() {
        assert!(parse_proxy_link("vmess://abc").is_none());
        assert!(parse_proxy_link("hy2://secret@").is_none());
        assert!(parse_proxy_link("203.0.113.7:443").is_none());
    }

    #[test]
    fn hop_ports_drop_invalid_segments() {
        assert_eq!(
            normalize_hop_ports("1000:2000,abc,3000-2000,0,443"),
            "1000-2000,443"
        );
        assert_eq!(normalize_hop_ports(" , "), "");
    }
}
