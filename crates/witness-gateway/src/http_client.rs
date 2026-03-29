use anyhow::{bail, Result};
use std::net::IpAddr;

/// Build a hardened reqwest Client.
/// Sets https_only unless allow_http is true (for dev/testing only).
pub fn build_client(allow_http: bool) -> reqwest::Client {
    reqwest::Client::builder()
        .https_only(!allow_http)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client")
}

/// Validate a URL before sending an outbound request.
/// Rejects loopback, RFC-1918 private ranges, and link-local addresses
/// to prevent Server-Side Request Forgery (SSRF).
pub fn validate_outbound_url(url: &str) -> Result<()> {
    let parsed = url
        .parse::<reqwest::Url>()
        .map_err(|e| anyhow::anyhow!("Invalid URL '{}': {}", url, e))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {}", url))?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        check_ip_allowed(ip)?;
    } else {
        use std::net::ToSocketAddrs;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let addrs = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("DNS resolution failed for '{}': {}", host, e))?;
        for addr in addrs {
            check_ip_allowed(addr.ip())?;
        }
    }

    Ok(())
}

fn check_ip_allowed(ip: IpAddr) -> Result<()> {
    if ip.is_loopback() {
        bail!("SSRF blocked: loopback address {}", ip);
    }
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                bail!("SSRF blocked: private address {}", ip);
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                bail!("SSRF blocked: private address {}", ip);
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                bail!("SSRF blocked: private address {}", ip);
            }
            // 169.254.0.0/16 (link-local / cloud metadata)
            if octets[0] == 169 && octets[1] == 254 {
                bail!("SSRF blocked: link-local/metadata address {}", ip);
            }
        }
        IpAddr::V6(v6) => {
            // fe80::/10 (IPv6 link-local)
            let segments = v6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                bail!("SSRF blocked: IPv6 link-local address {}", ip);
            }
            // fc00::/7 (IPv6 unique local)
            if (segments[0] & 0xfe00) == 0xfc00 {
                bail!("SSRF blocked: IPv6 unique-local address {}", ip);
            }
        }
    }
    Ok(())
}
