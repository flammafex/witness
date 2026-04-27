use std::net::{IpAddr, SocketAddr};

use hyper::client::connect::dns::Name;
use reqwest::dns::{Addrs, Resolve, Resolving};

#[derive(Debug, Clone)]
pub struct SafeResolver;

#[derive(Debug, thiserror::Error)]
pub enum SafeResolverError {
    #[error("SSRF blocked: private IP {ip} resolved for {host}")]
    PrivateIpBlocked { ip: IpAddr, host: String },
    #[error("DNS resolution failed for {host}: {source}")]
    ResolutionFailed { host: String, source: std::io::Error },
    #[error("No addresses found for {host}")]
    NoAddresses { host: String },
}

impl SafeResolver {
    pub fn new() -> Self {
        Self
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 169.254.0.0/16 (link-local / cloud metadata)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fe80::/10 (IPv6 link-local)
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // fc00::/7 (IPv6 unique local)
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            false
        }
    }
}

fn is_whitelisted(host: &str) -> bool {
    let host_lower = host.to_lowercase();
    host_lower.ends_with(".internal")
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".docker")
        || host_lower.ends_with(".svc")
        || host_lower.ends_with(".cluster.local")
}

pub async fn resolve_safe(host: &str) -> Result<Vec<SocketAddr>, SafeResolverError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:0", host))
        .await
        .map_err(|e| SafeResolverError::ResolutionFailed {
            host: host.to_string(),
            source: e,
        })?
        .collect();

    if addrs.is_empty() {
        return Err(SafeResolverError::NoAddresses {
            host: host.to_string(),
        });
    }

    let whitelisted = is_whitelisted(host);

    if !whitelisted {
        for addr in &addrs {
            if is_private_ip(addr.ip()) {
                return Err(SafeResolverError::PrivateIpBlocked {
                    ip: addr.ip(),
                    host: host.to_string(),
                });
            }
        }
    }

    Ok(addrs)
}

impl Resolve for SafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.to_string();
        Box::pin(async move {
            match resolve_safe(&host).await {
                Ok(addrs) => {
                    let addrs: Addrs = Box::new(addrs.into_iter());
                    Ok(addrs)
                }
                Err(e) => {
                    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, e);
                    Err(Box::new(io_err) as Box<dyn std::error::Error + Send + Sync>)
                }
            }
        })
    }
}

impl Default for SafeResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_safe_blocks_loopback() {
        let result = resolve_safe("127.0.0.1").await;
        assert!(result.is_err(), "Expected error for 127.0.0.1");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("SSRF blocked"),
            "Error should mention SSRF: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_resolve_safe_blocks_private_10() {
        let result = resolve_safe("10.0.0.1").await;
        assert!(result.is_err(), "Expected error for 10.0.0.1");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("SSRF blocked"),
            "Error should mention SSRF: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_resolve_safe_blocks_private_172() {
        let result = resolve_safe("172.16.0.1").await;
        assert!(result.is_err(), "Expected error for 172.16.0.1");
    }

    #[tokio::test]
    async fn test_resolve_safe_blocks_private_192() {
        let result = resolve_safe("192.168.1.1").await;
        assert!(result.is_err(), "Expected error for 192.168.1.1");
    }

    #[tokio::test]
    async fn test_resolve_safe_allows_public_ip_literal() {
        let result = resolve_safe("1.1.1.1").await;
        assert!(
            result.is_ok(),
            "1.1.1.1 should be allowed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_resolve_safe_allows_public_hostname() {
        let result = resolve_safe("example.com").await;
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("SSRF blocked"),
                "example.com should not be SSRF-blocked: {}",
                msg
            );
        }
    }

    #[tokio::test]
    async fn test_whitelist_patterns() {
        assert!(is_whitelisted("witness.internal"));
        assert!(is_whitelisted("app.svc"));
        assert!(is_whitelisted("service.cluster.local"));
        assert!(is_whitelisted("myhost.local"));
        assert!(is_whitelisted("container.docker"));

        assert!(!is_whitelisted("example.com"));
        assert!(!is_whitelisted("attacker.internal.evil.com"));
    }

    #[tokio::test]
    async fn test_safe_resolver_trait_blocks_private() {
        let resolver = SafeResolver::new();
        let name: Name = "10.0.0.1".parse().expect("valid name");
        let result = resolver.resolve(name).await;
        assert!(result.is_err(), "SafeResolver should block 10.0.0.1");
    }

    #[tokio::test]
    async fn test_safe_resolver_trait_allows_public() {
        let resolver = SafeResolver::new();
        let name: Name = "1.1.1.1".parse().expect("valid name");
        let result = resolver.resolve(name).await;
        assert!(
            result.is_ok(),
            "SafeResolver should allow 1.1.1.1: {:?}",
            result.err()
        );
    }
}
