use std::net::{IpAddr, SocketAddr};

/// Determine the real client IP.
///
/// When `behind_proxy` is `true`, reads the leftmost entry of the
/// `X-Forwarded-For` header, which is the original client address as set by a
/// trusted reverse proxy.  Falls back to the socket address if the header is
/// absent or unparseable.
///
/// When `behind_proxy` is `false` (direct-connect mode), returns the TCP
/// socket address unconditionally.  Using the header in direct mode would let
/// any client spoof its IP to bypass rate limiting.
pub fn real_ip(
    headers: &axum::http::HeaderMap,
    socket_addr: SocketAddr,
    behind_proxy: bool,
) -> IpAddr {
    if behind_proxy {
        if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // Take the leftmost (original client) address
            if let Some(first) = forwarded.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    socket_addr.ip()
}
