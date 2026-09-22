//! Resolution for passthrough, forced through a public resolver.
//!
//! The system resolver is unusable while interception is on: our hosts entries point every
//! target back at ourselves, so asking the OS where `codewhisperer.us-east-1.amazonaws.com`
//! lives would just loop. We query 8.8.8.8 directly and cache the answer briefly.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

use crate::{Error, Result};

const TTL: Duration = Duration::from_secs(300);
const UPSTREAM: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

#[derive(Clone)]
struct Cached {
    ips: Arc<Vec<IpAddr>>,
    at: Instant,
}

pub struct DnsResolver {
    resolver: TokioResolver,
    cache: DashMap<String, Cached>,
}

/// Resolver options that make "ask 8.8.8.8" mean exactly that.
///
/// Pointing the resolver at a public nameserver is not enough on its own: hickory still reads
/// the system hosts file first (`ResolveHosts::Auto`), and that file is the very thing we
/// rewrote to point these hostnames at ourselves. Left at the default, passthrough dials
/// 127.0.0.1, lands back on our own listener, and fails the handshake it just made — the proxy
/// talking to itself while the IDE waits.
fn resolver_opts() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = ResolveHosts::Never;
    opts
}

impl DnsResolver {
    pub fn new() -> Result<Self> {
        let config =
            ResolverConfig::from_name_servers(vec![NameServerConfig::udp_and_tcp(UPSTREAM)]);
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        *builder.options_mut() = resolver_opts();
        let resolver = builder
            .build()
            .map_err(|e| Error::Provider(format!("dns resolver init: {e}")))?;
        Ok(Self {
            resolver,
            cache: DashMap::new(),
        })
    }

    /// Resolve `host` to its address list, IPv4 first, cached for [`TTL`]. The caller tries
    /// the addresses in order — caching a single one would strand us if that address dies.
    pub async fn resolve(&self, host: &str) -> Result<Arc<Vec<IpAddr>>> {
        if let Some(hit) = self.cache.get(host) {
            if hit.at.elapsed() < TTL {
                return Ok(hit.ips.clone());
            }
        }

        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| Error::Provider(format!("dns lookup for {host}: {e}")))?;
        let mut v4: Vec<IpAddr> = Vec::new();
        let mut v6: Vec<IpAddr> = Vec::new();
        for ip in lookup.iter() {
            if ip.is_ipv4() {
                v4.push(ip);
            } else {
                v6.push(ip);
            }
        }
        v4.extend(v6);
        if v4.is_empty() {
            return Err(Error::Provider(format!("no address for {host}")));
        }
        let ips = Arc::new(v4);

        self.cache.insert(
            host.to_string(),
            Cached {
                ips: ips.clone(),
                at: Instant::now(),
            },
        );
        Ok(ips)
    }

    /// Insert a cached answer. Intended for tests, so passthrough can target a local mock
    /// upstream without touching the network.
    pub fn seed(&self, host: &str, ips: Vec<IpAddr>) {
        self.cache.insert(
            host.to_string(),
            Cached {
                ips: Arc::new(ips),
                at: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upstream_resolver_never_reads_the_hijacked_hosts_file() {
        assert_eq!(
            resolver_opts().use_hosts_file,
            ResolveHosts::Never,
            "reading /etc/hosts here sends passthrough traffic back into our own listener"
        );
    }
}
