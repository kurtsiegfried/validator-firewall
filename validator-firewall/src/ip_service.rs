use anyhow::{anyhow, Context};
use aya::maps::{HashMap, Map, MapData};
use cidr::Ipv4Cidr;
use duckdb::params;
use log::{debug, error, info, warn};
use rangemap::RangeInclusiveSet;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

const DENY_LIST_SIZE: u32 = 524288;
const DYNAMIC_LIST_BUFFER: u32 = 1024;
const DENY_LIST_CAP: usize = (DENY_LIST_SIZE - DYNAMIC_LIST_BUFFER) as usize;
const POLL_INTERVAL: Duration = Duration::from_secs(10);

pub struct HttpDenyListClient {
    url: String,
    client: reqwest::Client,
}

impl HttpDenyListClient {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
        }
    }
}

impl DenyListClient for HttpDenyListClient {
    async fn get_deny_list(&self) -> anyhow::Result<Vec<Ipv4Cidr>> {
        let resp = self
            .client
            .get(&self.url)
            .send()
            .await
            .context("HTTP request to deny-list service failed")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "deny-list service returned non-success status: {}",
                resp.status()
            ));
        }
        let deny_list: Vec<Ipv4Cidr> = resp
            .json()
            .await
            .context("failed to decode deny-list JSON")?;
        info!(
            "Retrieved {} CIDRs from external ip service",
            deny_list.len()
        );
        Ok(deny_list)
    }
}

pub struct DuckDbDenyListClient {
    conn: Arc<Mutex<duckdb::Connection>>,
    query: String,
}

impl DuckDbDenyListClient {
    pub fn new(query: String) -> Self {
        Self {
            conn: Arc::new(Mutex::new(
                duckdb::Connection::open_in_memory()
                    .expect("failed to open in-memory duckdb connection"),
            )),
            query,
        }
    }
}

impl DenyListClient for DuckDbDenyListClient {
    async fn get_deny_list(&self) -> anyhow::Result<Vec<Ipv4Cidr>> {
        info!("Executing query: {}", self.query);

        let conn = self.conn.clone();
        let query = self.query.clone();

        // duckdb operations are synchronous; run them on the blocking pool so
        // the async runtime is not stalled.
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Ipv4Cidr>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(&query).context("duckdb prepare failed")?;
            let mut rows = stmt.query(params![]).context("duckdb query failed")?;
            let mut deny_list = Vec::new();
            while let Some(row) = rows.next().context("duckdb row fetch failed")? {
                let ip: u32 = row.get(0).context("duckdb row missing u32 column 0")?;
                let converted: Ipv4Addr = ip.into();
                let cidr = Ipv4Cidr::new(converted, 32)
                    .context("failed to construct /32 from row value")?;
                deny_list.push(cidr);
            }
            info!("Retrieved {} IPs from query", deny_list.len());
            Ok(deny_list)
        })
        .await
        .context("duckdb spawn_blocking task panicked")?
    }
}

pub struct NoOpDenyListClient;

impl DenyListClient for NoOpDenyListClient {
    async fn get_deny_list(&self) -> anyhow::Result<Vec<Ipv4Cidr>> {
        Ok(Vec::new())
    }
}

pub trait DenyListClient {
    async fn get_deny_list(&self) -> anyhow::Result<Vec<Ipv4Cidr>>;
}

pub struct DenyListService<T: DenyListClient> {
    deny_list_client: T,
}

impl<T: DenyListClient> DenyListService<T> {
    pub fn new(client: T) -> Self {
        Self {
            deny_list_client: client,
        }
    }

    pub async fn get_deny_list(&self) -> anyhow::Result<Vec<Ipv4Cidr>> {
        self.deny_list_client.get_deny_list().await
    }
}

pub struct DenyListStateUpdater<T: DenyListClient> {
    exit_flag: Arc<AtomicBool>,
    deny_service: Arc<DenyListService<T>>,
    static_allow_ranges: RangeInclusiveSet<u32>,
    static_deny_ranges: RangeInclusiveSet<u32>,
    static_deny_cidrs: Arc<HashSet<Ipv4Cidr>>,
}

pub fn to_range(ip: Ipv4Cidr) -> RangeInclusive<u32> {
    let start_addr: u32 = ip.first_address().into();
    let end_addr: u32 = ip.last_address().into();
    start_addr..=end_addr
}

impl<T: DenyListClient> DenyListStateUpdater<T> {
    pub fn new(
        exit_flag: Arc<AtomicBool>,
        deny_service: Arc<DenyListService<T>>,
        static_overrides: Arc<(HashSet<Ipv4Cidr>, HashSet<Ipv4Cidr>)>,
    ) -> Self {
        Self {
            exit_flag,
            deny_service,
            static_allow_ranges: RangeInclusiveSet::from_iter(
                static_overrides.0.iter().copied().map(to_range),
            ),
            static_deny_ranges: RangeInclusiveSet::from_iter(
                static_overrides.1.iter().copied().map(to_range),
            ),
            static_deny_cidrs: Arc::new(static_overrides.1.clone()),
        }
    }

    pub fn is_statically_denied(&self, addr: &u32) -> bool {
        self.static_deny_ranges.contains(addr)
    }

    pub fn is_statically_allowed(&self, addr: &u32) -> bool {
        self.static_allow_ranges.contains(addr)
    }

    /// Seeds the BPF deny map with the expanded static-deny entries, capped at
    /// `DENY_LIST_CAP` to leave headroom for dynamic entries.
    fn seed_static_deny(&self, deny_map: &mut HashMap<MapData, u32, u8>) -> anyhow::Result<()> {
        let mut count: usize = 0;
        let mut truncated = false;
        'outer: for cidr in self.static_deny_cidrs.iter() {
            for ip in cidr.into_iter().addresses() {
                if count >= DENY_LIST_CAP {
                    truncated = true;
                    break 'outer;
                }
                let ip_numeric: u32 = u32::from(ip);
                if self.is_statically_allowed(&ip_numeric) {
                    continue;
                }
                if let Err(e) = deny_map.insert(ip_numeric, 0u8, 0) {
                    warn!("failed to seed static deny entry {ip}: {e}");
                    continue;
                }
                count += 1;
            }
        }
        if truncated {
            error!(
                "Static deny list exceeds {} entries; truncating. Excess hosts will not be blocked.",
                DENY_LIST_CAP
            );
        }
        info!(
            "Seeded {} addresses into deny list from static overrides",
            count
        );
        Ok(())
    }

    pub async fn run(&self, deny_map: Map) {
        let mut deny_map: HashMap<_, u32, u8> = match HashMap::try_from(deny_map) {
            Ok(m) => m,
            Err(e) => {
                error!("failed to bind deny map: {e}");
                return;
            }
        };

        if let Err(e) = self.seed_static_deny(&mut deny_map) {
            error!("failed to seed static deny list: {e}");
        }

        let mut dynamic_deny_set: HashSet<u32> = HashSet::new();
        while !self.exit_flag.load(Ordering::Relaxed) {
            match self.deny_service.get_deny_list().await {
                Ok(nodes) => {
                    self.refresh_dynamic_deny(&mut deny_map, &mut dynamic_deny_set, &nodes);
                }
                Err(e) => {
                    error!("Error fetching deny list: {e:#}");
                }
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    fn refresh_dynamic_deny(
        &self,
        deny_map: &mut HashMap<MapData, u32, u8>,
        dynamic_deny_set: &mut HashSet<u32>,
        nodes: &[Ipv4Cidr],
    ) {
        dynamic_deny_set.clear();
        for cidr in nodes {
            for ip4addr in cidr.into_iter().addresses() {
                let ip_numeric: u32 = u32::from(ip4addr);
                if !self.is_statically_allowed(&ip_numeric) {
                    dynamic_deny_set.insert(ip_numeric);
                }
            }
        }

        let to_remove: Vec<u32> = deny_map
            .iter()
            .filter_map(Result::ok)
            .filter(|(addr, _)| !dynamic_deny_set.contains(addr))
            .filter(|(addr, _)| !self.is_statically_denied(addr))
            .map(|(addr, _)| addr)
            .collect();

        debug!("Pruning {} ips from deny list", to_remove.len());
        for ip in to_remove {
            if let Err(e) = deny_map.remove(&ip) {
                warn!("failed to remove {ip} from deny map: {e}");
            }
        }

        for ip in dynamic_deny_set.iter() {
            if deny_map.get(ip, 0).is_err() {
                if let Err(e) = deny_map.insert(ip, 0u8, 0) {
                    warn!("failed to insert {ip} into deny map: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rangemap::RangeInclusiveSet;
    use std::str::FromStr;

    #[test]
    fn test_inet_ranges() {
        let mut deny_range = RangeInclusiveSet::new();
        let single_host = Ipv4Cidr::from_str("1.1.1.1/32").unwrap();

        let start_addr: u32 = single_host.first().address().into();
        let end_addr: u32 = single_host.last().address().into();
        deny_range.insert(start_addr..=end_addr);

        assert!(deny_range.contains(&start_addr));
    }

    #[test]
    fn test_range_coalescing() {
        let mut deny_range = RangeInclusiveSet::new();
        let first_host = Ipv4Cidr::from_str("1.1.1.1/32").unwrap();
        let adjacent_host = Ipv4Cidr::from_str("1.1.1.2/32").unwrap();

        let bare_host = Ipv4Cidr::from_str("192.168.1.1").unwrap();
        assert!(bare_host.is_host_address());

        let start_addr: u32 = first_host.first().address().into();
        let end_addr: u32 = first_host.last().address().into();
        deny_range.insert(start_addr..=end_addr);

        let start_addr: u32 = adjacent_host.first().address().into();
        let end_addr: u32 = adjacent_host.last().address().into();
        deny_range.insert(start_addr..=end_addr);
        assert_eq!(deny_range.len(), 1);
    }

    struct StaticClient {
        nodes: Vec<Ipv4Cidr>,
    }

    impl DenyListClient for StaticClient {
        async fn get_deny_list(&self) -> anyhow::Result<Vec<Ipv4Cidr>> {
            Ok(self.nodes.clone())
        }
    }

    fn cidr(s: &str) -> Ipv4Cidr {
        Ipv4Cidr::from_str(s).unwrap()
    }

    #[test]
    fn static_overrides_populate_ranges() {
        let allow: HashSet<Ipv4Cidr> = [cidr("10.0.0.1/32"), cidr("10.0.0.2/32")]
            .into_iter()
            .collect();
        let deny: HashSet<Ipv4Cidr> = [cidr("192.168.0.0/30")].into_iter().collect();
        let updater = DenyListStateUpdater::new(
            Arc::new(AtomicBool::new(false)),
            Arc::new(DenyListService::new(StaticClient { nodes: vec![] })),
            Arc::new((allow, deny)),
        );

        let allowed: u32 = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let not_allowed: u32 = u32::from(Ipv4Addr::new(10, 0, 0, 3));
        let denied: u32 = u32::from(Ipv4Addr::new(192, 168, 0, 2));
        let not_denied: u32 = u32::from(Ipv4Addr::new(192, 168, 0, 5));

        assert!(updater.is_statically_allowed(&allowed));
        assert!(!updater.is_statically_allowed(&not_allowed));
        assert!(updater.is_statically_denied(&denied));
        assert!(!updater.is_statically_denied(&not_denied));
    }
}
