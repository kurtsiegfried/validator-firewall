mod ip_service;
mod stats_service;

mod config;
mod leader_tracker;

use crate::config::{load_static_overrides, NameAddressPair};
use crate::ip_service::{
    DenyListService, DenyListStateUpdater, DuckDbDenyListClient, HttpDenyListClient,
    NoOpDenyListClient,
};
use crate::leader_tracker::{CommandControlService, RPCLeaderTracker};
use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::{lpm_trie::Key as LpmKey, HashMap, LpmTrie},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use cidr::Ipv4Cidr;
use clap::Parser;
use log::{debug, error, info, warn};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::signal;

#[derive(Debug, Parser)]
struct HVFConfig {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long)]
    static_overrides: Option<PathBuf>,
    #[clap(short, long, default_value = "http://localhost:8899")]
    rpc_endpoint: String,
    #[arg(short, long, value_name = "PORT", value_parser = clap::value_parser!(u16), num_args = 0..)]
    protected_ports: Vec<u16>,
    #[clap(short, long)]
    leader_id: Option<String>,
    #[clap(short, long)]
    external_ip_service_url: Option<String>,
    #[clap(short, long)]
    query_file: Option<PathBuf>,
    /// DEBUG ONLY: skip the RPC leader tracker and pin the firewall to
    /// "far from leader" mode. Used to exercise the LPM-allow datapath in
    /// isolation. Do not use in production.
    #[clap(long)]
    debug_force_far_from_leader: bool,
}

const DENY_LIST_MAP: &str = "hvf_deny_list";
const ALLOW_LIST_LPM_MAP: &str = "hvf_always_allow_lpm";
const PROTECTED_PORTS_MAP: &str = "hvf_protected_ports";
const CONNECTION_STATS: &str = "hvf_stats";
const CNC_ARRAY: &str = "hvf_cnc";

// Must match validator-firewall-ebpf ALLOW_LPM_SIZE.
const ALLOW_LPM_MAX_ENTRIES: usize = 1024;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config = HVFConfig::parse();

    tracing_subscriber::fmt().json().init();

    let static_overrides = {
        let mut local_allow = HashSet::new();
        let mut local_deny = HashSet::new();

        // Load static overrides if provided
        if let Some(path) = config.static_overrides {
            let overrides = load_static_overrides(path)?;
            let denied: HashSet<Ipv4Cidr> = overrides.deny.iter().map(|x| x.ip).collect();
            let intersection: Vec<&NameAddressPair> = overrides
                .allow
                .iter()
                .filter(|x| denied.contains(&x.ip))
                .collect();

            if !intersection.is_empty() {
                error!(
                    "Static overrides contain overlapping entries for deny and allow: {:?}",
                    intersection
                );
                std::process::exit(1);
            }
            for node in overrides.allow.iter() {
                local_allow.insert(node.ip);
            }
            for node in overrides.deny.iter() {
                local_deny.insert(node.ip);
            }

            info!("Loaded static overrides: {:?}", overrides);
        };
        Arc::new((local_allow, local_deny))
    };

    let protected_ports = if config.protected_ports.is_empty() {
        warn!("No protected ports provided, defaulting to 8009 and 8010");
        vec![8009, 8010]
    } else {
        config.protected_ports.clone()
    };

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/validator-firewall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/validator-firewall"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf
        .program_mut("validator_firewall")
        .context("eBPF program 'validator_firewall' missing from object")?
        .try_into()?;
    program.load()?;
    // Prefer native (driver) XDP — orders of magnitude better pps than SKB
    // mode. The eBPF program is declared `#[xdp(frags)]` so multi-buffer-
    // capable drivers (mlx5_core, ice, i40e, …) accept it on jumbo-frame
    // interfaces. SKB mode is kept as a defense-in-depth fallback for
    // interfaces whose driver lacks a native XDP path at all (e.g. r8169).
    if let Err(native_err) = program.attach(&config.iface, XdpFlags::DRV_MODE) {
        warn!(
            "native XDP attach on {} failed ({}); falling back to SKB mode \
             (significant pps loss — investigate driver/MTU)",
            &config.iface, native_err
        );
        program
            .attach(&config.iface, XdpFlags::SKB_MODE)
            .context("XDP attach failed in both native and SKB mode")?;
        info!("XDP attached on {} in SKB mode", &config.iface);
    } else {
        info!("XDP attached on {} in native (driver) mode", &config.iface);
    }

    info!("Filtering UDP ports: {:?}", protected_ports);
    push_ports_to_map(&mut bpf, protected_ports)?;
    push_allow_list_to_map(&mut bpf, &static_overrides.0)?;

    let exit = Arc::new(AtomicBool::new(false));
    let gossip_exit = exit.clone();

    let ip_svc_handle = if let Some(url) = config.external_ip_service_url {
        info!("Using external IP service: {}", url);
        let ip_service = HttpDenyListClient::new(url);
        let state_updater = DenyListStateUpdater::new(
            gossip_exit,
            Arc::new(DenyListService::new(ip_service)),
            static_overrides.clone(),
        );

        let map = bpf
            .take_map(DENY_LIST_MAP)
            .context("hvf_deny_list map missing from eBPF object")?;
        let state_updater_handle = tokio::spawn(async move {
            state_updater.run(map).await;
        });

        state_updater_handle
    } else if let Some(query_file) = config.query_file {
        //read contents of file to string
        let query = std::fs::read_to_string(query_file)?;

        let s_updater = DenyListStateUpdater::new(
            gossip_exit,
            Arc::new(DenyListService::new(DuckDbDenyListClient::new(query))),
            static_overrides.clone(),
        );

        let map = bpf
            .take_map(DENY_LIST_MAP)
            .context("hvf_deny_list map missing from eBPF object")?;
        let gossip_handle = tokio::spawn(async move {
            s_updater.run(map).await;
        });
        gossip_handle
    } else {
        //Default to no-op deny list client

        warn!("No deny list client specified, only using static overrides");
        let noop = NoOpDenyListClient {};
        let s_updater = DenyListStateUpdater::new(
            gossip_exit,
            Arc::new(DenyListService::new(noop)),
            static_overrides.clone(),
        );

        let map = bpf
            .take_map(DENY_LIST_MAP)
            .context("hvf_deny_list map missing from eBPF object")?;
        let gossip_handle = tokio::spawn(async move {
            s_updater.run(map).await;
        });
        gossip_handle
    };

    let cnc_map = bpf
        .take_map(CNC_ARRAY)
        .context("hvf_cnc map missing from eBPF object")?;

    // Either run the live leader tracker or pin the CnC to a debug mode.
    let (tracker_handle, tracker_service_handle) = if config.debug_force_far_from_leader {
        warn!(
            "--debug-force-far-from-leader: skipping RPC leader tracker; \
             pinning close_to_leader=false (LPM-allow datapath only)"
        );
        let mut cnc: aya::maps::Array<_, validator_firewall_common::RuntimeControls> =
            aya::maps::Array::try_from(cnc_map)?;
        cnc.set(
            0,
            validator_firewall_common::RuntimeControls {
                global_enabled: true,
                close_to_leader: false,
            },
            0,
        )?;
        // Spawn no-op tasks so the join shape downstream is unchanged.
        let noop_a = tokio::spawn(async {});
        let noop_b = tokio::spawn(async {});
        (noop_a, noop_b)
    } else {
        let tracker = Arc::new(RPCLeaderTracker::new(
            exit.clone(),
            RpcClient::new(config.rpc_endpoint.clone()),
            12,
            config.leader_id,
        ));
        let bg_tracker = tracker.clone();
        let tracker_handle = tokio::spawn(async move {
            bg_tracker.clone().run().await;
        });
        let mut tracker_service = CommandControlService::new(exit.clone(), tracker, cnc_map);
        let tracker_service_handle = tokio::spawn(async move {
            tracker_service.run().await;
        });
        (tracker_handle, tracker_service_handle)
    };

    //Start the stats service
    let stats_exit = exit.clone();
    let stats_map = bpf
        .take_map(CONNECTION_STATS)
        .context("hvf_stats map missing from eBPF object")?;
    let stats_service = stats_service::StatsService::new(stats_exit, 10, stats_map);
    let stats_handle = tokio::spawn(async move {
        stats_service.run().await;
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    exit.store(true, std::sync::atomic::Ordering::SeqCst);

    let results = tokio::join!(
        ip_svc_handle,
        stats_handle,
        tracker_handle,
        tracker_service_handle
    );
    log_task_join("ip_svc", results.0);
    log_task_join("stats", results.1);
    log_task_join("tracker", results.2);
    log_task_join("tracker_service", results.3);
    info!("Exiting...");

    Ok(())
}

fn log_task_join(name: &str, result: Result<(), tokio::task::JoinError>) {
    if let Err(e) = result {
        if e.is_panic() {
            error!("task '{name}' panicked: {e}");
        } else {
            warn!("task '{name}' was cancelled: {e}");
        }
    }
}

fn push_ports_to_map(bpf: &mut Ebpf, ports: Vec<u16>) -> Result<(), anyhow::Error> {
    let mut protected_ports: HashMap<_, u16, u8> = HashMap::try_from(
        bpf.map_mut(PROTECTED_PORTS_MAP)
            .context("hvf_protected_ports map missing from eBPF object")?,
    )?;
    for port in ports {
        protected_ports.insert(port, 0u8, 0)?;
    }
    Ok(())
}

fn push_allow_list_to_map(
    bpf: &mut Ebpf,
    allow_cidrs: &HashSet<Ipv4Cidr>,
) -> Result<(), anyhow::Error> {
    // hvf_always_allow_lpm is an LPM trie keyed by NETWORK-order [u8; 4]; the
    // kernel matches bits MSB-first byte-0-first, so feeding host-order bytes
    // here would silently reverse-match prefixes. Use Ipv4Addr::octets() —
    // it always returns [a, b, c, d] in network order regardless of host
    // endianness. (See REVIEW_NOTES.md M6 / commit message.)
    let mut allow_map: LpmTrie<_, [u8; 4], u8> = LpmTrie::try_from(
        bpf.map_mut(ALLOW_LIST_LPM_MAP)
            .context("hvf_always_allow_lpm map missing from eBPF object")?,
    )?;

    let mut count: usize = 0;
    let mut truncated = false;
    for cidr in allow_cidrs.iter() {
        if count >= ALLOW_LPM_MAX_ENTRIES {
            truncated = true;
            break;
        }
        let key = LpmKey::<[u8; 4]>::new(
            u32::from(cidr.network_length()),
            cidr.first_address().octets(),
        );
        allow_map.insert(&key, 0u8, 0)?;
        count += 1;
    }
    if truncated {
        warn!(
            "Static allow list exceeds {} CIDRs; truncated. Excess prefixes will be dropped when far from leader.",
            ALLOW_LPM_MAX_ENTRIES
        );
    }
    info!(
        "Loaded {} CIDRs into always-allow LPM trie (used when far from leader)",
        count
    );
    Ok(())
}

#[cfg(test)]
mod tests {

    use cidr::Ipv4Cidr;
    use std::str::FromStr;

    #[test]
    fn test_scalar_conversion() {
        let string_scalar = Ipv4Cidr::from_str("1.3.5.7").unwrap();
        assert_eq!(string_scalar.network_length(), 32);
    }
}
