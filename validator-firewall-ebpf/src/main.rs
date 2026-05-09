#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{lpm_trie::Key as LpmKey, Array, HashMap, LpmTrie, PerCpuHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error, warn};

use validator_firewall_common::{ConnectionStats, RuntimeControls, StatType};

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

const DENY_LIST_SIZE: u32 = 524288;
const ALLOW_LPM_SIZE: u32 = 1024;

// BPF maps shared with userspace.
//
// Endianness convention for integer keys/values: HOST byte order, on both
// sides. Concretely, an IPv4 address `1.2.3.4` is stored as the integer
// `0x01020304_u32`, matching the std `From<u32> for Ipv4Addr` mapping. The
// eBPF program does the network→host conversion at packet ingest via
// `u32::from_be_bytes(src_addr)` / `u16::from_be_bytes(udp.dst)`, and the
// userspace side uses `u32::from(ipv4_addr)` / a `u16` port from clap, which
// produce the same host-order integer. Do not store wire-order values in
// these maps — `aya-log`'s `{:i}` formatter and the `Ipv4Addr::from(u32)`
// renderer both assume host order.
#[map(name = "hvf_deny_list")]
static LEADER_SLOT_DENY_LIST: HashMap<u32, u8> =
    HashMap::<u32, u8>::with_max_entries(DENY_LIST_SIZE, 0);

// `hvf_always_allow_lpm` deviates from the host-order convention above:
// LPM-trie keys MUST be stored in NETWORK byte order (`Ipv4Addr::octets()` /
// `(*ipv4_hdr).src_addr`), because the kernel walks bits MSB-first byte-0-
// first when matching. Feeding host-order bytes here silently makes a /16
// for `8.8.0.0` match packets from `0.0.x.x` instead — which is what bit us
// the last time we tried this. See REVIEW_NOTES.md M6 for the full write-up.
#[map(name = "hvf_always_allow_lpm")]
static FULL_SCHEDULE_ALLOW_LPM: LpmTrie<[u8; 4], u8> =
    LpmTrie::<[u8; 4], u8>::with_max_entries(ALLOW_LPM_SIZE, 0);

#[map(name = "hvf_stats")]
static STATS: PerCpuHashMap<u32, ConnectionStats> =
    PerCpuHashMap::<u32, ConnectionStats>::with_max_entries(16384, 0);

#[map(name = "hvf_protected_ports")]
static PROTECTED_PORTS: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(1024, 0);

#[map(name = "hvf_cnc")]
static CNC: Array<RuntimeControls> = Array::<RuntimeControls>::with_max_entries(1, 0);

// `frags` declares this program as multi-buffer-XDP-aware: the kernel sets
// BPF_F_XDP_HAS_FRAGS on load and the driver allows native attach on
// jumbo-frame interfaces (MTU > ~3520, where a packet may span multiple page
// fragments). We only ever read the first 42 bytes (Eth+IPv4+UDP), which the
// driver is required to place in the linear part, so the match logic needs
// no helper changes.
#[xdp(frags)]
pub fn validator_firewall(ctx: XdpContext) -> u32 {
    let cnc = match CNC.get(0) {
        Some(cnc) => cnc,
        None => {
            warn!(&ctx, "No CNC data found, using defaults");
            &RuntimeControls{ global_enabled: true, close_to_leader: true }
        }
    };

    if cnc.global_enabled {
        match try_process_packet(&ctx, cnc.close_to_leader) {
            Ok(ret) => ret,
            Err(_) => {
                error!(&ctx, "Error processing packet!");
                xdp_action::XDP_PASS
            }
        }
    } else {
        xdp_action::XDP_PASS
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

//Hide some unsafe blocks
#[inline(always)]
fn is_allowed(address: u32, src_bytes: [u8; 4], close_to_leader: bool) -> bool {
    if close_to_leader {
        // Deny list is a regular HashMap keyed by host-order u32.
        unsafe { LEADER_SLOT_DENY_LIST.get(&address).is_none() }
    } else {
        // Allow list is an LPM trie keyed by NETWORK-order src_bytes; pass
        // the packet's src_addr through directly (it's already big-endian).
        let key = LpmKey::<[u8; 4]>::new(32, src_bytes);
        FULL_SCHEDULE_ALLOW_LPM.get(&key).is_some()
    }
}

#[inline(always)]
fn is_protected_port(dest_port: u16) -> bool {
    unsafe { PROTECTED_PORTS.get(&dest_port).is_some() }
}

#[inline(always)]
fn increment_counter(ctx: &XdpContext, address: u32, stat_type: StatType) {
    unsafe {
        if let None = STATS.get_ptr(&address) {
            let _ = STATS.insert(&address, &ConnectionStats::default(), 0);
        }
        match STATS.get_ptr_mut(&address) {
            Some(stats) => {
                match stat_type {
                    StatType::All => {
                        (*stats).pkt_count  += 1;
                    },
                    StatType::Blocked => {
                        (*stats).blocked_pkt_count += 1;
                    },
                    StatType::FarFromLeader => {
                        (*stats).far_from_leader_pkt_count += 1;
                    },
                    StatType::ZeroRtt => {
                        (*stats).zero_rtt_pkt_count += 1;
                    }
                }
            },
            None => {
                error!(ctx, "No entry for {} in stats map!", address);
            }
        }
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn try_process_packet(ctx: &XdpContext, close_to_leader: bool) -> Result<u32, ()> {
    // network-types 0.2 stores raw u8/u16 fields in network byte order, AND
    // its EtherType / IpProto enum variants are pre-swapped to wire order
    // (variants defined as `0x0800_u16.to_be()` etc.). So we compare against
    // the on-wire u16 directly, *without* a `u16::from_be` round-trip. Doing
    // a from_be here would double-swap and silently misclassify every IPv4
    // packet as "unknown" — the protected-port path is then never entered
    // and the stats map stays empty (we hit this exact bug at 0.0.5 → 0.2.0).
    let eth_header: *const EthHdr = ptr_at(ctx, 0)?;
    let ether_type_wire = unsafe { (*eth_header).ether_type };
    if ether_type_wire == EtherType::Ipv6 as u16 {
        return Ok(xdp_action::XDP_PASS);
    }
    if ether_type_wire != EtherType::Ipv4 as u16 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_header: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    // IpProto is a single u8, no endianness — compare directly.
    let proto = unsafe { (*ipv4_header).proto };
    if proto == IpProto::Udp as u8 {
        // Two views of the source IP, kept in sync:
        //  - src_bytes:   network-order [a, b, c, d], fed straight to the LPM
        //                 trie key (kernel matches MSB-first, byte-0-first).
        //  - source_addr: host-order u32, used for the host-order HashMap
        //                 keys (deny list, stats) and aya-log's {:i} renderer.
        let src_bytes = unsafe { (*ipv4_header).src_addr };
        let source_addr = u32::from_be_bytes(src_bytes);
        let udp_header: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
        let dest_port = u16::from_be_bytes(unsafe { (*udp_header).dst });
        if !is_protected_port(dest_port) {
            return Ok(xdp_action::XDP_PASS);
        }

        //Traffic above here is other OS traffic, not counted in our stats
        increment_counter(ctx, source_addr, StatType::All);
        if !close_to_leader {
            increment_counter(ctx, source_addr, StatType::FarFromLeader);
        }
        if is_quic_zero_rtt(ctx, source_addr) {
            increment_counter(ctx, source_addr, StatType::ZeroRtt);
        }
        let action = if is_allowed(source_addr, src_bytes, close_to_leader) {
            debug!(
                ctx,
                "ALLOW SRC IP: {:i}, DEST PORT: {}",
                source_addr,
                dest_port
            );
            xdp_action::XDP_PASS
        } else {
            debug!(
                ctx,
                "DROP SRC IP: {:i}, DEST PORT: {}",
                source_addr,
                dest_port
            );
            increment_counter(ctx, source_addr, StatType::Blocked);
            xdp_action::XDP_DROP
        };

        Ok(action)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

//Placeholder — QUIC 0-RTT detection not yet implemented.
#[inline(always)]
fn is_quic_zero_rtt(_ctx: &XdpContext, _source_addr: u32) -> bool {
    false
}