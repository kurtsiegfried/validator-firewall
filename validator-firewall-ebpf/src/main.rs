#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error, warn};

use validator_firewall_common::{RuntimeControls,ConnectionStats,StatType};

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

const DENY_LIST_SIZE: u32 = 524288;

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
#[map(name = "hvf_always_allow")]
static FULL_SCHEDULE_ALLOW_LIST: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(8192, 0);
#[map(name = "hvf_stats")]
static STATS: PerCpuHashMap<u32, ConnectionStats> =
    PerCpuHashMap::<u32, ConnectionStats>::with_max_entries(16384, 0);

#[map(name = "hvf_protected_ports")]
static PROTECTED_PORTS: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(1024, 0);

#[map(name = "hvf_cnc")]
static CNC: Array<RuntimeControls> = Array::<RuntimeControls>::with_max_entries(1, 0);

#[xdp]
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
fn is_allowed(address: u32, close_to_leader: bool) -> bool {
    return if close_to_leader {
        unsafe { LEADER_SLOT_DENY_LIST.get(&address).is_none() }
    } else {
        unsafe { FULL_SCHEDULE_ALLOW_LIST.get(&address).is_some() }
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
    // network-types 0.2 stores raw u8/u16 fields in network byte order; we
    // compare against the protocol-enum variants cast to their wire values
    // (avoids the Result-returning helper which the verifier doesn't like).
    let eth_header: *const EthHdr = ptr_at(ctx, 0)?;
    let ether_type = u16::from_be(unsafe { (*eth_header).ether_type });
    if ether_type == EtherType::Ipv6 as u16 {
        return Ok(xdp_action::XDP_PASS);
    }
    if ether_type != EtherType::Ipv4 as u16 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_header: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let proto = unsafe { (*ipv4_header).proto };
    if proto == IpProto::Udp as u8 {
        let source_addr = u32::from_be_bytes(unsafe { (*ipv4_header).src_addr });
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
        let action = if is_allowed(source_addr, close_to_leader) {
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