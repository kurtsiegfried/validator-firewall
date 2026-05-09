#![no_std]

// Shared layout for BPF maps used by both crates.
//
// `RuntimeControls` and `ConnectionStats` are written by one side and read by
// the other through aya BPF maps; both sides must observe identical layout.
// `#[repr(C)]` guarantees that on a given host (no field reordering, no
// implementation-defined padding for these field sets). aya verifies the
// `mem::size_of::<T>()` of the userspace type against the BPF object's
// recorded `value_size` at map bind time, so accidental drift surfaces as a
// startup error rather than silent corruption.

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeControls {
    pub global_enabled: bool,
    pub close_to_leader: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionStats {
    pub pkt_count: u64,
    pub blocked_pkt_count: u64,
    pub far_from_leader_pkt_count: u64,
    pub zero_rtt_pkt_count: u64,
}

pub enum StatType {
    All,
    Blocked,
    FarFromLeader,
    ZeroRtt,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuntimeControls {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionStats {}
