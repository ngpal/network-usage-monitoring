#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use core::mem;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map, xdp},
    maps::HashMap,
    programs::{TcContext, XdpContext},
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use network_usage_monitoring_common::NetStats;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static mut NET_COUNTERS: HashMap<u16, NetStats> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn ingress_counter(ctx: XdpContext) -> u32 {
    match try_ingress_counter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    // cast pointers to usize for arithmetic and comparison
    let start_addr = start as usize;
    let end_addr = end as usize;

    if start_addr + offset + len > end_addr {
        return Err(());
    }

    // Use pointer arithmetic with add(), safer and verifier friendly
    Ok(start.wrapping_add(offset) as *const T)
}

fn try_ingress_counter(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    // let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    // Get IP protocol and header length
    let proto = unsafe { (*ipv4hdr).proto };
    let ihl = (unsafe { (*ipv4hdr).ihl() } & 0x0F) * 4; // in bytes

    // Only handle TCP and UDP
    if proto != IpProto::Udp && proto != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    // Calculate transport header offset
    let transport_offset = EthHdr::LEN + ihl as usize;

    // Read ports (first 4 bytes of TCP/UDP header)
    let ports: *const u8 = ptr_at::<[u8; 4]>(&ctx, transport_offset)? as *const u8;
    // let src_port = u16::from_be(unsafe { *(ports as *const u16) });
    let dst_port = u16::from_be(unsafe { *(ports.add(2) as *const u16) });

    // --- you can use src_port or dst_port as keys now ---
    // for example, count per-port traffic:
    let mut stats = unsafe {
        NET_COUNTERS
            .get(&dst_port)
            .copied()
            .unwrap_or(NetStats::default())
    };

    stats.ingress.packets += 1;

    let data_start = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;
    if data_end >= data_start {
        stats.ingress.bytes += (data_end - data_start) as u64;
    } else {
        return Err(()); // invalid packet
    }

    unsafe {
        NET_COUNTERS.insert(&dst_port, &stats, 0).unwrap_or(());
    }

    Ok(xdp_action::XDP_PASS)
}

#[classifier]
pub fn egress_counter(ctx: TcContext) -> i32 {
    match try_egress_counter(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

pub fn try_egress_counter(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    // only handle IPv4
    if !matches!(ethhdr.ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let transport_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let src_port = match ipv4hdr.proto {
        IpProto::Tcp => {
            // TCP
            let tcphdr: TcpHdr = ctx.load(transport_offset).map_err(|_| ())?;
            u16::from_be(tcphdr.source)
        }
        IpProto::Udp => {
            // UDP
            let udphdr: UdpHdr = ctx.load(transport_offset).map_err(|_| ())?;
            u16::from_be_bytes(udphdr.source)
        }
        _ => return Ok(TC_ACT_PIPE), // skip non-TCP/UDP
    };

    let mut stats = unsafe {
        NET_COUNTERS
            .get(&src_port)
            .copied()
            .unwrap_or(NetStats::default())
    };

    stats.egress.packets += 1;

    let data_start = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;
    if data_end >= data_start {
        stats.egress.bytes += (data_end - data_start) as u64;
    } else {
        return Err(());
    }

    unsafe { NET_COUNTERS.insert(&src_port, &stats, 0).unwrap_or(()) }

    Ok(TC_ACT_PIPE)
}
