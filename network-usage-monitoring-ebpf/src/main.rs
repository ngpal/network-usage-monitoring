#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use network_usage_monitoring_common::IpStats;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static mut IP_COUNTERS: HashMap<u32, IpStats> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
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

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    let mut stats = unsafe {
        IP_COUNTERS
            .get(&source_addr)
            .copied()
            .unwrap_or(IpStats::default())
    };
    stats.packets += 1;
    let data_start = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;

    if data_end >= data_start {
        stats.bytes += (data_end - data_start) as u64;
    } else {
        return Err(()); // invalid packet
    }

    unsafe {
        IP_COUNTERS.insert(&source_addr, &stats, 0).unwrap_or(());
    }

    Ok(xdp_action::XDP_PASS)
}
