#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::eth::{EthHdr, EtherType};

#[xdp]
pub fn network_usage_monitoring(ctx: XdpContext) -> u32 {
    match try_network_usage_monitoring(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn et2str(et: EtherType) -> &'static str {
    match et {
        EtherType::Loop => "Loop",
        EtherType::Ipv4 => "Ipv4",
        EtherType::Arp => "Arp",
        EtherType::Ipv6 => "Ipv6",
        EtherType::FibreChannel => "FibreChannel",
        EtherType::Infiniband => "Infiniband",
        EtherType::LoopbackIeee8023 => "LoopbackIeee8023",
    }
}

fn try_network_usage_monitoring(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let eth_hdr_size = mem::size_of::<EthHdr>();
    if data + eth_hdr_size > data_end {
        return Err(xdp_action::XDP_ABORTED);
    }

    let eth_hdr = unsafe { &*(data as *const EthHdr) };

    let e_type = eth_hdr.ether_type;
    let mac = eth_hdr.src_addr;
    if mac == [0x76, 0xa6, 0xcd, 0xdc, 0xcb, 0x64] {
        return Ok(xdp_action::XDP_PASS);
    }

    info!(
        &ctx,
        "src mac = {} {} {} {} {} {} type = {}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        et2str(e_type)
    );

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
