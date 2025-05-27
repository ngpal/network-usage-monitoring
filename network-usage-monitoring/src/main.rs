use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Pod,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::{
    signal,
    sync::Notify,
    time::{sleep, Duration},
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct IpStats {
    packets: u64,
    bytes: u64,
}

unsafe impl Pod for IpStats {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let notify = Arc::new(Notify::new());
    let notify_task = notify.clone();
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/network-usage-monitoring"
    )))?;

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    tokio::spawn(async move {
        let ip_counters: HashMap<_, u32, IpStats> =
            HashMap::try_from(bpf.map("IP_COUNTERS").unwrap()).unwrap();
        loop {
            println!("--- IP packet counts ---");
            let mut total = 0;
            let mut entries = ip_counters.iter();
            while let Some(Ok((ip, stat))) = entries.next() {
                let ip = Ipv4Addr::from(ip.to_be()); // IP is in big endian
                println!(
                    "{:<15} => {:>9} packets {:>9} bytes",
                    ip, stat.packets, stat.bytes
                );
                total += stat.bytes;
            }
            println!("-------------------------\n");
            println!("Total bytes recieved: {}\n", total);

            tokio::select! {
                _ = sleep(Duration::from_secs(5)) => {},
                _ = notify_task.notified() => {
                    break;
                }
            }
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    notify.notify_one();
    info!("Exiting...");

    Ok(())
}
