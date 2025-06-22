use std::net::Ipv4Addr;

use anyhow::Context;
use aya::{
    maps::{HashMap, MapData},
    programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use log::{info, warn};
use network_usage_monitoring_common::IpStats;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Terminal,
};
use std::io;
use tokio::time::Duration;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s1")]
    iface: String,
}

struct App<'a> {
    ip_counters: HashMap<&'a mut MapData, u32, IpStats>,
    data: Vec<(Ipv4Addr, IpStats)>,
    total_bytes: u64,
}

impl<'a> App<'a> {
    fn new(bpf: &'a mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = bpf.map_mut("IP_COUNTERS").context("Map not found")?;
        let ip_counters: HashMap<&mut MapData, u32, IpStats> = HashMap::try_from(map)?;
        Ok(Self {
            ip_counters,
            data: Vec::new(),
            total_bytes: 0,
        })
    }

    fn update(&mut self) {
        self.data.clear();
        self.total_bytes = 0;

        let mut entries = self.ip_counters.iter();
        while let Some(Ok((ip, stat))) = entries.next() {
            let ip = Ipv4Addr::from(ip.to_le());
            self.total_bytes += stat.ingress.bytes;
            self.data.push((ip, stat));
        }

        self.data
            .sort_by(|a, b| b.1.ingress.bytes.cmp(&a.1.ingress.bytes)); // top-talkers first
    }
}

fn draw_ui(f: &mut ratatui::Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .constraints([Constraint::Percentage(98), Constraint::Max(1)].as_ref())
        .split(f.area());

    let mut total_in = 0;
    let mut total_out = 0;
    let rows = app.data.iter().map(|(ip, stat)| {
        total_in += stat.ingress.bytes;
        total_out += stat.egress.bytes;
        Row::new(vec![
            ip.to_string(),
            stat.ingress.packets.to_string(),
            stat.ingress.bytes.to_string(),
            stat.egress.packets.to_string(),
            stat.egress.bytes.to_string(),
        ])
    });

    let table = Table::new(rows, [Constraint::Ratio(1, 5); 5])
        .header(
            Row::new(vec![
                "IP",
                "Packets (in)",
                "Bytes (in)",
                "Packets (out)",
                "Bytes (out)",
            ])
            .style(Style::default().fg(Color::Yellow)),
        )
        .block(
            Block::default()
                .title("Network Usage")
                .borders(Borders::ALL),
        )
        .widths(&[Constraint::Ratio(1, 5); 5]);

    f.render_widget(table, chunks[0]);
    f.render_widget(
        Paragraph::new(format!(
            "Total bytes in: {} Total bytes out: {}",
            total_in, total_out
        )),
        chunks[1],
    );
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/network-usage-monitoring"
    )))?;

    let ingress_program: &mut Xdp = bpf.program_mut("ingress_counter").unwrap().try_into()?;
    ingress_program.load()?;
    ingress_program
        .attach(&opt.iface, XdpFlags::default())
        .context("failed to attach XDP program")?;

    let egress_program: &mut SchedClassifier =
        bpf.program_mut("egress_counter").unwrap().try_into()?;
    egress_program.load()?;
    egress_program.attach(&opt.iface, TcAttachType::Egress)?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let mut app = App::new(&mut bpf)?;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    loop {
        app.update();
        terminal.draw(|f| draw_ui(f, &app))?;

        // check for quit
        if event::poll(Duration::from_millis(1000))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    info!("Exiting...");

    Ok(())
}
