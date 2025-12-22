use anyhow::{Context, Result};
use clap::Parser;
use ipnet::IpNet;
use rpki::rtr::client::{Client, PayloadTarget};
use rpki::rtr::client::PayloadError;
use rpki::rtr::payload::{Action, Payload, RouteOrigin, Timing};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(author, version, about = "Validate IP prefixes against an RTR server", long_about = None)]
struct Args {
    /// RTR server address (e.g., [2a06:de00:50:cafe:100::e]:3323)
    #[arg(short, long)]
    server: String,

    /// IP prefix to validate (e.g., 2001:db8::/32 or 192.0.2.0/24)
    #[arg(short, long)]
    prefix: String,

    /// ASN to check (optional, if not provided will show all matching ROAs)
    #[arg(short, long)]
    asn: Option<u32>,

}

struct RoaCollector {
    roas: Vec<RouteOrigin>,
    eod_received: bool,
}

impl RoaCollector {
    fn new() -> Self {
        Self {
            roas: Vec::new(),
            eod_received: false,
        }
    }
}

impl PayloadTarget for RoaCollector {
    type Update = Vec<(Action, Payload)>;

    fn start(&mut self, _reset: bool) -> Self::Update {
        Vec::new()
    }

    fn apply(
        &mut self,
        update: Self::Update,
        timing: Timing,
    ) -> Result<(), PayloadError> {
        // Process all payloads in the update
        for (action, payload) in update {
            if let Action::Announce = action {
                if let Payload::Origin(origin) = payload {
                    self.roas.push(origin);
                }
            }
        }

        // The Timing parameter is provided with the End-of-Data PDU
        // When we receive timing info and have collected ROAs, EOD is reached
        if self.roas.len() > 0 && timing.refresh > 0 {
            self.eod_received = true;
            // Signal completion by returning an error to stop the client
            return Err(PayloadError::Corrupt);
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let prefix = IpNet::from_str(&args.prefix)
        .context("Failed to parse prefix")?;

    let server_addr = if let Ok(addr) = args.server.parse::<SocketAddr>() {
        addr
    } else {
        let addrs: Vec<SocketAddr> = args.server.to_socket_addrs()
            .context("Failed to resolve server address")?.
            collect();
        *addrs.first()
            .context("No addresses found for hostname")?
    };

    println!("Connecting to RTR server at {}...", server_addr);

    let stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect(server_addr)
    )
        .await
        .context("Connection timeout")?
        .context("Failed to connect to RTR server")?;

    println!("Connected! Fetching ROAs until End of Data marker...\n");

    let collector = RoaCollector::new();
    let mut client = Client::new(stream, collector, None);

    let result = client.run().await;

    let collector = match result {
        Ok(()) => {
            println!("RTR session completed successfully");
            client.into_target()
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::Other || e.to_string().contains("corrupt") {
                println!("End of Data received - initial sync complete");
                client.into_target()
            } else {
                return Err(e).context("Failed to fetch ROAs from RTR server");
            }
        }
    };

    let total_roas = collector.roas.len();

    if total_roas == 0 {
        return Err(anyhow::anyhow!("No ROAs received from RTR server - connection may have failed"));
    }

    println!("Total ROAs received: {}", total_roas);

    let mut matching_roas = Vec::new();
    for roa in &collector.roas {
        let roa_addr = roa.prefix.addr();
        let roa_prefix_len = roa.prefix.prefix_len();

        let is_match = match (prefix, roa_addr) {
            (IpNet::V4(v4_prefix), IpAddr::V4(v4_addr)) => {
                v4_addr == v4_prefix.addr() && roa_prefix_len == v4_prefix.prefix_len()
            }
            (IpNet::V6(v6_prefix), IpAddr::V6(v6_addr)) => {
                v6_addr == v6_prefix.addr() && roa_prefix_len == v6_prefix.prefix_len()
            }
            _ => false,
        };

        if is_match {
            let max_len = roa.prefix.max_len().unwrap_or(roa_prefix_len);
            matching_roas.push((u32::from(roa.asn), max_len));
        }
    }

    println!("\nValidation results for prefix: {}\n", prefix);

    if matching_roas.is_empty() {
        println!("❌ NOT FOUND - No ROA found for this prefix");
        println!("Status: INVALID (prefix not authorized in RPKI)");
    } else {
        println!("✅ FOUND - {} matching ROA(s):", matching_roas.len());
        for (asn, max_len) in &matching_roas {
            println!("  - AS{} (max length: {})", asn, max_len);
        }

        if let Some(check_asn) = args.asn {
            let is_valid = matching_roas.iter().any(|(asn, _)| *asn == check_asn);
            println!();
            if is_valid {
                println!("✅ VALID - AS{} is authorized to announce {}", check_asn, prefix);
            } else {
                println!("❌ INVALID - AS{} is NOT authorized to announce {}", check_asn, prefix);
                println!("Authorized ASNs: {:?}", matching_roas.iter().map(|(asn, _)| format!("AS{}", asn)).collect::<Vec<_>>());
            }
        }
    }

    Ok(())
}
