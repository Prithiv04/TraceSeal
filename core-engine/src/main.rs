use std::path::PathBuf;

use clap::{Parser, Subcommand};
use traceseal_core::{fixture, prove, verify_files};

#[derive(Parser)]
#[command(
    name = "traceseal",
    version,
    about = "TRACESEAL local TLSNotary core engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Fixture {
        #[arg(long, default_value = "127.0.0.1:4443")]
        bind: String,
        #[arg(long)]
        untrusted_cert: bool,
    },
    Prove {
        #[arg(long, default_value = "https://localhost:4443/trace-seal-503")]
        url: String,
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "status,error,service,message"
        )]
        disclose: Vec<String>,
        #[arg(long, default_value = "artifacts")]
        output: PathBuf,
        #[arg(long, default_value_t = 30)]
        request_timeout_seconds: u64,
    },
    Verify {
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long)]
        presentation: PathBuf,
    },
    Inspect {
        #[arg(long)]
        package: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring provider");
    let cli = Cli::parse();
    match cli.command {
        Command::Fixture {
            bind,
            untrusted_cert,
        } => {
            if let Err(e) = fixture::serve_fixture(&bind, untrusted_cert).await {
                eprintln!("fixture error: {e}");
                std::process::exit(2)
            }
        }
        Command::Prove {
            url,
            disclose,
            output,
            request_timeout_seconds,
        } => match prove(
            &url,
            &disclose,
            &output,
            std::time::Duration::from_secs(request_timeout_seconds),
        )
        .await
        {
            Ok(r) => {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
                if r.verification_status != "VERIFIED" {
                    std::process::exit(1)
                }
            }
            Err(e) => {
                eprintln!("prove failed: {e}");
                std::process::exit(2)
            }
        },
        Command::Verify {
            attestation,
            presentation,
        } => {
            let mut r = verify_files(&attestation, &presentation);
            r.verifier.exit_code = Some(if r.verification_status == "VERIFIED" {
                0
            } else {
                1
            });
            println!("{}", serde_json::to_string(&r).unwrap());
            if r.verification_status != "VERIFIED" {
                std::process::exit(1)
            }
        }
        Command::Inspect { package } => {
            let p = package.join("verification-report.json");
            match std::fs::read_to_string(p) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("inspect failed: {e}");
                    std::process::exit(2)
                }
            }
        }
    }
}
