//! The `latentdb` binary: a thin CLI over the API library.
//!
//! Commands:
//!   latentdb serve       Start the HTTP API (default).
//!   latentdb seed-demo    Seed the Acme Robotics demo tenant.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "serve".to_string());
    match cmd.as_str() {
        "serve" => latentdb_api::run().await,
        "seed-demo" => latentdb_api::seed_demo().await,
        "help" | "--help" | "-h" => {
            println!("latentdb <serve|seed-demo>");
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\nusage: latentdb <serve|seed-demo>");
            std::process::exit(2);
        }
    }
}
