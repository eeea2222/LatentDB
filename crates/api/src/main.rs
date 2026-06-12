//! The `latentdb` binary: a thin CLI over the API library.
//!
//! Commands:
//!   latentdb serve       Start the HTTP API (default).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmd = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "serve".to_string());
    match cmd.as_str() {
        "serve" => latentdb_api::run().await,
        "help" | "--help" | "-h" => {
            println!("latentdb <serve>");
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\nusage: latentdb <serve>");
            std::process::exit(2);
        }
    }
}
