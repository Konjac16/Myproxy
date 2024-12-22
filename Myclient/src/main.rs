
mod client;
use tokio;
use client::local_proxy;
#[tokio::main]
async fn main() {
    if let Err(e) = local_proxy().await {
        eprintln!("Local proxy failed: {}", e);
    }
}