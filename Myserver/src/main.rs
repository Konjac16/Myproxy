
mod server;
use tokio;
use server::remote_proxy;
#[tokio::main]
async fn main() {
    if let Err(e) = remote_proxy().await {
        eprintln!("Local proxy failed: {}", e);
    }
}