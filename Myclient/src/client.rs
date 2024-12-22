use tokio::net::{TcpListener, TcpStream};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use Mycore::mycore::{Cipher, Password, SecureSocket};

pub async fn local_proxy() -> io::Result<()> {
    let addr = "127.0.0.1:1080";
    let listener = TcpListener::bind(addr).await?;
    println!("Local proxy server running at {}", addr);
    loop {
        let (socket, _) = listener.accept().await?;
        println!("Received connection");
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket).await {
                eprintln!("Failed to handle connection: {}", e);
            } else {
                println!("Connection handled successfully");
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream) -> io::Result<()> {
    // 连接到远程服务器
    let remote_addr = "127.0.0.1:9090";
    let remote = TcpStream::connect(remote_addr).await?;
    let password = Password::new();
    let cipher = Cipher::new(password);
    let mut secure_socket = SecureSocket::new(remote, cipher);

    // 转发数据
    let (mut ri, mut wi) = socket.split();
    let (mut ro, mut wo) = tokio::io::split(secure_socket);

    tokio::try_join!(
        async {
            if let Err(e) = io::copy(&mut ri, &mut wo).await {
                eprintln!("Error forwarding data from client to remote: {}", e);
            }
            if let Err(e) = wo.shutdown().await {
                eprintln!("Error shutting down write half of remote: {}", e);
            }
            Ok::<(), io::Error>(())
        },
        async {
            if let Err(e) = io::copy(&mut ro, &mut wi).await {
                eprintln!("Error forwarding data from remote to client: {}", e);
            }
            if let Err(e) = wi.shutdown().await {
                eprintln!("Error shutting down write half of client: {}", e);
            }
            Ok::<(), io::Error>(())
        },
    )?;

    Ok(())
}