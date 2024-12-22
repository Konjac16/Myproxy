use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use std::net::{Ipv4Addr, Ipv6Addr};
use Mycore::mycore::{Cipher, Password, SecureSocket};

pub async fn remote_proxy() -> io::Result<()> {
    let addr = "127.0.0.1:9090";
    let listener = TcpListener::bind(addr).await?;
    println!("Remote proxy server running at {}", addr);

    let password = Password::new();
    let cipher = Cipher::new(password);
    loop {
        let (socket, _) = listener.accept().await?;
        println!("Received connection");

        let cipher_clone = cipher.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(socket, cipher_clone).await {
                eprintln!("Failed to handle connection: {}", e);
            }
        });
    }
}

async fn handle_socks5(mut socket: TcpStream, cipher: Cipher) -> io::Result<()> {
    let mut buf = [0; 4096];

    // 读取客户端的握手请求
    let n = socket.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    // 解析握手请求
    // SOCKS5 握手请求格式: VER, NMETHODS, METHODS
    if buf[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid SOCKS version"));
    }

    // 发送握手响应
    socket.write_all(&[0x05, 0x00]).await?;

    // 读取客户端的连接请求
    let n = socket.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    // 解析连接请求
    // SOCKS5 连接请求格式: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
    if buf[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid SOCKS version"));
    }

    match buf[1] {
        0x01 => handle_connect(&mut socket, &buf, cipher).await,
        0x02 => handle_bind(&mut socket, &buf).await,
        0x03 => handle_udp_associate(&mut socket, &buf).await,
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported command")),
    }
}

async fn handle_connect(socket: &mut TcpStream, buf: &[u8], cipher: Cipher) -> io::Result<()> {
    let addr = parse_address(buf)?;
    let mut remote = TcpStream::connect(addr).await?;

    let secure_socket = SecureSocket::new(cipher);

    // 发送连接成功响应
    socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;

    // 转发数据
    let (mut ri, mut wi) = socket.split();
    let (mut ro, mut wo) = remote.split();

    tokio::try_join!(
        async {
            match io::copy(&mut ri, &mut wo).await {
                Ok(_) => {
                    if let Err(e) = wo.shutdown().await {
                        eprintln!("Error shutting down write half of remote: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Error forwarding data from client to remote: {}", e);
                    // 关闭连接
                    let _ = wo.shutdown().await;
                }
            }
            Ok::<(), io::Error>(())
        },
        async {
            match io::copy(&mut ro, &mut wi).await {
                Ok(_) => {
                    if let Err(e) = wi.shutdown().await {
                        eprintln!("Error shutting down write half of client: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Error forwarding data from remote to client: {}", e);
                    // 关闭连接
                    let _ = wi.shutdown().await;
                }
            }
            Ok::<(), io::Error>(())
        }
    ).map_err(|e| {
        eprintln!("Error in try_join: {}", e);
        e
    })?;

    Ok(())
}

async fn handle_bind(socket: &mut TcpStream, buf: &[u8]) -> io::Result<()> {
    let addr = parse_address(buf)?;
    let listener = TcpListener::bind(addr).await?;

    // 发送绑定成功响应
    let local_addr = listener.local_addr()?;
    let response = build_response(&local_addr);
    socket.write_all(&response).await?;

    let (mut remote, _) = listener.accept().await?;

    // 发送第二次绑定成功响应
    let remote_addr = remote.peer_addr()?;
    let response = build_response(&remote_addr);
    socket.write_all(&response).await?;

    // 转发数据
    let (mut ri, mut wi) = socket.split();
    let (mut ro, mut wo) = remote.split();

    tokio::try_join!(
        async {
            match io::copy(&mut ri, &mut wo).await {
                Ok(_) => {
                    if let Err(e) = wo.shutdown().await {
                        eprintln!("Error shutting down write half of remote: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Error forwarding data from client to remote: {}", e);
                    // 关闭连接
                    let _ = wo.shutdown().await;
                }
            }
            Ok::<(), io::Error>(())
        },
        async {
            match io::copy(&mut ro, &mut wi).await {
                Ok(_) => {
                    if let Err(e) = wi.shutdown().await {
                        eprintln!("Error shutting down write half of client: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Error forwarding data from remote to client: {}", e);
                    // 关闭连接
                    let _ = wi.shutdown().await;
                }
            }
            Ok::<(), io::Error>(())
        }
    ).map_err(|e| {
        eprintln!("Error in try_join: {}", e);
        e
    })?;

    Ok(())
}

async fn handle_udp_associate(socket: &mut TcpStream, buf: &[u8]) -> io::Result<()> {
    let addr = parse_address(buf)?;
    let udp_socket = UdpSocket::bind(addr).await?;

    // 发送 UDP 关联成功响应
    let local_addr = udp_socket.local_addr()?;
    let response = build_response(&local_addr);
    socket.write_all(&response).await?;

    // 处理 UDP 数据包
    let mut buf = [0; 4096];
    loop {
        let (n, src) = udp_socket.recv_from(&mut buf).await?;
        udp_socket.send_to(&buf[..n], src).await?;
    }
}

fn parse_address(buf: &[u8]) -> io::Result<String> {
    match buf[3] {
        0x01 => {
            // IPv4
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok(format!("{}:{}", ip, port))
        }
        0x03 => {
            // Domain name
            let len = buf[4] as usize;
            let domain = std::str::from_utf8(&buf[5..5 + len]).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid domain name"))?;
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            Ok(format!("{}:{}", domain, port))
        }
        0x04 => {
            // IPv6
            let ip = Ipv6Addr::new(
                u16::from_be_bytes([buf[4], buf[5]]),
                u16::from_be_bytes([buf[6], buf[7]]),
                u16::from_be_bytes([buf[8], buf[9]]),
                u16::from_be_bytes([buf[10], buf[11]]),
                u16::from_be_bytes([buf[12], buf[13]]),
                u16::from_be_bytes([buf[14], buf[15]]),
                u16::from_be_bytes([buf[16], buf[17]]),
                u16::from_be_bytes([buf[18], buf[19]]),
            );
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok(format!("{}:{}", ip, port))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid address type")),
    }
}

fn build_response(addr: &std::net::SocketAddr) -> Vec<u8> {
    let mut response = vec![0x05, 0x00, 0x00, 0x01];
    match addr {
        std::net::SocketAddr::V4(addr) => {
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(addr) => {
            response[3] = 0x04;
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    response
}