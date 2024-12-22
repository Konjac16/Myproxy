use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::net::{Ipv4Addr, Ipv6Addr};

pub async fn handle_socks5(mut socket: TcpStream) -> io::Result<()> {
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

    // 响应客户端的握手
    // SOCKS5 握手响应格式: VER, METHOD
    socket.write_all(&[0x05, 0x00]).await?;
    socket.flush().await?;

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

    // 这里只处理 CONNECT 命令
    if buf[1] != 0x01 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported command"));
    }

    // 解析目标地址和端口
    let addr = match buf[3] {
        0x01 => {
            // IPv4
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            format!("{}:{}", ip, port)
        }
        0x03 => {
            // 域名
            let len = buf[4] as usize;
            let domain = std::str::from_utf8(&buf[5..5 + len]).unwrap();
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            format!("{}:{}", domain, port)
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
            format!("{}:{}", ip, port)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid address type")),
    };

    // 输出请求的网址
    println!("Request URL: {}", addr);

    // 连接目标地址
    let mut remote = match TcpStream::connect(addr).await {
        Ok(stream) => stream,
        Err(e) => {
            // 响应客户端连接失败
            socket.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            socket.flush().await?;
            return Err(e);
        }
    };

    // 获取本地绑定的地址和端口
    let local_addr = remote.local_addr()?;
    let local_ip = match local_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let local_port = local_addr.port().to_be_bytes();

    // 响应客户端的连接请求
    // SOCKS5 连接响应格式: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let mut response = vec![0x05, 0x00, 0x00, 0x01];
    response.extend_from_slice(&local_ip);
    response.extend_from_slice(&local_port);
    socket.write_all(&response).await?;
    socket.flush().await?;

    // 转发数据
    let (mut ri, mut wi) = socket.split();
    let (mut ro, mut wo) = remote.split();

    tokio::try_join!(
        async {
            if let Err(e) = io::copy(&mut ri, &mut wo).await {
                eprintln!("Error forwarding data from client to remote: {}", e);
            }
            Ok::<(), io::Error>(())
        },
        async {
            if let Err(e) = io::copy(&mut ro, &mut wi).await {
                eprintln!("Error forwarding data from remote to client: {}", e);
            }
            Ok::<(), io::Error>(())
        },
    )?;

    Ok(())
}