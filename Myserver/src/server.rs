use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use Mycore::mycore::{Cipher, Password, SecureSocket};

pub async fn remote_proxy() -> io::Result<()> {
    let addr = "198.13.55.17:1080";
    let listener = TcpListener::bind(addr).await?;
    println!("Remote proxy server running at {}", addr);

    let password = Password::new();
    let cipher = Cipher::new(password);

    loop {
        let (socket, _) = listener.accept().await?;
        println!("Received connection");

        let cipher_clone = cipher.clone();
        tokio::spawn(async move {
            let secure_socket = SecureSocket::new(socket, cipher_clone);
            if let Err(e) = handle_socks5(secure_socket).await {
                eprintln!("Failed to handle connection: {}", e);
            }
        });
    }
}

async fn handle_socks5(mut socket: SecureSocket) -> io::Result<()> {
    let mut buf = [0; 4096];

    // 读取客户端的握手请求并解密
    let n = socket.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    // 解析握手请求
    // SOCKS5 握手请求格式: VER, NMETHODS, METHODS
    if buf[0] != 0x05 {
        let error_msg = "Invalid SOCKS version";
        socket.write_all(error_msg.as_bytes()).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, error_msg));
    }

    // 发送握手响应
    socket.write_all(&[0x05, 0x00]).await?;

    // 读取客户端的连接请求并解密
    let n = socket.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    // 解析连接请求
    // SOCKS5 连接请求格式: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
    if buf[0] != 0x05 {
        let error_msg = "Invalid SOCKS version in connect request";
        socket.write_all(error_msg.as_bytes()).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, error_msg));
    }

    let cmd = buf[1];
    if cmd != 0x01 {
        let error_msg = "Unsupported SOCKS command";
        socket.write_all(error_msg.as_bytes()).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidInput, error_msg));
    }

    // 解析目标地址和端口
    let atyp = buf[3];
    let (dst_addr, dst_port) = match atyp {
        0x01 => { // IPv4
            let addr = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (addr, port)
        },
        0x03 => { // 域名
            let len = buf[4] as usize;
            let addr = String::from_utf8_lossy(&buf[5..5+len]).to_string();
            let port = u16::from_be_bytes([buf[5+len], buf[6+len]]);
            (addr, port)
        },
        0x04 => { // IPv6
            let addr = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
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
            (addr, port)
        },
        _ => {
            let error_msg = "Unsupported address type";
            socket.write_all(error_msg.as_bytes()).await?;
            return Err(io::Error::new(io::ErrorKind::InvalidInput, error_msg));
        },
    };

    println!("Connecting to {}:{}", dst_addr, dst_port);

    // 建立到目标服务器的连接
    match TcpStream::connect(format!("{}:{}", dst_addr, dst_port)).await {
        Ok(mut target_stream) => {
            // 发送连接成功响应
            let response = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            socket.write_all(&response).await?;

            // 分离源和目标流
            let (mut src_read, mut src_write) = io::split(socket);
            let (mut tgt_read, mut tgt_write) = target_stream.split();

            // 使用 tokio::join 同时转发数据
            let (res1, res2) = tokio::join!(
                transfer(&mut src_read, &mut tgt_write),
                transfer(&mut tgt_read, &mut src_write),
            );

            if let Err(e) = res1 {
                eprintln!("Error transferring from source to target: {}", e);
            }

            if let Err(e) = res2 {
                eprintln!("Error transferring from target to source: {}", e);
            }
        },
        Err(e) => {
            let error_msg = format!("Failed to connect to target: {}", e);
            socket.write_all(error_msg.as_bytes()).await?;
            return Err(io::Error::new(io::ErrorKind::Other, error_msg));
        },
    }

    Ok(())
}

async fn transfer<R, W>(reader: &mut R, writer: &mut W) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
    }
    Ok(())
}