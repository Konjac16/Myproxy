use rand::seq::SliceRandom;
use rand::{SeedableRng, rngs::StdRng};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};

pub const PASSWORD_LENGTH: usize = 256;
pub const RNG_SEED: [u8; 32] = [0; 32]; 

#[derive(Clone)]
pub struct Password([u8; PASSWORD_LENGTH]);

impl Password {
    pub fn new() -> Self {
        let mut rng = StdRng::from_seed(RNG_SEED);
        let mut password = [0u8; PASSWORD_LENGTH];
        let mut bytes: Vec<u8> = (0..=255).collect();
        bytes.shuffle(&mut rng);
        password.copy_from_slice(&bytes);
        Password(password)
    }
}

#[derive(Clone)]
pub struct Cipher {
    encode_password: Password,
    decode_password: Password,
}

impl Cipher {
    pub fn new(encode_password: Password) -> Self {
        let mut decode_password = [0u8; PASSWORD_LENGTH];
        for (i, &v) in encode_password.0.iter().enumerate() {
            decode_password[v as usize] = i as u8;
        }
        Cipher {
            encode_password,
            decode_password: Password(decode_password),
        }
    }

    pub fn encode(&self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte = self.encode_password.0[*byte as usize];
        }
    }

    pub fn decode(&self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte = self.decode_password.0[*byte as usize];
        }
    }
}

pub struct SecureSocket {
    cipher: Cipher,
}

impl SecureSocket {
    pub fn new(cipher: Cipher) -> Self {
        SecureSocket { cipher }
    }

    pub async fn encode_copy<'a>(
        &self,
        dst: &mut WriteHalf<'a>,
        src: &mut ReadHalf<'a>,
    ) -> io::Result<()> {
        let mut buf = [0u8; 1024];
        loop {
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            self.cipher.encode(&mut buf[..n]);
            dst.write_all(&buf[..n]).await?;
        }
        Ok(())
    }

    pub async fn decode_copy<'a>(
        &self,
        dst: &mut WriteHalf<'a>,
        src: &mut ReadHalf<'a>,
    ) -> io::Result<()> {
        let mut buf = [0u8; 1024];
        loop {
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            self.cipher.decode(&mut buf[..n]);
            dst.write_all(&buf[..n]).await?;
        }
        Ok(())
    }
    
}
