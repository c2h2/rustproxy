//! VMess AEAD server-side protocol implementation.
//!
//! Implements the modern VMess AEAD variant (no legacy MD5-based auth).
//! Clients (v2ray, v2rayNG, clash, etc.) connect with a UUID and the server
//! decrypts traffic, extracts the destination address, and returns a
//! `VMessStream` that transparently handles chunked AEAD encryption.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::KeyInit as AesKeyInit;
use aes::Aes128;
use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::{Aes128Gcm, Nonce};
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/* ========================= Constants ========================= */

const VMESS_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_SALT_CONST: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";

const AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const VMESS_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const VMESS_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const VMESS_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const VMESS_HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";

const TIMESTAMP_TOLERANCE: u64 = 120; // ±120 seconds
const AES_GCM_TAG_SIZE: usize = 16;

/* ========================= Security types ========================= */

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VMessSecurity {
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero, // no encryption, no auth — same as None
}

impl VMessSecurity {
    fn from_byte(b: u8) -> Option<Self> {
        match b & 0x0f {
            0x03 => Some(VMessSecurity::Aes128Gcm),
            0x04 => Some(VMessSecurity::Chacha20Poly1305),
            0x05 => Some(VMessSecurity::None),
            0x00 => Some(VMessSecurity::Zero),
            _ => None, // legacy AES-128-CFB etc. not supported
        }
    }
}

/* ========================= KDF ========================= */

/// HMAC-SHA256 based KDF used throughout VMess AEAD.
/// kdf(key, path...) = HMAC-SHA256(HMAC-SHA256(...(HMAC-SHA256(KDF_SALT_CONST, key), path[0])...), path[n])
fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    // Start with HMAC(KDF_SALT_CONST, key)
    let mut current = {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(KDF_SALT_CONST)
            .expect("HMAC can take key of any size");
        mac.update(key);
        mac.finalize().into_bytes()
    };

    for path in paths {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&current)
            .expect("HMAC can take key of any size");
        mac.update(path);
        current = mac.finalize().into_bytes();
    }

    current.into()
}

/// Derive 16-byte key from 32-byte KDF output (take first 16 bytes)
fn kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, paths);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Derive 12-byte nonce from 32-byte KDF output (take first 12 bytes)
fn kdf12(key: &[u8], paths: &[&[u8]]) -> [u8; 12] {
    let full = kdf(key, paths);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

/* ========================= CmdKey ========================= */

/// CmdKey = MD5(UUID || VMESS_MAGIC)
fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(VMESS_MAGIC);
    let result = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&result);
    key
}

/* ========================= EAuID (Auth ID) ========================= */

/// Decrypt an EAuID (16 bytes) and validate it.
/// Returns true if CRC32 matches and timestamp is within tolerance.
fn validate_eauid(eauid: &[u8; 16], cmd_key: &[u8; 16]) -> bool {
    // Derive AES key for auth ID decryption
    let aes_key = kdf16(cmd_key, &[AUTH_ID_ENCRYPTION_KEY]);

    // AES-128-ECB decrypt (single 16-byte block)
    use aes::cipher::BlockDecrypt;
    let cipher = Aes128::new(aes_key.as_ref().into());
    let mut block = aes::Block::clone_from_slice(eauid);
    cipher.decrypt_block(&mut block);
    let plaintext: [u8; 16] = block.into();

    // plaintext: [timestamp_u64_be (8B)] [random (4B)] [crc32_ieee (4B)]
    let timestamp = u64::from_be_bytes(plaintext[0..8].try_into().unwrap());
    let checksum = u32::from_be_bytes(plaintext[12..16].try_into().unwrap());

    // Verify CRC32 of first 12 bytes
    let computed_crc = crc32fast::hash(&plaintext[0..12]);
    if computed_crc != checksum {
        return false;
    }

    // Verify timestamp within tolerance
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let diff = if now > timestamp {
        now - timestamp
    } else {
        timestamp - now
    };
    diff <= TIMESTAMP_TOLERANCE
}

/* ========================= FNV1a hash ========================= */

fn fnv1a32(data: &[u8]) -> u32 {
    use fnv::FnvHasher;
    use std::hash::Hasher;
    let mut hasher = FnvHasher::with_key(0x811c9dc5);
    hasher.write(data);
    hasher.finish() as u32
}

/* ========================= VMessServer ========================= */

pub struct VMessServer {
    /// List of user UUIDs (16 bytes each)
    #[allow(dead_code)]
    users: Vec<[u8; 16]>,
    /// Pre-computed CmdKeys for each user
    cmd_keys: Vec<[u8; 16]>,
}

/// Parsed VMess header info
struct VMessHeader {
    /// Data encryption IV (from header)
    data_iv: [u8; 16],
    /// Data encryption key (from header)
    data_key: [u8; 16],
    /// Response auth byte
    resp_auth: u8,
    /// Security type for data stream
    security: VMessSecurity,
    /// Target address string "host:port"
    target: String,
    /// Options byte
    _opts: u8,
}

impl VMessServer {
    pub fn new(uuids: Vec<[u8; 16]>) -> Self {
        let cmd_keys: Vec<[u8; 16]> = uuids.iter().map(|u| cmd_key(u)).collect();
        VMessServer {
            users: uuids,
            cmd_keys,
        }
    }

    /// Accept a VMess connection: perform AEAD handshake, return a VMessStream + target address.
    pub async fn accept<S>(
        &self,
        mut stream: S,
    ) -> Result<(VMessStream<S>, String), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Step 1: Read 16-byte EAuID
        let mut eauid = [0u8; 16];
        stream.read_exact(&mut eauid).await?;

        // Try each user's CmdKey
        let matched_idx = self
            .cmd_keys
            .iter()
            .position(|ck| validate_eauid(&eauid, ck));

        let user_idx = matched_idx
            .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                "VMess: no matching user for EAuID".into()
            })?;

        let ck = &self.cmd_keys[user_idx];

        // Step 2: Read encrypted header length (2 bytes + 16 byte tag = 18 bytes)
        let mut enc_header_len = [0u8; 2 + AES_GCM_TAG_SIZE];
        stream.read_exact(&mut enc_header_len).await?;

        // Step 3: Read 8-byte nonce
        let mut connection_nonce = [0u8; 8];
        stream.read_exact(&mut connection_nonce).await?;

        // Decrypt header length with AES-128-GCM
        // Key = KDF(CmdKey, KDFSaltConst_VMessHeaderPayloadLengthAEADKey, EAuID, ConnectionNonce)
        let header_len_key = kdf16(ck, &[VMESS_HEADER_LEN_KEY, &eauid, &connection_nonce]);
        let header_len_iv = kdf12(ck, &[VMESS_HEADER_LEN_IV, &eauid, &connection_nonce]);

        let mut header_len_cipher =
            Aes128Gcm::new(header_len_key.as_ref().into());
        let nonce = Nonce::from_slice(&header_len_iv);

        // In-place decrypt: data is first 2 bytes, tag is last 16 bytes
        let (data_part, tag_part) = enc_header_len.split_at_mut(2);
        let tag = aes_gcm::Tag::from_slice(tag_part);
        header_len_cipher
            .decrypt_in_place_detached(nonce, &eauid, data_part, tag)
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                "VMess: header length decryption failed".into()
            })?;

        let header_len = u16::from_be_bytes([data_part[0], data_part[1]]) as usize;
        if header_len == 0 || header_len > 1024 {
            return Err("VMess: invalid header length".into());
        }

        // Step 4: Read encrypted header (header_len + 16 byte tag)
        let mut enc_header = vec![0u8; header_len + AES_GCM_TAG_SIZE];
        stream.read_exact(&mut enc_header).await?;

        // Decrypt header
        let header_key = kdf16(ck, &[VMESS_HEADER_KEY, &eauid, &connection_nonce]);
        let header_iv = kdf12(ck, &[VMESS_HEADER_IV, &eauid, &connection_nonce]);

        let mut header_cipher =
            Aes128Gcm::new(header_key.as_ref().into());
        let nonce = Nonce::from_slice(&header_iv);

        let (hdata, htag) = enc_header.split_at_mut(header_len);
        let htag = aes_gcm::Tag::from_slice(htag);
        header_cipher
            .decrypt_in_place_detached(nonce, &eauid, hdata, htag)
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                "VMess: header decryption failed".into()
            })?;

        let header = Self::parse_header(&enc_header[..header_len])?;

        // Step 5: Send response header
        Self::send_response_header(&mut stream, &header).await?;

        // Step 6: Build VMessStream
        let vmess_stream = VMessStream::new(stream, &header);
        Ok((vmess_stream, header.target))
    }

    /// Parse the decrypted VMess header.
    ///
    /// Layout:
    /// [version(1)] [data_iv(16)] [data_key(16)] [resp_auth(1)] [opts(1)]
    /// [padding_len_and_security(1)] [reserved(1)] [cmd(1)] [port(2)]
    /// [addr_type(1)] [addr(var)] [padding(var)] [fnv1a(4)]
    fn parse_header(
        data: &[u8],
    ) -> Result<VMessHeader, Box<dyn std::error::Error + Send + Sync>> {
        if data.len() < 41 {
            // Minimum: 1+16+16+1+1+1+1+1+2+1+1+0 (padding) +4 = 45 with at least 1 byte addr
            // Actually let's be more lenient and check as we go
            return Err("VMess: header too short".into());
        }

        let version = data[0];
        if version != 1 {
            return Err(format!("VMess: unsupported header version {}", version).into());
        }

        let mut data_iv = [0u8; 16];
        data_iv.copy_from_slice(&data[1..17]);
        let mut data_key = [0u8; 16];
        data_key.copy_from_slice(&data[17..33]);
        let resp_auth = data[33];
        let opts = data[34];
        let padding_and_security = data[35];
        let padding_len = (padding_and_security >> 4) as usize;
        let security_byte = padding_and_security & 0x0f;
        let _reserved = data[36];
        let cmd = data[37];

        if cmd != 0x01 {
            // 0x01 = TCP, 0x02 = UDP — we only support TCP
            return Err(format!("VMess: unsupported command {}", cmd).into());
        }

        let port = u16::from_be_bytes([data[38], data[39]]);
        let addr_type = data[40];

        let (addr_str, addr_end) = match addr_type {
            0x01 => {
                // IPv4 (4 bytes)
                if data.len() < 41 + 4 {
                    return Err("VMess: header too short for IPv4".into());
                }
                let ip = format!("{}.{}.{}.{}", data[41], data[42], data[43], data[44]);
                (ip, 45)
            }
            0x02 => {
                // Domain name: 1 byte length + domain
                if data.len() < 42 {
                    return Err("VMess: header too short for domain length".into());
                }
                let domain_len = data[41] as usize;
                if data.len() < 42 + domain_len {
                    return Err("VMess: header too short for domain".into());
                }
                let domain = String::from_utf8_lossy(&data[42..42 + domain_len]).to_string();
                (domain, 42 + domain_len)
            }
            0x03 => {
                // IPv6 (16 bytes)
                if data.len() < 41 + 16 {
                    return Err("VMess: header too short for IPv6".into());
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[41..57]);
                let ipv6 = std::net::Ipv6Addr::from(octets);
                (format!("[{}]", ipv6), 57)
            }
            _ => {
                return Err(format!("VMess: unsupported address type {}", addr_type).into());
            }
        };

        // After address: padding (padding_len bytes) + FNV1a checksum (4 bytes)
        let fnv_start = addr_end + padding_len;
        if data.len() < fnv_start + 4 {
            return Err("VMess: header too short for FNV checksum".into());
        }
        let expected_fnv = u32::from_be_bytes(
            data[fnv_start..fnv_start + 4].try_into().unwrap(),
        );
        let computed_fnv = fnv1a32(&data[..fnv_start]);
        if expected_fnv != computed_fnv {
            return Err("VMess: header FNV1a checksum mismatch".into());
        }

        let security = VMessSecurity::from_byte(security_byte)
            .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                format!("VMess: unsupported security type {}", security_byte).into()
            })?;

        Ok(VMessHeader {
            data_iv,
            data_key,
            resp_auth,
            security,
            target: format!("{}:{}", addr_str, port),
            _opts: opts,
        })
    }

    /// Send the VMess AEAD response header.
    async fn send_response_header<S>(
        stream: &mut S,
        header: &VMessHeader,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncWrite + Unpin,
    {
        // Response header (AEAD variant):
        // Derive response key and IV from data_key and data_iv using KDF
        let resp_key = kdf16(&header.data_key, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY]);
        let resp_iv = kdf12(&header.data_iv, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV]);
        let resp_payload_key = kdf16(&header.data_key, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let resp_payload_iv = kdf12(&header.data_iv, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);

        // Response header content: [resp_auth(1)] [opts(1)] [cmd(1)] [cmd_len(1)]
        // opts=0, cmd=0 (no dynamic port), cmd_len=0
        let resp_content = [header.resp_auth, 0x00, 0x00, 0x00];

        // Encrypt header length (length of resp_content = 4)
        let len_bytes = (resp_content.len() as u16).to_be_bytes();
        let mut len_buf = len_bytes.to_vec();
        let mut len_cipher = Aes128Gcm::new(resp_key.as_ref().into());
        let len_nonce = Nonce::from_slice(&resp_iv);
        let len_tag = len_cipher
            .encrypt_in_place_detached(len_nonce, &[], &mut len_buf)
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                "VMess: response header length encryption failed".into()
            })?;

        // Encrypt header content
        let mut content_buf = resp_content.to_vec();
        let mut content_cipher = Aes128Gcm::new(resp_payload_key.as_ref().into());
        let content_nonce = Nonce::from_slice(&resp_payload_iv);
        let content_tag = content_cipher
            .encrypt_in_place_detached(content_nonce, &[], &mut content_buf)
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                "VMess: response header content encryption failed".into()
            })?;

        // Write: [enc_len(2) + tag(16)] [enc_content(4) + tag(16)]
        let mut response = Vec::with_capacity(2 + 16 + resp_content.len() + 16);
        response.extend_from_slice(&len_buf);
        response.extend_from_slice(&len_tag);
        response.extend_from_slice(&content_buf);
        response.extend_from_slice(&content_tag);

        stream.write_all(&response).await?;
        stream.flush().await?;
        Ok(())
    }
}

/* ========================= VMessStream ========================= */

/// A stream wrapper that handles VMess AEAD chunked encryption/decryption.
/// Implements `AsyncRead + AsyncWrite` so it can be used with relay functions.
#[allow(dead_code)]
pub struct VMessStream<S> {
    inner: S,
    /// Data stream security type
    security: VMessSecurity,
    /// Read (decrypt) state
    read_key: [u8; 16],
    read_iv_prefix: [u8; 10], // header_iv[2..12] — used to build per-chunk nonce
    read_counter: u16,
    read_buf: Vec<u8>,      // decrypted data buffer
    read_buf_pos: usize,    // current position in read_buf
    read_done: bool,        // received zero-length chunk (EOS)
    /// Write (encrypt) state
    write_key: [u8; 16],
    write_iv_prefix: [u8; 10],
    write_counter: u16,
    /// Shutdown requested
    write_shutdown: bool,
}

impl<S> VMessStream<S> {
    fn new(inner: S, header: &VMessHeader) -> Self {
        // For AES-128-GCM data stream:
        // Read key/IV = from header (data flowing from client to us)
        // Write key/IV = from header (data flowing from us to client)
        //
        // Per V2Ray spec: client→server uses data_key/data_iv for encryption
        // Server→client uses the SAME data_key/data_iv but the response header
        // already uses different KDF-derived keys, and for the data stream
        // the server reuses data_key/data_iv with a separate counter.
        //
        // Actually in VMess AEAD: both directions use the same key/IV base
        // but with independent counters.
        let mut read_iv_prefix = [0u8; 10];
        read_iv_prefix.copy_from_slice(&header.data_iv[2..12]);
        let mut write_iv_prefix = [0u8; 10];
        write_iv_prefix.copy_from_slice(&header.data_iv[2..12]);

        VMessStream {
            inner,
            security: header.security,
            read_key: header.data_key,
            read_iv_prefix,
            read_counter: 0,
            read_buf: Vec::new(),
            read_buf_pos: 0,
            read_done: false,
            write_key: header.data_key,
            write_iv_prefix,
            write_counter: 0,
            write_shutdown: false,
        }
    }

    /// Build a 12-byte nonce from counter + IV prefix
    fn make_nonce(counter: u16, iv_prefix: &[u8; 10]) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..2].copy_from_slice(&counter.to_be_bytes());
        nonce[2..12].copy_from_slice(iv_prefix);
        nonce
    }
}

#[allow(dead_code)]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> VMessStream<S> {
    /// Read and decrypt one AEAD chunk from the inner stream.
    /// Returns Ok(true) if data was read, Ok(false) if EOS.
    async fn read_chunk(&mut self) -> io::Result<bool> {
        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        match self.inner.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.read_done = true;
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
        let chunk_len = u16::from_be_bytes(len_buf) as usize;

        // Zero-length chunk = EOS
        if chunk_len == 0 {
            self.read_done = true;
            return Ok(false);
        }

        match self.security {
            VMessSecurity::Aes128Gcm | VMessSecurity::Chacha20Poly1305 => {
                // chunk_len includes the AEAD tag (16 bytes)
                if chunk_len < AES_GCM_TAG_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VMess: chunk too small for AEAD tag",
                    ));
                }
                let mut enc_buf = vec![0u8; chunk_len];
                self.inner.read_exact(&mut enc_buf).await?;

                let nonce_bytes = Self::make_nonce(self.read_counter, &self.read_iv_prefix);
                self.read_counter = self.read_counter.wrapping_add(1);

                let payload_len = chunk_len - AES_GCM_TAG_SIZE;
                let (payload, tag_bytes) = enc_buf.split_at_mut(payload_len);
                let tag = aes_gcm::Tag::from_slice(tag_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                match self.security {
                    VMessSecurity::Aes128Gcm => {
                        let mut cipher = Aes128Gcm::new(self.read_key.as_ref().into());
                        cipher
                            .decrypt_in_place_detached(nonce, &[], payload, tag)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "VMess: AES-GCM chunk decrypt failed",
                                )
                            })?;
                    }
                    VMessSecurity::Chacha20Poly1305 => {
                        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaKeyInit, aead::AeadMutInPlace as ChaAead};
                        let mut cipher = ChaCha20Poly1305::new(
                            chacha20poly1305::Key::from_slice(&self.read_key),
                        );
                        let cha_nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                        let cha_tag = chacha20poly1305::Tag::from_slice(tag_bytes);
                        cipher
                            .decrypt_in_place_detached(cha_nonce, &[], payload, cha_tag)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "VMess: ChaCha20 chunk decrypt failed",
                                )
                            })?;
                    }
                    _ => unreachable!(),
                }

                self.read_buf = enc_buf[..payload_len].to_vec();
                self.read_buf_pos = 0;
                Ok(true)
            }
            VMessSecurity::None | VMessSecurity::Zero => {
                // No encryption — read raw payload
                let mut buf = vec![0u8; chunk_len];
                self.inner.read_exact(&mut buf).await?;
                self.read_buf = buf;
                self.read_buf_pos = 0;
                Ok(true)
            }
        }
    }

    /// Encrypt and write a chunk to the inner stream.
    async fn write_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        match self.security {
            VMessSecurity::Aes128Gcm | VMessSecurity::Chacha20Poly1305 => {
                let nonce_bytes = Self::make_nonce(self.write_counter, &self.write_iv_prefix);
                self.write_counter = self.write_counter.wrapping_add(1);

                let mut payload = data.to_vec();
                let nonce = Nonce::from_slice(&nonce_bytes);

                let tag = match self.security {
                    VMessSecurity::Aes128Gcm => {
                        let mut cipher = Aes128Gcm::new(self.write_key.as_ref().into());
                        cipher
                            .encrypt_in_place_detached(nonce, &[], &mut payload)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "VMess: AES-GCM chunk encrypt failed",
                                )
                            })?
                            .to_vec()
                    }
                    VMessSecurity::Chacha20Poly1305 => {
                        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaKeyInit, aead::AeadMutInPlace as ChaAead};
                        let mut cipher = ChaCha20Poly1305::new(
                            chacha20poly1305::Key::from_slice(&self.write_key),
                        );
                        let cha_nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                        cipher
                            .encrypt_in_place_detached(cha_nonce, &[], &mut payload)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "VMess: ChaCha20 chunk encrypt failed",
                                )
                            })?
                            .to_vec()
                    }
                    _ => unreachable!(),
                };

                let chunk_len = (payload.len() + tag.len()) as u16;
                self.inner.write_all(&chunk_len.to_be_bytes()).await?;
                self.inner.write_all(&payload).await?;
                self.inner.write_all(&tag).await?;
            }
            VMessSecurity::None | VMessSecurity::Zero => {
                let chunk_len = data.len() as u16;
                self.inner.write_all(&chunk_len.to_be_bytes()).await?;
                self.inner.write_all(data).await?;
            }
        }
        Ok(())
    }

    /// Send zero-length chunk to signal EOS.
    async fn send_eos(&mut self) -> io::Result<()> {
        self.inner.write_all(&[0u8; 2]).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

// Note: VMessStream does NOT implement AsyncRead/AsyncWrite directly because
// chunked AEAD decryption requires async reads (exact-size) that cannot be
// done in a synchronous poll_read context without a complex state machine.
// Instead, use `into_async_rw()` which spawns background tasks and returns
// duplex streams that implement AsyncRead+AsyncWrite transparently.

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> VMessStream<S> {
    /// Convert this VMessStream into a pair of duplex streams that can be used
    /// with standard AsyncRead/AsyncWrite relay functions.
    ///
    /// This spawns two background tasks:
    /// - A reader task that reads AEAD chunks from the inner stream and writes plaintext
    ///   to the read-side duplex.
    /// - A writer task that reads plaintext from the write-side duplex and writes
    ///   AEAD chunks to the inner stream.
    ///
    /// Returns a single DuplexStream that implements AsyncRead + AsyncWrite.
    pub fn into_async_rw(self) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        let (inner_read, inner_write) = tokio::io::split(self.inner);
        let security = self.security;
        let read_key = self.read_key;
        let read_iv_prefix = self.read_iv_prefix;
        let write_key = self.write_key;
        let write_iv_prefix = self.write_iv_prefix;

        // Read side: inner -> decrypted duplex
        let (read_tx, read_rx) = tokio::io::duplex(256 * 1024);

        // Write side: duplex -> encrypted inner
        let (write_tx, write_rx) = tokio::io::duplex(256 * 1024);

        // Spawn reader task
        tokio::spawn(async move {
            let mut inner_read = inner_read;
            let mut read_tx = read_tx;
            let mut counter: u16 = 0;

            loop {
                // Read 2-byte length
                let mut len_buf = [0u8; 2];
                match inner_read.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(_) => break,
                }
                let chunk_len = u16::from_be_bytes(len_buf) as usize;
                if chunk_len == 0 {
                    break; // EOS
                }

                match security {
                    VMessSecurity::Aes128Gcm | VMessSecurity::Chacha20Poly1305 => {
                        if chunk_len < AES_GCM_TAG_SIZE {
                            break;
                        }
                        let mut enc_buf = vec![0u8; chunk_len];
                        if inner_read.read_exact(&mut enc_buf).await.is_err() {
                            break;
                        }

                        let nonce_bytes = Self::make_nonce(counter, &read_iv_prefix);
                        counter = counter.wrapping_add(1);

                        let payload_len = chunk_len - AES_GCM_TAG_SIZE;
                        let (payload, tag_bytes) = enc_buf.split_at_mut(payload_len);

                        let ok = match security {
                            VMessSecurity::Aes128Gcm => {
                                let mut cipher = Aes128Gcm::new(read_key.as_ref().into());
                                let nonce = Nonce::from_slice(&nonce_bytes);
                                let tag = aes_gcm::Tag::from_slice(tag_bytes);
                                cipher.decrypt_in_place_detached(nonce, &[], payload, tag).is_ok()
                            }
                            VMessSecurity::Chacha20Poly1305 => {
                                use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaKeyInit, aead::AeadMutInPlace as ChaAead};
                                let mut cipher = ChaCha20Poly1305::new(
                                    chacha20poly1305::Key::from_slice(&read_key),
                                );
                                let cha_nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                                let cha_tag = chacha20poly1305::Tag::from_slice(tag_bytes);
                                cipher.decrypt_in_place_detached(cha_nonce, &[], payload, cha_tag).is_ok()
                            }
                            _ => unreachable!(),
                        };

                        if !ok {
                            break;
                        }

                        if read_tx.write_all(&enc_buf[..payload_len]).await.is_err() {
                            break;
                        }
                    }
                    VMessSecurity::None | VMessSecurity::Zero => {
                        let mut buf = vec![0u8; chunk_len];
                        if inner_read.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        if read_tx.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                }
            }

            let _ = read_tx.shutdown().await;
        });

        // Spawn writer task
        tokio::spawn(async move {
            let mut inner_write = inner_write;
            let mut write_rx = write_rx;
            let mut counter: u16 = 0;
            let mut buf = vec![0u8; 16384]; // read in 16KB chunks

            loop {
                let n = match write_rx.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };

                let data = &buf[..n];

                match security {
                    VMessSecurity::Aes128Gcm | VMessSecurity::Chacha20Poly1305 => {
                        let nonce_bytes = Self::make_nonce(counter, &write_iv_prefix);
                        counter = counter.wrapping_add(1);

                        let mut payload = data.to_vec();

                        let tag_vec = match security {
                            VMessSecurity::Aes128Gcm => {
                                let mut cipher = Aes128Gcm::new(write_key.as_ref().into());
                                let nonce = Nonce::from_slice(&nonce_bytes);
                                match cipher.encrypt_in_place_detached(nonce, &[], &mut payload) {
                                    Ok(tag) => tag.to_vec(),
                                    Err(_) => break,
                                }
                            }
                            VMessSecurity::Chacha20Poly1305 => {
                                use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaKeyInit, aead::AeadMutInPlace as ChaAead};
                                let mut cipher = ChaCha20Poly1305::new(
                                    chacha20poly1305::Key::from_slice(&write_key),
                                );
                                let cha_nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                                match cipher.encrypt_in_place_detached(cha_nonce, &[], &mut payload) {
                                    Ok(tag) => tag.to_vec(),
                                    Err(_) => break,
                                }
                            }
                            _ => unreachable!(),
                        };

                        let chunk_len = (payload.len() + tag_vec.len()) as u16;
                        if inner_write.write_all(&chunk_len.to_be_bytes()).await.is_err() {
                            break;
                        }
                        if inner_write.write_all(&payload).await.is_err() {
                            break;
                        }
                        if inner_write.write_all(&tag_vec).await.is_err() {
                            break;
                        }
                    }
                    VMessSecurity::None | VMessSecurity::Zero => {
                        let chunk_len = data.len() as u16;
                        if inner_write.write_all(&chunk_len.to_be_bytes()).await.is_err() {
                            break;
                        }
                        if inner_write.write_all(data).await.is_err() {
                            break;
                        }
                    }
                }

                if inner_write.flush().await.is_err() {
                    break;
                }
            }

            // Send EOS
            let _ = inner_write.write_all(&[0u8; 2]).await;
            let _ = inner_write.shutdown().await;
        });

        // Return: read_rx is the read half (decrypted data from client),
        // write_tx is the write half (plaintext to encrypt and send to client)
        (read_rx, write_tx)
    }
}

/* ========================= UUID helpers ========================= */

/// Parse a UUID string (with or without dashes) to 16 bytes.
/// If not a valid UUID, derive one via UUID v5 (DNS namespace).
pub fn parse_or_derive_uuid(input: &str) -> [u8; 16] {
    // Try parsing as UUID
    if let Ok(parsed) = uuid::Uuid::parse_str(input) {
        return *parsed.as_bytes();
    }

    // Derive via UUID v5 with DNS namespace
    let derived = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, input.as_bytes());
    tracing::info!(
        "Derived VMess UUID: {} (from input: {})",
        derived,
        input
    );
    *derived.as_bytes()
}

/* ========================= Tests ========================= */

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;

    #[test]
    fn test_kdf_deterministic() {
        let key = b"test-key-1234567";
        let result1 = kdf(key, &[b"path1"]);
        let result2 = kdf(key, &[b"path1"]);
        assert_eq!(result1, result2);

        let result3 = kdf(key, &[b"path2"]);
        assert_ne!(result1, result3);
    }

    #[test]
    fn test_cmd_key_deterministic() {
        let uuid = [1u8; 16];
        let k1 = cmd_key(&uuid);
        let k2 = cmd_key(&uuid);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_eauid_roundtrip() {
        let uuid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
        let ck = cmd_key(&uuid);
        let aes_key = kdf16(&ck, &[AUTH_ID_ENCRYPTION_KEY]);

        // Build plaintext
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut plaintext = [0u8; 16];
        plaintext[0..8].copy_from_slice(&now.to_be_bytes());
        plaintext[8..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // random
        let crc = crc32fast::hash(&plaintext[0..12]);
        plaintext[12..16].copy_from_slice(&crc.to_be_bytes());

        // Encrypt (AES-128-ECB)
        let cipher = Aes128::new(aes_key.as_ref().into());
        let mut block = aes::Block::clone_from_slice(&plaintext);
        cipher.encrypt_block(&mut block);
        let eauid: [u8; 16] = block.into();

        // Validate
        assert!(validate_eauid(&eauid, &ck));

        // Wrong key should fail
        let wrong_uuid = [0xFF; 16];
        let wrong_ck = cmd_key(&wrong_uuid);
        assert!(!validate_eauid(&eauid, &wrong_ck));
    }

    #[test]
    fn test_fnv1a32() {
        // Known FNV-1a values
        let hash = fnv1a32(b"");
        assert_eq!(hash, 0x811c9dc5); // FNV offset basis
    }

    #[test]
    fn test_parse_or_derive_uuid() {
        // Valid UUID
        let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let bytes = parse_or_derive_uuid(uuid_str);
        assert_eq!(bytes[0], 0xb8);

        // Non-UUID string → deterministic derivation
        let d1 = parse_or_derive_uuid("test-password-123");
        let d2 = parse_or_derive_uuid("test-password-123");
        assert_eq!(d1, d2);

        let d3 = parse_or_derive_uuid("different-password");
        assert_ne!(d1, d3);
    }

    #[test]
    fn test_vmess_security_from_byte() {
        assert_eq!(VMessSecurity::from_byte(0x03), Some(VMessSecurity::Aes128Gcm));
        assert_eq!(VMessSecurity::from_byte(0x04), Some(VMessSecurity::Chacha20Poly1305));
        assert_eq!(VMessSecurity::from_byte(0x05), Some(VMessSecurity::None));
        assert_eq!(VMessSecurity::from_byte(0x00), Some(VMessSecurity::Zero));
        assert_eq!(VMessSecurity::from_byte(0x01), Option::None); // legacy, unsupported
    }

    /* ============ VMess AEAD client-side helpers for testing ============ */

    /// Build EAuID: AES-128-ECB(key=KDF(CmdKey, "AES Auth ID Encryption"), plaintext)
    /// plaintext = [timestamp_be(8)] [random(4)] [crc32(first 12 bytes)(4)]
    fn build_eauid(ck: &[u8; 16]) -> [u8; 16] {
        let aes_key = kdf16(ck, &[AUTH_ID_ENCRYPTION_KEY]);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut plain = [0u8; 16];
        plain[0..8].copy_from_slice(&now.to_be_bytes());
        plain[8..12].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]); // random
        let crc = crc32fast::hash(&plain[0..12]);
        plain[12..16].copy_from_slice(&crc.to_be_bytes());

        let cipher = Aes128::new(aes_key.as_ref().into());
        let mut block = aes::Block::clone_from_slice(&plain);
        cipher.encrypt_block(&mut block);
        block.into()
    }

    /// Build the VMess request header plaintext (before encryption).
    /// Returns (header_bytes, data_iv, data_key, resp_auth)
    fn build_header_plaintext(
        target_host: &str,
        target_port: u16,
        security: u8, // 0x03 = AES-128-GCM
    ) -> (Vec<u8>, [u8; 16], [u8; 16], u8) {
        let data_iv: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let data_key: [u8; 16] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        ];
        let resp_auth: u8 = 0xAB;
        let opts: u8 = 0x01; // standard opts (S bit = chunk stream)
        let padding_len: u8 = 0;
        let padding_and_security = (padding_len << 4) | (security & 0x0f);
        let reserved: u8 = 0x00;
        let cmd: u8 = 0x01; // TCP

        let host_bytes = target_host.as_bytes();

        let mut hdr = Vec::new();
        hdr.push(1u8); // version
        hdr.extend_from_slice(&data_iv);
        hdr.extend_from_slice(&data_key);
        hdr.push(resp_auth);
        hdr.push(opts);
        hdr.push(padding_and_security);
        hdr.push(reserved);
        hdr.push(cmd);
        hdr.extend_from_slice(&target_port.to_be_bytes());
        hdr.push(0x02); // addr_type = domain
        hdr.push(host_bytes.len() as u8);
        hdr.extend_from_slice(host_bytes);
        // no padding (padding_len=0)

        // Append FNV1a checksum
        let fnv = fnv1a32(&hdr);
        hdr.extend_from_slice(&fnv.to_be_bytes());

        (hdr, data_iv, data_key, resp_auth)
    }

    /// Full VMess AEAD client: send handshake, receive response header, verify resp_auth.
    /// Returns the TcpStream positioned at the data phase + the data_key + data_iv.
    async fn vmess_client_handshake(
        stream: &mut TcpStream,
        uuid: &[u8; 16],
        target_host: &str,
        target_port: u16,
        security: u8,
    ) -> (
        [u8; 16], // data_key
        [u8; 16], // data_iv
        u8,       // resp_auth (for verification)
    ) {
        let ck = cmd_key(uuid);

        // 1. Build & send EAuID
        let eauid = build_eauid(&ck);
        stream.write_all(&eauid).await.unwrap();

        // 2. Build & encrypt header
        let (header_plain, data_iv, data_key, resp_auth) =
            build_header_plaintext(target_host, target_port, security);

        // Connection nonce (random 8 bytes)
        let connection_nonce: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];

        // Encrypt header length
        let header_len = header_plain.len() as u16;
        let header_len_key = kdf16(&ck, &[VMESS_HEADER_LEN_KEY, &eauid, &connection_nonce]);
        let header_len_iv = kdf12(&ck, &[VMESS_HEADER_LEN_IV, &eauid, &connection_nonce]);
        let mut len_buf = header_len.to_be_bytes().to_vec();
        let mut len_cipher = Aes128Gcm::new(header_len_key.as_ref().into());
        let len_tag = len_cipher
            .encrypt_in_place_detached(Nonce::from_slice(&header_len_iv), &eauid, &mut len_buf)
            .unwrap();

        // Send: [enc_header_len(2) + tag(16)]
        stream.write_all(&len_buf).await.unwrap();
        stream.write_all(&len_tag).await.unwrap();

        // Send: [connection_nonce(8)]
        stream.write_all(&connection_nonce).await.unwrap();

        // Encrypt header payload
        let header_key = kdf16(&ck, &[VMESS_HEADER_KEY, &eauid, &connection_nonce]);
        let header_iv = kdf12(&ck, &[VMESS_HEADER_IV, &eauid, &connection_nonce]);
        let mut hdr_buf = header_plain.clone();
        let mut hdr_cipher = Aes128Gcm::new(header_key.as_ref().into());
        let hdr_tag = hdr_cipher
            .encrypt_in_place_detached(Nonce::from_slice(&header_iv), &eauid, &mut hdr_buf)
            .unwrap();

        // Send: [enc_header + tag(16)]
        stream.write_all(&hdr_buf).await.unwrap();
        stream.write_all(&hdr_tag).await.unwrap();
        stream.flush().await.unwrap();

        // 3. Read AEAD response header
        // Response: [enc_len(2) + tag(16)] [enc_content(N) + tag(16)]
        let resp_len_key = kdf16(&data_key, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY]);
        let resp_len_iv = kdf12(&data_iv, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV]);
        let resp_payload_key = kdf16(&data_key, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let resp_payload_iv = kdf12(&data_iv, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);

        // Read encrypted length + tag
        let mut resp_len_enc = [0u8; 2 + AES_GCM_TAG_SIZE];
        stream.read_exact(&mut resp_len_enc).await.unwrap();

        let (rlen_data, rlen_tag) = resp_len_enc.split_at_mut(2);
        let rlen_tag = aes_gcm::Tag::from_slice(rlen_tag);
        let mut resp_len_cipher = Aes128Gcm::new(resp_len_key.as_ref().into());
        resp_len_cipher
            .decrypt_in_place_detached(Nonce::from_slice(&resp_len_iv), &[], rlen_data, rlen_tag)
            .expect("Response length decryption failed");

        let resp_content_len = u16::from_be_bytes([rlen_data[0], rlen_data[1]]) as usize;
        assert_eq!(resp_content_len, 4, "Expected response content length = 4");

        // Read encrypted content + tag
        let mut resp_content_enc = vec![0u8; resp_content_len + AES_GCM_TAG_SIZE];
        stream.read_exact(&mut resp_content_enc).await.unwrap();

        let (rcont_data, rcont_tag) = resp_content_enc.split_at_mut(resp_content_len);
        let rcont_tag = aes_gcm::Tag::from_slice(rcont_tag);
        let mut resp_content_cipher = Aes128Gcm::new(resp_payload_key.as_ref().into());
        resp_content_cipher
            .decrypt_in_place_detached(Nonce::from_slice(&resp_payload_iv), &[], rcont_data, rcont_tag)
            .expect("Response content decryption failed");

        // Verify resp_auth matches
        assert_eq!(rcont_data[0], resp_auth, "Response auth byte mismatch");

        (data_key, data_iv, resp_auth)
    }

    /// Encrypt a data chunk (client→server) using AES-128-GCM AEAD chunking.
    fn encrypt_data_chunk(data: &[u8], key: &[u8; 16], iv_prefix: &[u8; 10], counter: u16) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        nonce[0..2].copy_from_slice(&counter.to_be_bytes());
        nonce[2..12].copy_from_slice(iv_prefix);

        let mut payload = data.to_vec();
        let mut cipher = Aes128Gcm::new(key.as_ref().into());
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut payload)
            .unwrap();

        let chunk_len = (payload.len() + tag.len()) as u16;
        let mut out = Vec::new();
        out.extend_from_slice(&chunk_len.to_be_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&tag);
        out
    }

    /// Decrypt a data chunk (server→client) using AES-128-GCM AEAD chunking.
    fn decrypt_data_chunk(enc: &[u8], key: &[u8; 16], iv_prefix: &[u8; 10], counter: u16) -> Vec<u8> {
        // enc = [payload + tag] (length prefix already stripped)
        let mut nonce = [0u8; 12];
        nonce[0..2].copy_from_slice(&counter.to_be_bytes());
        nonce[2..12].copy_from_slice(iv_prefix);

        let payload_len = enc.len() - AES_GCM_TAG_SIZE;
        let mut payload = enc[..payload_len].to_vec();
        let tag = aes_gcm::Tag::from_slice(&enc[payload_len..]);

        let mut cipher = Aes128Gcm::new(key.as_ref().into());
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut payload, tag)
            .expect("Data chunk decryption failed");
        payload
    }

    /* ============ End-to-end tests ============ */

    /// Test: Full VMess AEAD handshake + bidirectional data with AES-128-GCM.
    /// Uses a real UUID. Client connects, server accepts, data flows both ways.
    #[tokio::test]
    async fn test_vmess_e2e_aes128gcm() {
        let _ = tracing_subscriber::fmt::try_init();

        // UUID (standard v4 format)
        let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let uuid = parse_or_derive_uuid(uuid_str);
        let server = std::sync::Arc::new(VMessServer::new(vec![uuid]));

        // Start TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server accept
        let srv = server.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _client_addr) = listener.accept().await.unwrap();
            let (vmess_stream, target) = srv.accept(stream).await.unwrap();
            (vmess_stream, target)
        });

        // Client: connect and do handshake
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (data_key, data_iv, _resp_auth) =
            vmess_client_handshake(&mut client, &uuid, "example.com", 443, 0x03).await;

        // Server side completes
        let (vmess_stream, target) = server_handle.await.unwrap();

        // Verify target address
        assert_eq!(target, "example.com:443");

        // Convert to async read/write via duplex bridge
        let (mut server_read, mut server_write) = vmess_stream.into_async_rw();

        let iv_prefix: [u8; 10] = data_iv[2..12].try_into().unwrap();

        // Client sends encrypted data chunk → server reads plaintext
        let test_data = b"Hello VMess AEAD from client!";
        let encrypted_chunk = encrypt_data_chunk(test_data, &data_key, &iv_prefix, 0);
        client.write_all(&encrypted_chunk).await.unwrap();
        // Send EOS
        client.write_all(&[0u8; 2]).await.unwrap();
        client.flush().await.unwrap();

        // Server reads decrypted data
        let mut buf = vec![0u8; 1024];
        let n = server_read.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], test_data);

        // Server writes plaintext → client reads encrypted chunk
        let response_data = b"Hello VMess AEAD from server!";
        server_write.write_all(response_data).await.unwrap();
        server_write.flush().await.unwrap();
        // Need to close/shutdown to flush the writer task
        drop(server_write);

        // Client reads the encrypted chunk from server
        // First read 2-byte length
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await.unwrap();
        let chunk_len = u16::from_be_bytes(len_buf) as usize;
        assert!(chunk_len > 0, "Expected non-zero chunk from server");

        // Read chunk body
        let mut chunk_body = vec![0u8; chunk_len];
        client.read_exact(&mut chunk_body).await.unwrap();

        // Decrypt
        let decrypted = decrypt_data_chunk(&chunk_body, &data_key, &iv_prefix, 0);
        assert_eq!(&decrypted, response_data);

        eprintln!("[PASS] VMess AEAD e2e AES-128-GCM: handshake OK, data round-trip OK");
    }

    /// Test: VMess handshake with wrong UUID should fail.
    #[tokio::test]
    async fn test_vmess_wrong_uuid_rejected() {
        let _ = tracing_subscriber::fmt::try_init();

        let server_uuid = parse_or_derive_uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let wrong_uuid = parse_or_derive_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        let server = std::sync::Arc::new(VMessServer::new(vec![server_uuid]));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = server.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            srv.accept(stream).await
        });

        // Client sends handshake with wrong UUID
        let mut client = TcpStream::connect(addr).await.unwrap();
        let wrong_ck = cmd_key(&wrong_uuid);
        let eauid = build_eauid(&wrong_ck);
        client.write_all(&eauid).await.unwrap();

        // Send some garbage for the rest
        client.write_all(&[0u8; 26]).await.unwrap(); // enc_header_len + nonce
        client.flush().await.unwrap();

        // Server should reject
        let result = server_handle.await.unwrap();
        match result {
            Ok(_) => panic!("Expected rejection for wrong UUID, but handshake succeeded"),
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("no matching user"),
                    "Expected 'no matching user' error, got: {}",
                    err_msg
                );
            }
        }

        eprintln!("[PASS] VMess wrong UUID correctly rejected");
    }

    /// Test: VMess handshake with IPv4 target address.
    #[tokio::test]
    async fn test_vmess_ipv4_target() {
        let _ = tracing_subscriber::fmt::try_init();

        let uuid = parse_or_derive_uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let server = std::sync::Arc::new(VMessServer::new(vec![uuid]));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = server.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            srv.accept(stream).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let ck = cmd_key(&uuid);

        // Build EAuID
        let eauid = build_eauid(&ck);
        client.write_all(&eauid).await.unwrap();

        // Build header with IPv4 address
        let data_iv: [u8; 16] = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ];
        let data_key: [u8; 16] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        ];
        let resp_auth: u8 = 0xCD;
        let mut hdr = Vec::new();
        hdr.push(1u8); // version
        hdr.extend_from_slice(&data_iv);
        hdr.extend_from_slice(&data_key);
        hdr.push(resp_auth);
        hdr.push(0x01); // opts
        hdr.push(0x03); // padding=0, security=AES-128-GCM
        hdr.push(0x00); // reserved
        hdr.push(0x01); // cmd=TCP
        hdr.extend_from_slice(&8080u16.to_be_bytes()); // port
        hdr.push(0x01); // addr_type = IPv4
        hdr.extend_from_slice(&[192, 168, 1, 100]); // 192.168.1.100
        let fnv = fnv1a32(&hdr);
        hdr.extend_from_slice(&fnv.to_be_bytes());

        let connection_nonce: [u8; 8] = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7];

        // Encrypt header length
        let header_len = hdr.len() as u16;
        let header_len_key = kdf16(&ck, &[VMESS_HEADER_LEN_KEY, &eauid, &connection_nonce]);
        let header_len_iv = kdf12(&ck, &[VMESS_HEADER_LEN_IV, &eauid, &connection_nonce]);
        let mut len_buf = header_len.to_be_bytes().to_vec();
        let mut len_cipher = Aes128Gcm::new(header_len_key.as_ref().into());
        let len_tag = len_cipher
            .encrypt_in_place_detached(Nonce::from_slice(&header_len_iv), &eauid, &mut len_buf)
            .unwrap();
        client.write_all(&len_buf).await.unwrap();
        client.write_all(&len_tag).await.unwrap();
        client.write_all(&connection_nonce).await.unwrap();

        // Encrypt header
        let header_key = kdf16(&ck, &[VMESS_HEADER_KEY, &eauid, &connection_nonce]);
        let header_iv = kdf12(&ck, &[VMESS_HEADER_IV, &eauid, &connection_nonce]);
        let mut hdr_buf = hdr.clone();
        let mut hdr_cipher = Aes128Gcm::new(header_key.as_ref().into());
        let hdr_tag = hdr_cipher
            .encrypt_in_place_detached(Nonce::from_slice(&header_iv), &eauid, &mut hdr_buf)
            .unwrap();
        client.write_all(&hdr_buf).await.unwrap();
        client.write_all(&hdr_tag).await.unwrap();
        client.flush().await.unwrap();

        let result = server_handle.await.unwrap();
        assert!(result.is_ok(), "Handshake should succeed for IPv4");
        let (_vmess_stream, target) = result.unwrap();
        assert_eq!(target, "192.168.1.100:8080");

        eprintln!("[PASS] VMess IPv4 target parsed correctly");
    }

    /// Test: Multiple users — server matches the correct one.
    #[tokio::test]
    async fn test_vmess_multi_user() {
        let _ = tracing_subscriber::fmt::try_init();

        let uuid1 = parse_or_derive_uuid("11111111-1111-1111-1111-111111111111");
        let uuid2 = parse_or_derive_uuid("22222222-2222-2222-2222-222222222222");
        let uuid3 = parse_or_derive_uuid("33333333-3333-3333-3333-333333333333");
        let server = std::sync::Arc::new(VMessServer::new(vec![uuid1, uuid2, uuid3]));

        // Connect as user2
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = server.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            srv.accept(stream).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let (_data_key, _data_iv, _resp_auth) =
            vmess_client_handshake(&mut client, &uuid2, "multi.test.com", 8443, 0x03).await;

        let result = server_handle.await.unwrap();
        assert!(result.is_ok(), "User2 should be accepted");
        let (_stream, target) = result.unwrap();
        assert_eq!(target, "multi.test.com:8443");

        eprintln!("[PASS] VMess multi-user: user2 correctly matched");
    }
}
