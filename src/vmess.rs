//! VMess AEAD server-side protocol implementation.
//!
//! Implements the modern VMess AEAD variant (no legacy MD5-based auth).
//! Clients (v2ray, v2rayNG, clash, etc.) connect with a UUID and the server
//! decrypts traffic, extracts the destination address, and returns a
//! `VMessStream` that transparently handles chunked AEAD encryption.

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

// Option flags from the VMess header
#[cfg(test)]
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;

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

/// VMess AEAD KDF: nested HMAC construction matching V2Ray's implementation.
///
/// V2Ray builds a chain of HMAC creators:
///   level 0 (root): HMAC-SHA256 keyed with "VMess AEAD KDF"
///   level i: HMAC keyed with paths[i-1], using level (i-1) as hash function
///
/// The final call feeds `key` as the message to the outermost HMAC.
fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    nested_hmac(key, paths, paths.len())
}

/// Compute the nested HMAC hash at `level` applied to `message`.
///
/// Level 0: H(message) = HMAC-SHA256(key=KDF_SALT_CONST)(message)
/// Level n: H(message) = HMAC(key=paths[n-1], hash_fn=level_{n-1})(message)
///
/// Where HMAC(K, M) using hash H = H(opad_K || H(ipad_K || M))
fn nested_hmac(message: &[u8], paths: &[&[u8]], level: usize) -> [u8; 32] {
    if level == 0 {
        // Base case: standard HMAC-SHA256 keyed with KDF_SALT_CONST
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(KDF_SALT_CONST)
            .expect("HMAC can take key of any size");
        mac.update(message);
        mac.finalize().into_bytes().into()
    } else {
        // Build HMAC manually: HMAC(key=paths[level-1], H=level_{level-1})(message)
        // H(data) = nested_hmac(data, paths, level - 1)
        //
        // HMAC(K, M) = H((K' ^ opad) || H((K' ^ ipad) || M))
        // block_size = 64 (Go's HMAC-SHA256 reports block size 64 at all levels)
        let hmac_key = paths[level - 1];
        const BLOCK_SIZE: usize = 64;

        // Derive K' (key padded/hashed to block_size)
        let mut k_prime = [0u8; BLOCK_SIZE];
        if hmac_key.len() > BLOCK_SIZE {
            let hashed = nested_hmac(hmac_key, paths, level - 1);
            k_prime[..32].copy_from_slice(&hashed);
        } else {
            k_prime[..hmac_key.len()].copy_from_slice(hmac_key);
        }

        // Compute ipad and opad
        let mut ipad = [0u8; BLOCK_SIZE];
        let mut opad = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            ipad[i] = k_prime[i] ^ 0x36;
            opad[i] = k_prime[i] ^ 0x5c;
        }

        // inner = H_{level-1}(ipad || message)
        let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
        inner_input.extend_from_slice(&ipad);
        inner_input.extend_from_slice(message);
        let inner_hash = nested_hmac(&inner_input, paths, level - 1);

        // result = H_{level-1}(opad || inner_hash)
        let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 32);
        outer_input.extend_from_slice(&opad);
        outer_input.extend_from_slice(&inner_hash);
        nested_hmac(&outer_input, paths, level - 1)
    }
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

/* ========================= SHAKE128 chunk masking ========================= */

/// Pre-computed SHAKE128 mask stream for VMess chunk size masking.
/// V2Ray seeds SHAKE128 with body IV and reads 2 bytes per chunk for XOR masking.
struct ShakeMask {
    stream: Vec<u8>,
    pos: usize,
}

impl ShakeMask {
    fn new(nonce: &[u8]) -> Self {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut hasher = sha3::Shake128::default();
        Update::update(&mut hasher, nonce);
        let mut reader = hasher.finalize_xof();
        // Pre-generate enough mask bytes (8KB = 4096 chunks, covers ~64GB of data)
        let mut stream = vec![0u8; 8192];
        XofReader::read(&mut reader, &mut stream);
        ShakeMask { stream, pos: 0 }
    }

    fn next_mask(&mut self) -> u16 {
        let mask = u16::from_be_bytes([self.stream[self.pos], self.stream[self.pos + 1]]);
        self.pos += 2;
        mask
    }

    fn encode_size(&mut self, size: u16) -> [u8; 2] {
        (size ^ self.next_mask()).to_be_bytes()
    }

    fn decode_size(&mut self, encoded: [u8; 2]) -> u16 {
        u16::from_be_bytes(encoded) ^ self.next_mask()
    }
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
    let mut hash: u32 = 0x811c9dc5; // FNV-1a 32-bit offset basis
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193); // FNV-1a 32-bit prime
    }
    hash
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
    /// Data encryption IV (from header) — used for client→server
    data_iv: [u8; 16],
    /// Data encryption key (from header) — used for client→server
    data_key: [u8; 16],
    /// Response body key = SHA256(data_key)[:16] — used for server→client
    resp_body_key: [u8; 16],
    /// Response body IV = SHA256(data_iv)[:16] — used for server→client
    resp_body_iv: [u8; 16],
    /// Response auth byte
    resp_auth: u8,
    /// Security type for data stream
    security: VMessSecurity,
    /// Target address string "host:port"
    target: String,
    /// Options byte (bitmask: 0x01=ChunkStream, 0x04=ChunkMasking, etc.)
    opts: u8,
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
        tracing::debug!("VMess header: raw_iv={:02x?}, raw_key={:02x?}, opts=0x{:02x}", &data_iv, &data_key, opts);
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

        // In AEAD mode, the header contains raw random bytes for request body key/IV.
        // Server uses them DIRECTLY (no SHA256) for request body encryption.
        // Response keys = SHA256(requestBodyKey/IV)[:16]
        let resp_body_key_full = Sha256::digest(&data_key);
        let mut resp_body_key = [0u8; 16];
        resp_body_key.copy_from_slice(&resp_body_key_full[..16]);

        let resp_body_iv_full = Sha256::digest(&data_iv);
        let mut resp_body_iv = [0u8; 16];
        resp_body_iv.copy_from_slice(&resp_body_iv_full[..16]);

        Ok(VMessHeader {
            data_iv,
            data_key,
            resp_body_key,
            resp_body_iv,
            resp_auth,
            security,
            target: format!("{}:{}", addr_str, port),
            opts,
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
        // Response header uses SHA256-derived response body keys
        let resp_key = kdf16(&header.resp_body_key, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY]);
        let resp_iv = kdf12(&header.resp_body_iv, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV]);
        let resp_payload_key = kdf16(&header.resp_body_key, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let resp_payload_iv = kdf12(&header.resp_body_iv, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);

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
pub struct VMessStream<S> {
    inner: S,
    /// Data stream security type
    security: VMessSecurity,
    /// Options flags
    opts: u8,
    /// Read (decrypt, client→server) key
    read_key: [u8; 16],
    /// Read IV (full 16 bytes, for SHAKE128 seed and nonce generation)
    read_iv: [u8; 16],
    /// Write (encrypt, server→client) key — uses response body key
    write_key: [u8; 16],
    /// Write IV (full 16 bytes) — uses response body IV
    write_iv: [u8; 16],
}

impl<S> VMessStream<S> {
    fn new(inner: S, header: &VMessHeader) -> Self {
        VMessStream {
            inner,
            security: header.security,
            opts: header.opts,
            // Client→server: request body keys
            read_key: header.data_key,
            read_iv: header.data_iv,
            // Server→client: SHA256-derived response body keys
            write_key: header.resp_body_key,
            write_iv: header.resp_body_iv,
        }
    }

    /// Build a 12-byte AEAD nonce: [counter_u16_be(2)] || iv[2..12]
    fn make_nonce(counter: u16, iv: &[u8; 16]) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..2].copy_from_slice(&counter.to_be_bytes());
        nonce[2..12].copy_from_slice(&iv[2..12]);
        nonce
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> VMessStream<S> {
    /// Convert this VMessStream into a pair of duplex streams that can be used
    /// with standard AsyncRead/AsyncWrite relay functions.
    ///
    /// Returns (read_half, write_half):
    /// - read_half: decrypted data from client (client→server direction)
    /// - write_half: plaintext to encrypt and send to client (server→client direction)
    pub fn into_async_rw(self) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        let (inner_read, inner_write) = tokio::io::split(self.inner);
        let security = self.security;
        let opts = self.opts;
        let read_key = self.read_key;
        let read_iv = self.read_iv;
        let write_key = self.write_key;
        let write_iv = self.write_iv;

        // Read side: inner -> decrypted duplex
        let (read_tx, read_rx) = tokio::io::duplex(256 * 1024);

        // Write side: duplex -> encrypted inner
        let (write_tx, write_rx) = tokio::io::duplex(256 * 1024);

        let use_chunk_masking = (opts & OPT_CHUNK_MASKING) != 0;
        let use_global_padding = (opts & OPT_GLOBAL_PADDING) != 0;

        // Spawn reader task (client→server: decrypt with request body keys)
        tokio::spawn(async move {
            let mut inner_read = inner_read;
            let mut read_tx = read_tx;
            let mut counter: u16 = 0;
            let mut shake_mask = if use_chunk_masking {
                Some(ShakeMask::new(&read_iv))
            } else {
                None
            };

            tracing::debug!("VMess reader task started, chunk_masking={}, global_padding={}", use_chunk_masking, use_global_padding);

            loop {
                // Step 1: If GlobalPadding enabled, consume padding length from SHAKE128 FIRST
                // V2Ray order: NextPaddingLen() then Decode() for each chunk
                let padding_len: usize = if use_global_padding {
                    if let Some(mask) = &mut shake_mask {
                        (mask.next_mask() % 64) as usize
                    } else {
                        0
                    }
                } else {
                    0
                };

                // Step 2: Read 2-byte chunk length
                let mut len_buf = [0u8; 2];
                if inner_read.read_exact(&mut len_buf).await.is_err() {
                    break;
                }

                // Step 3: Decode chunk size (with SHAKE128 mask if applicable)
                let chunk_size = if let Some(mask) = &mut shake_mask {
                    mask.decode_size(len_buf) as usize
                } else {
                    u16::from_be_bytes(len_buf) as usize
                };

                tracing::trace!("VMess reader: raw_len={:02x}{:02x} decoded_size={} padding={}", len_buf[0], len_buf[1], chunk_size, padding_len);

                // The decoded chunk_size = encrypted_payload_size + padding_len
                // encrypted_payload_size = plaintext + AEAD_overhead (16 for GCM)

                // Check for EOF
                match security {
                    VMessSecurity::Aes128Gcm | VMessSecurity::Chacha20Poly1305 => {
                        // EOF when chunk_size == padding_len + AEAD_overhead (just tag, no payload)
                        let aead_portion = if chunk_size >= padding_len { chunk_size - padding_len } else { 0 };
                        if aead_portion <= AES_GCM_TAG_SIZE {
                            break; // EOF or empty
                        }
                    }
                    VMessSecurity::None | VMessSecurity::Zero => {
                        if chunk_size <= padding_len {
                            break; // EOF
                        }
                    }
                }

                // Read the full chunk (AEAD ciphertext+tag + padding)
                let mut full_buf = vec![0u8; chunk_size];
                if inner_read.read_exact(&mut full_buf).await.is_err() {
                    break;
                }

                // Split off padding (last padding_len bytes are random, discard)
                let aead_len = chunk_size - padding_len;

                match security {
                    VMessSecurity::Aes128Gcm | VMessSecurity::Chacha20Poly1305 => {
                        let nonce_bytes = Self::make_nonce(counter, &read_iv);
                        counter = counter.wrapping_add(1);

                        let payload_len = aead_len - AES_GCM_TAG_SIZE;
                        let (payload, tag_bytes) = full_buf[..aead_len].split_at_mut(payload_len);

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
                            tracing::debug!("VMess: chunk decrypt failed at counter {}", counter - 1);
                            break;
                        }

                        if read_tx.write_all(&full_buf[..payload_len]).await.is_err() {
                            break;
                        }
                    }
                    VMessSecurity::None | VMessSecurity::Zero => {
                        if read_tx.write_all(&full_buf[..aead_len]).await.is_err() {
                            break;
                        }
                    }
                }
            }

            let _ = read_tx.shutdown().await;
        });

        // Spawn writer task (server→client: encrypt with response body keys)
        tokio::spawn(async move {
            let mut inner_write = inner_write;
            let mut write_rx = write_rx;
            let mut counter: u16 = 0;
            let mut shake_mask = if use_chunk_masking {
                Some(ShakeMask::new(&write_iv))
            } else {
                None
            };
            let mut buf = vec![0u8; 16384]; // read in 16KB chunks

            loop {
                let n = match write_rx.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };

                let data = &buf[..n];

                // V2Ray order: NextPaddingLen() FIRST, then Encode()
                let padding_len: usize = if use_global_padding {
                    if let Some(ref mut mask) = shake_mask {
                        (mask.next_mask() % 64) as usize
                    } else {
                        0
                    }
                } else {
                    0
                };

                match security {
                    VMessSecurity::Aes128Gcm | VMessSecurity::Chacha20Poly1305 => {
                        let nonce_bytes = Self::make_nonce(counter, &write_iv);
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

                        // chunk_size = encrypted_data + tag + padding
                        let chunk_size = (payload.len() + tag_vec.len() + padding_len) as u16;
                        let encoded_size = if let Some(ref mut mask) = shake_mask {
                            mask.encode_size(chunk_size)
                        } else {
                            chunk_size.to_be_bytes()
                        };

                        if inner_write.write_all(&encoded_size).await.is_err() {
                            break;
                        }
                        if inner_write.write_all(&payload).await.is_err() {
                            break;
                        }
                        if inner_write.write_all(&tag_vec).await.is_err() {
                            break;
                        }
                        // Write random padding
                        if padding_len > 0 {
                            let padding = vec![0u8; padding_len]; // zeros are fine for padding
                            if inner_write.write_all(&padding).await.is_err() {
                                break;
                            }
                        }
                    }
                    VMessSecurity::None | VMessSecurity::Zero => {
                        let chunk_size = (data.len() + padding_len) as u16;
                        let encoded_size = if let Some(ref mut mask) = shake_mask {
                            mask.encode_size(chunk_size)
                        } else {
                            chunk_size.to_be_bytes()
                        };
                        if inner_write.write_all(&encoded_size).await.is_err() {
                            break;
                        }
                        if inner_write.write_all(data).await.is_err() {
                            break;
                        }
                        if padding_len > 0 {
                            let padding = vec![0u8; padding_len];
                            if inner_write.write_all(&padding).await.is_err() {
                                break;
                            }
                        }
                    }
                }

                if inner_write.flush().await.is_err() {
                    break;
                }
            }

            // Send EOF chunk (must include padding, matching v2ray's protocol)
            // V2ray EOF check: size == overhead + padding
            let eof_padding: usize = if use_global_padding {
                if let Some(ref mut mask) = shake_mask {
                    (mask.next_mask() % 64) as usize
                } else {
                    0
                }
            } else {
                0
            };

            let eof_size = match security {
                VMessSecurity::Aes128Gcm | VMessSecurity::Chacha20Poly1305 =>
                    (AES_GCM_TAG_SIZE + eof_padding) as u16,
                _ => eof_padding as u16,
            };
            let eof_encoded = if let Some(ref mut mask) = shake_mask {
                mask.encode_size(eof_size)
            } else {
                eof_size.to_be_bytes()
            };
            let _ = inner_write.write_all(&eof_encoded).await;
            // For AEAD modes, send the empty-payload tag
            if matches!(security, VMessSecurity::Aes128Gcm | VMessSecurity::Chacha20Poly1305) {
                let nonce_bytes = Self::make_nonce(counter, &write_iv);
                let mut empty = Vec::new();
                match security {
                    VMessSecurity::Aes128Gcm => {
                        let mut cipher = Aes128Gcm::new(write_key.as_ref().into());
                        let nonce = Nonce::from_slice(&nonce_bytes);
                        if let Ok(tag) = cipher.encrypt_in_place_detached(nonce, &[], &mut empty) {
                            let _ = inner_write.write_all(&tag).await;
                        }
                    }
                    VMessSecurity::Chacha20Poly1305 => {
                        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaKeyInit, aead::AeadMutInPlace as ChaAead};
                        let mut cipher = ChaCha20Poly1305::new(
                            chacha20poly1305::Key::from_slice(&write_key),
                        );
                        let cha_nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                        if let Ok(tag) = cipher.encrypt_in_place_detached(cha_nonce, &[], &mut empty) {
                            let _ = inner_write.write_all(&tag).await;
                        }
                    }
                    _ => {}
                }
            }
            // Send padding bytes after the tag
            if eof_padding > 0 {
                let padding = vec![0u8; eof_padding];
                let _ = inner_write.write_all(&padding).await;
            }
            let _ = inner_write.flush().await;
            let _ = inner_write.shutdown().await;
        });

        // read_rx: decrypted data from client
        // write_tx: plaintext to encrypt and send to client
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

        // Non-UUID string -> deterministic derivation
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

    #[test]
    fn test_shake_mask_deterministic() {
        let iv = [0x10u8; 16];
        let mut mask1 = ShakeMask::new(&iv);
        let mut mask2 = ShakeMask::new(&iv);
        // Same seed should produce same masks
        assert_eq!(mask1.next_mask(), mask2.next_mask());
        assert_eq!(mask1.next_mask(), mask2.next_mask());
    }

    #[test]
    fn test_shake_mask_encode_decode_roundtrip() {
        let iv = [0x20u8; 16];
        let mut encoder = ShakeMask::new(&iv);
        let mut decoder = ShakeMask::new(&iv);

        let sizes = [42u16, 1024, 16384, 16, 0, 65535];
        for &size in &sizes {
            let encoded = encoder.encode_size(size);
            let decoded = decoder.decode_size(encoded);
            assert_eq!(decoded, size, "Roundtrip failed for size {}", size);
        }
    }

    /* ============ VMess AEAD client-side helpers for testing ============ */

    /// Build EAuID: AES-128-ECB(key=KDF(CmdKey, "AES Auth ID Encryption"), plaintext)
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
    fn build_header_plaintext(
        target_host: &str,
        target_port: u16,
        security: u8,
        opts: u8,
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
        // no padding

        // Append FNV1a checksum
        let fnv = fnv1a32(&hdr);
        hdr.extend_from_slice(&fnv.to_be_bytes());

        (hdr, data_iv, data_key, resp_auth)
    }

    /// Full VMess AEAD client handshake for testing.
    async fn vmess_client_handshake(
        stream: &mut TcpStream,
        uuid: &[u8; 16],
        target_host: &str,
        target_port: u16,
        security: u8,
        opts: u8,
    ) -> (
        [u8; 16], // data_key
        [u8; 16], // data_iv
        u8,       // resp_auth
    ) {
        let ck = cmd_key(uuid);

        // 1. Build & send EAuID
        let eauid = build_eauid(&ck);
        stream.write_all(&eauid).await.unwrap();

        // 2. Build & encrypt header
        let (header_plain, data_iv, data_key, resp_auth) =
            build_header_plaintext(target_host, target_port, security, opts);

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

        stream.write_all(&len_buf).await.unwrap();
        stream.write_all(&len_tag).await.unwrap();
        stream.write_all(&connection_nonce).await.unwrap();

        // Encrypt header payload
        let header_key = kdf16(&ck, &[VMESS_HEADER_KEY, &eauid, &connection_nonce]);
        let header_iv = kdf12(&ck, &[VMESS_HEADER_IV, &eauid, &connection_nonce]);
        let mut hdr_buf = header_plain.clone();
        let mut hdr_cipher = Aes128Gcm::new(header_key.as_ref().into());
        let hdr_tag = hdr_cipher
            .encrypt_in_place_detached(Nonce::from_slice(&header_iv), &eauid, &mut hdr_buf)
            .unwrap();

        stream.write_all(&hdr_buf).await.unwrap();
        stream.write_all(&hdr_tag).await.unwrap();
        stream.flush().await.unwrap();

        // 3. Derive body keys:
        // Request body: use raw header values directly (no transformation)
        // Response body: SHA256(requestBodyKey)[:16], SHA256(requestBodyIV)[:16]
        let resp_body_key_full = Sha256::digest(&data_key);
        let mut resp_body_key = [0u8; 16];
        resp_body_key.copy_from_slice(&resp_body_key_full[..16]);
        let resp_body_iv_full = Sha256::digest(&data_iv);
        let mut resp_body_iv = [0u8; 16];
        resp_body_iv.copy_from_slice(&resp_body_iv_full[..16]);

        let resp_len_key = kdf16(&resp_body_key, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY]);
        let resp_len_iv = kdf12(&resp_body_iv, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV]);
        let resp_payload_key = kdf16(&resp_body_key, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let resp_payload_iv = kdf12(&resp_body_iv, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);

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

        assert_eq!(rcont_data[0], resp_auth, "Response auth byte mismatch");

        // Return the raw header values (server uses them directly)
        (data_key, data_iv, resp_auth)
    }

    /// Encrypt a data chunk with chunk masking support.
    fn encrypt_data_chunk(
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        counter: u16,
        shake_mask: &mut Option<ShakeMask>,
    ) -> Vec<u8> {
        let nonce_bytes = VMessStream::<tokio::net::TcpStream>::make_nonce(counter, iv);

        let mut payload = data.to_vec();
        let mut cipher = Aes128Gcm::new(key.as_ref().into());
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &[], &mut payload)
            .unwrap();

        let chunk_size = (payload.len() + tag.len()) as u16;
        let encoded_size = if let Some(ref mut mask) = shake_mask {
            mask.encode_size(chunk_size)
        } else {
            chunk_size.to_be_bytes()
        };

        let mut out = Vec::new();
        out.extend_from_slice(&encoded_size);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&tag);
        out
    }

    /// Build EOF marker for data stream.
    fn build_eof_marker(
        key: &[u8; 16],
        iv: &[u8; 16],
        counter: u16,
        shake_mask: &mut Option<ShakeMask>,
    ) -> Vec<u8> {
        let nonce_bytes = VMessStream::<tokio::net::TcpStream>::make_nonce(counter, iv);

        // EOF = chunk with size == overhead (16)
        let eof_size = AES_GCM_TAG_SIZE as u16;
        let encoded_size = if let Some(ref mut mask) = shake_mask {
            mask.encode_size(eof_size)
        } else {
            eof_size.to_be_bytes()
        };

        // Encrypt empty payload -> just tag
        let mut empty = Vec::new();
        let mut cipher = Aes128Gcm::new(key.as_ref().into());
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &[], &mut empty)
            .unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(&encoded_size);
        out.extend_from_slice(&tag);
        out
    }

    /// Decrypt a server→client data chunk with chunk masking.
    fn decrypt_server_chunk(
        reader: &mut &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        counter: u16,
        shake_mask: &mut Option<ShakeMask>,
    ) -> Option<Vec<u8>> {
        if reader.len() < 2 {
            return None;
        }
        let encoded_size = [reader[0], reader[1]];
        *reader = &reader[2..];

        let chunk_size = if let Some(ref mut mask) = shake_mask {
            mask.decode_size(encoded_size)
        } else {
            u16::from_be_bytes(encoded_size)
        } as usize;

        if chunk_size == AES_GCM_TAG_SIZE {
            return None; // EOF
        }

        let nonce_bytes = VMessStream::<tokio::net::TcpStream>::make_nonce(counter, iv);

        let payload_len = chunk_size - AES_GCM_TAG_SIZE;
        let mut payload = reader[..payload_len].to_vec();
        let tag = aes_gcm::Tag::from_slice(&reader[payload_len..chunk_size]);
        *reader = &reader[chunk_size..];

        let mut cipher = Aes128Gcm::new(key.as_ref().into());
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &[], &mut payload, tag)
            .expect("Server chunk decrypt failed");
        Some(payload)
    }

    /* ============ End-to-end tests ============ */

    /// Test with chunk masking (opts=0x05, matching v2ray 5.x default)
    #[tokio::test]
    async fn test_vmess_e2e_chunk_masking() {
        let _ = tracing_subscriber::fmt::try_init();

        let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let uuid = parse_or_derive_uuid(uuid_str);
        let server = std::sync::Arc::new(VMessServer::new(vec![uuid]));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = server.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            srv.accept(stream).await.unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let opts = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING; // 0x05
        let (data_key, data_iv, _resp_auth) =
            vmess_client_handshake(&mut client, &uuid, "example.com", 443, 0x03, opts).await;

        let (vmess_stream, target) = server_handle.await.unwrap();
        assert_eq!(target, "example.com:443");

        let (mut server_read, mut server_write) = vmess_stream.into_async_rw();

        // Client→server: encrypt with request body keys + chunk masking
        let mut client_mask = Some(ShakeMask::new(&data_iv));
        let test_data = b"Hello VMess with chunk masking!";
        let chunk = encrypt_data_chunk(test_data, &data_key, &data_iv, 0, &mut client_mask);
        client.write_all(&chunk).await.unwrap();
        let eof = build_eof_marker(&data_key, &data_iv, 1, &mut client_mask);
        client.write_all(&eof).await.unwrap();
        client.flush().await.unwrap();

        // Server reads decrypted data
        let mut buf = vec![0u8; 1024];
        let n = server_read.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], test_data);

        // Server→client: encrypt with response body keys + chunk masking
        let response_data = b"Response with chunk masking!";
        server_write.write_all(response_data).await.unwrap();
        server_write.flush().await.unwrap();
        drop(server_write);

        // Client reads server response
        // Response body keys = SHA256(requestBodyKey)[:16] where requestBodyKey = raw data_key
        let resp_body_key_full = Sha256::digest(&data_key);
        let mut resp_body_key = [0u8; 16];
        resp_body_key.copy_from_slice(&resp_body_key_full[..16]);
        let resp_body_iv_full = Sha256::digest(&data_iv);
        let mut resp_body_iv = [0u8; 16];
        resp_body_iv.copy_from_slice(&resp_body_iv_full[..16]);

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let mut raw_buf = vec![0u8; 4096];
        let n = client.read(&mut raw_buf).await.unwrap();
        let raw = &raw_buf[..n];

        let mut server_mask = Some(ShakeMask::new(&resp_body_iv));
        let mut cursor: &[u8] = raw;
        let decrypted = decrypt_server_chunk(&mut cursor, &resp_body_key, &resp_body_iv, 0, &mut server_mask);
        assert_eq!(decrypted.as_deref(), Some(response_data.as_slice()));

        eprintln!("[PASS] VMess e2e with chunk masking (opts=0x05)");
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

        let mut client = TcpStream::connect(addr).await.unwrap();
        let wrong_ck = cmd_key(&wrong_uuid);
        let eauid = build_eauid(&wrong_ck);
        client.write_all(&eauid).await.unwrap();
        client.write_all(&[0u8; 26]).await.unwrap();
        client.flush().await.unwrap();

        let result = server_handle.await.unwrap();
        match result {
            Ok(_) => panic!("Expected rejection for wrong UUID"),
            Err(e) => {
                assert!(
                    e.to_string().contains("no matching user"),
                    "Expected 'no matching user' error, got: {}",
                    e
                );
            }
        }

        eprintln!("[PASS] VMess wrong UUID correctly rejected");
    }

    /// Test: Multiple users — server matches the correct one.
    #[tokio::test]
    async fn test_vmess_multi_user() {
        let _ = tracing_subscriber::fmt::try_init();

        let uuid1 = parse_or_derive_uuid("11111111-1111-1111-1111-111111111111");
        let uuid2 = parse_or_derive_uuid("22222222-2222-2222-2222-222222222222");
        let uuid3 = parse_or_derive_uuid("33333333-3333-3333-3333-333333333333");
        let server = std::sync::Arc::new(VMessServer::new(vec![uuid1, uuid2, uuid3]));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = server.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            srv.accept(stream).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let opts = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING;
        let (_data_key, _data_iv, _resp_auth) =
            vmess_client_handshake(&mut client, &uuid2, "multi.test.com", 8443, 0x03, opts).await;

        let result = server_handle.await.unwrap();
        assert!(result.is_ok(), "User2 should be accepted");
        let (_stream, target) = result.unwrap();
        assert_eq!(target, "multi.test.com:8443");

        eprintln!("[PASS] VMess multi-user: user2 correctly matched");
    }
}
