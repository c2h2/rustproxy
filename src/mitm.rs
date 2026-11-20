//! TLS interception (`--mitm`) for the HTTP `CONNECT` and SOCKS5 modes.
//!
//! When enabled, a tunnel whose first bytes are a TLS ClientHello is
//! terminated locally with a leaf certificate minted on the fly (signed by a
//! local CA the client must trust), re-encrypted to the real server, and the
//! decrypted byte stream in between is written to a pcap file as synthetic
//! TCP/IP packets — so Wireshark dissects it as plain HTTP/1.1 or HTTP/2.
//!
//! Anything that is not TLS, or whose SNI matches `--mitm-bypass`, is relayed
//! untouched exactly as without `--mitm`.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use once_cell::sync::OnceCell;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{StartHandshake, TlsConnector};
use tracing::{debug, info, warn};

use crate::mitm_record::{addr_string, ConnMeta, H1Session, Recorder};

/// How long to wait for the client's first bytes before assuming a
/// server-speaks-first protocol and relaying the tunnel untouched.
const FIRST_BYTES_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound on each TLS handshake (client leg and upstream leg).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// A ClientHello larger than this is not something we try to parse.
const MAX_CLIENT_HELLO: usize = 64 * 1024;
/// Minted leaf certificates kept in memory before the cache is reset.
const MAX_CACHED_CERTS: usize = 8192;
/// Max payload per synthetic packet (must fit an IPv4 total-length field).
const PCAP_SEGMENT: usize = 32 * 1024;
/// LINKTYPE_RAW: each record starts directly with an IPv4/IPv6 header.
const PCAP_LINKTYPE_RAW: u32 = 101;
const PCAP_MAGIC: u32 = 0xa1b2_c3d4;

type RelayResult = (u64, u64, Option<io::Error>, Option<io::Error>);

/// When a client last completed, and last failed, a TLS handshake against a
/// minted certificate (milliseconds since the Unix epoch).
#[derive(Debug, Clone, Default)]
pub struct ClientStatus {
    pub ok_ms: Option<u64>,
    pub fail_ms: Option<u64>,
    pub fail_reason: String,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Settings parsed from the `--mitm*` flags.
#[derive(Debug, Clone)]
pub struct MitmConfig {
    /// Directory holding `ca.crt` / `ca.key` (created on first run).
    pub ca_dir: PathBuf,
    /// Replace an existing CA with a freshly generated one (`--mitm-regen-ca`).
    /// Without it an existing CA is always reused, never regenerated.
    pub regen_ca: bool,
    /// Decrypted-traffic capture file (`None` disables the capture).
    pub pcap: Option<PathBuf>,
    /// NSS key log file, for decrypting a real packet capture in Wireshark.
    pub keylog: Option<PathBuf>,
    /// Skip verification of the real server's certificate.
    pub insecure: bool,
    /// Host suffixes that are tunnelled without interception.
    pub bypass: Vec<String>,
    /// Keep HTTP flows in memory for the traffic browser.
    pub record: bool,
    /// Memory budget for recorded bodies, in MiB.
    pub store_mb: usize,
    /// Let intercepted connections negotiate HTTP/2 even while recording
    /// (those connections reach the pcap but not the traffic browser).
    pub keep_h2: bool,
}

static GLOBAL: OnceCell<Arc<Mitm>> = OnceCell::new();

/// Enable interception process-wide. Call once, before listeners start.
pub fn init(cfg: MitmConfig) -> Result<(), String> {
    let mitm = Mitm::for_config(cfg)?;
    GLOBAL
        .set(Arc::new(mitm))
        .map_err(|_| "TLS interception already initialised".to_string())
}

/// The process-wide interceptor, if `--mitm` was given.
pub fn global() -> Option<Arc<Mitm>> {
    GLOBAL.get().cloned()
}

pub struct Mitm {
    provider: Arc<CryptoProvider>,
    issuer: Issuer<'static, KeyPair>,
    /// The public CA certificate (PEM), served by the CA download page.
    ca_pem: String,
    /// One key pair shared by every minted leaf (only the names differ).
    leaf_key: KeyPair,
    leaf_signer: Arc<dyn rustls::sign::SigningKey>,
    certs: DashMap<String, Arc<CertifiedKey>>,
    client_cfg: ClientConfig,
    keylog: Option<Arc<dyn rustls::KeyLog>>,
    pcap: Option<mpsc::Sender<Vec<u8>>>,
    bypass: Vec<String>,
    next_id: AtomicU64,
    recorder: Option<Arc<Recorder>>,
    /// Latest handshake outcome per client, for the "check this device"
    /// test on the CA page.
    clients: DashMap<IpAddr, ClientStatus>,
    keep_h2: bool,
    pcap_path: Option<PathBuf>,
}

impl Mitm {
    /// Build an interceptor that is not installed process-wide.
    pub fn for_config(cfg: MitmConfig) -> Result<Self, String> {
        Self::new(cfg, None)
    }

    /// `extra_roots` adds trust anchors for the upstream leg (used by tests).
    fn new(cfg: MitmConfig, extra_roots: Option<Vec<CertificateDer<'static>>>) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let (issuer, ca_pem) = load_or_create_ca(&cfg.ca_dir, cfg.regen_ca)?;

        let leaf_key = KeyPair::generate().map_err(|e| format!("leaf key generation: {e}"))?;
        let leaf_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let leaf_signer = provider
            .key_provider
            .load_private_key(leaf_der)
            .map_err(|e| format!("leaf key load: {e}"))?;

        let keylog: Option<Arc<dyn rustls::KeyLog>> = match &cfg.keylog {
            Some(path) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| format!("cannot open key log {}: {e}", path.display()))?;
                Some(Arc::new(FileKeyLog(Mutex::new(file))))
            }
            None => None,
        };

        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS client config: {e}"))?;
        let mut client_cfg = if cfg.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(provider.clone())))
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for der in extra_roots.unwrap_or_default() {
                roots.add(der).map_err(|e| format!("extra root: {e}"))?;
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        if let Some(ref kl) = keylog {
            client_cfg.key_log = kl.clone();
        }

        let pcap = match &cfg.pcap {
            Some(path) => Some(spawn_pcap_writer(path)?),
            None => None,
        };

        let bypass = cfg
            .bypass
            .iter()
            .map(|s| s.trim().trim_start_matches("*.").trim_start_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Self {
            provider,
            issuer,
            ca_pem,
            leaf_key,
            leaf_signer,
            certs: DashMap::new(),
            client_cfg,
            keylog,
            pcap,
            bypass,
            next_id: AtomicU64::new(1),
            clients: DashMap::new(),
            recorder: cfg.record.then(|| Arc::new(Recorder::new(cfg.store_mb.max(1) * 1024 * 1024))),
            keep_h2: cfg.keep_h2,
            pcap_path: cfg.pcap.clone(),
        })
    }

    /// The CA certificate clients must trust, PEM encoded. Public material:
    /// the private key never leaves `ca.key`.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// The CA certificate in DER form (the `.cer` Windows prefers).
    pub fn ca_der(&self) -> Vec<u8> {
        use rustls::pki_types::pem::PemObject;
        CertificateDer::from_pem_slice(self.ca_pem.as_bytes())
            .map(|der| der.to_vec())
            .unwrap_or_default()
    }

    /// SHA-256 fingerprint of the CA certificate, `AA:BB:…`, as shown by
    /// Keychain Access / certmgr / iOS so the download can be verified.
    pub fn ca_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.ca_der())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Whether `ip` has recently accepted or rejected our certificates.
    pub fn client_status(&self, ip: IpAddr) -> ClientStatus {
        self.clients.get(&ip.to_canonical()).map(|s| s.clone()).unwrap_or_default()
    }

    fn note_client(&self, ip: IpAddr, failure: Option<&str>) {
        if self.clients.len() > 4096 {
            self.clients.clear();
        }
        let mut entry = self.clients.entry(ip.to_canonical()).or_default();
        match failure {
            None => entry.ok_ms = Some(now_ms()),
            Some(reason) => {
                entry.fail_ms = Some(now_ms());
                entry.fail_reason = reason.to_string();
            }
        }
    }

    /// The flow store behind the traffic browser, when recording is enabled.
    pub fn recorder(&self) -> Option<Arc<Recorder>> {
        self.recorder.clone()
    }

    /// The decrypted-capture file, if one is being written.
    pub fn pcap_path(&self) -> Option<&Path> {
        self.pcap_path.as_deref()
    }

    fn is_bypassed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.bypass.iter().any(|suffix| {
            host == *suffix
                || (host.len() > suffix.len()
                    && host.ends_with(suffix.as_str())
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
        })
    }

    /// Leaf certificate for `host`, minted and cached on first use.
    fn cert_for(&self, host: &str) -> Result<Arc<CertifiedKey>, String> {
        let key = host.to_ascii_lowercase();
        if let Some(ck) = self.certs.get(&key) {
            return Ok(ck.clone());
        }

        let mut params = CertificateParams::new(vec![key.clone()])
            .map_err(|e| format!("invalid certificate name {host:?}: {e}"))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, key.as_str());
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(365);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        // Every leaf shares one key, so the serial must be random: a repeated
        // issuer+serial pair is a hard error in some clients (e.g. Firefox).
        let mut serial: [u8; 16] = rand::random();
        serial[0] &= 0x7f;
        params.serial_number = Some(SerialNumber::from_slice(&serial));

        let cert = params
            .signed_by(&self.leaf_key, &self.issuer)
            .map_err(|e| format!("signing certificate for {host}: {e}"))?;
        let ck = Arc::new(CertifiedKey::new(
            vec![cert.der().clone()],
            self.leaf_signer.clone(),
        ));

        if self.certs.len() >= MAX_CACHED_CERTS {
            self.certs.clear();
        }
        self.certs.insert(key, ck.clone());
        Ok(ck)
    }

    /// Relay one tunnel, intercepting it when the client starts a TLS
    /// handshake. `authority` is the `host:port` the client asked for and
    /// `upstream` an already-connected socket to it.
    ///
    /// Returns the same tuple as `run_pumps`; for an intercepted tunnel the
    /// byte counts are plaintext bytes.
    pub async fn relay<C>(
        self: &Arc<Self>,
        mut client: C,
        client_addr: SocketAddr,
        authority: &str,
        upstream: TcpStream,
        buf_size: usize,
    ) -> RelayResult
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (req_host, req_port) = split_authority(authority);
        let client_ip = Some(client_addr.ip());

        if self.is_bypassed(&req_host) {
            debug!("mitm: bypass {} (host rule)", authority);
            return crate::tcp_proxy::run_pumps(client, upstream, buf_size, client_ip).await;
        }

        // Buffer the client's opening bytes until they form a complete
        // ClientHello (or prove not to be TLS). Nothing is consumed for good:
        // on any fallback the buffer is replayed to the real server.
        let mut hello = Vec::with_capacity(2048);
        let mut acceptor = Acceptor::default();
        let accepted = loop {
            let mut chunk = [0u8; 4096];
            let wait = if hello.is_empty() { FIRST_BYTES_TIMEOUT } else { HANDSHAKE_TIMEOUT };
            let n = match timeout(wait, client.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break None,
                Ok(Ok(n)) => n,
            };
            hello.extend_from_slice(&chunk[..n]);
            if hello[0] != 0x16 || hello.len() > MAX_CLIENT_HELLO {
                break None;
            }
            let mut fresh = &chunk[..n];
            if acceptor.read_tls(&mut fresh).is_err() {
                break None;
            }
            match acceptor.accept() {
                Ok(Some(accepted)) => break Some(accepted),
                Ok(None) => continue,
                Err(_) => break None,
            }
        };

        let Some(accepted) = accepted else {
            debug!("mitm: {} is not TLS, relaying untouched", authority);
            // Plain HTTP inside a tunnel is still worth listing in the
            // traffic browser; the bytes themselves are relayed as-is.
            let session = match (&self.recorder, looks_like_http(&hello)) {
                (Some(rec), true) => Some(H1Session::new(
                    rec.clone(),
                    ConnMeta {
                        client: addr_string(client_addr),
                        server: upstream.peer_addr().map(addr_string).unwrap_or_default(),
                        scheme: "http",
                        default_host: authority.to_string(),
                    },
                )),
                _ => None,
            };
            let client = Tap { inner: Prefixed::new(hello, client), capture: None, session };
            return crate::tcp_proxy::run_pumps(client, upstream, buf_size, client_ip).await;
        };

        let (sni, alpn) = {
            let ch = accepted.client_hello();
            let sni = ch.server_name().map(|s| s.to_string());
            let alpn: Vec<Vec<u8>> = ch
                .alpn()
                .map(|it| it.map(|p| p.to_vec()).collect())
                .unwrap_or_default();
            (sni, alpn)
        };
        let host = sni.unwrap_or(req_host);

        if self.is_bypassed(&host) {
            debug!("mitm: bypass {} (SNI rule)", host);
            let client = Prefixed::new(hello, client);
            return crate::tcp_proxy::run_pumps(client, upstream, buf_size, client_ip).await;
        }

        let fail = |stage: &str, e: String| -> RelayResult {
            warn!("mitm: {} ({}:{}) {}: {}", client_addr, host, req_port, stage, e);
            (0, 0, Some(io::Error::new(io::ErrorKind::Other, e)), None)
        };

        // Upstream first: its ALPN choice decides what we offer the client,
        // so both legs speak the same protocol and bytes can be relayed 1:1.
        let server_addr = upstream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], req_port)));
        let server_name = match ServerName::try_from(host.clone()) {
            Ok(n) => n,
            Err(e) => return fail("invalid server name", e.to_string()),
        };
        let mut client_cfg = self.client_cfg.clone();
        // The traffic browser parses HTTP/1.x, so steer both legs to it by
        // not offering h2 upstream (unless the client offers nothing else).
        let alpn = if self.recorder.is_some() && !self.keep_h2 {
            let h1: Vec<Vec<u8>> = alpn.iter().filter(|p| p.as_slice() != b"h2").cloned().collect();
            if h1.is_empty() { alpn } else { h1 }
        } else {
            alpn
        };
        client_cfg.alpn_protocols = alpn;
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let upstream_tls = match timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name, upstream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return fail(
                    "upstream TLS handshake failed (use --mitm-insecure for untrusted server certs)",
                    e.to_string(),
                )
            }
            Err(_) => return fail("upstream TLS handshake", "timed out".into()),
        };
        let negotiated = upstream_tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());

        let cert = match self.cert_for(&host) {
            Ok(c) => c,
            Err(e) => return fail("certificate", e),
        };
        let mut server_cfg = match ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
        {
            Ok(b) => b.with_no_client_auth().with_cert_resolver(Arc::new(FixedCert(cert))),
            Err(e) => return fail("TLS server config", e.to_string()),
        };
        server_cfg.alpn_protocols = negotiated.iter().cloned().collect();
        if let Some(ref kl) = self.keylog {
            server_cfg.key_log = kl.clone();
        }

        let start = StartHandshake::from_parts(accepted, client);
        let client_tls = match timeout(HANDSHAKE_TIMEOUT, start.into_stream(Arc::new(server_cfg))).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.note_client(client_addr.ip(), Some(&e.to_string()));
                return fail(
                    "client TLS handshake failed (is the rustproxy CA trusted? pinned hosts need --mitm-bypass)",
                    e.to_string(),
                )
            }
            Err(_) => return fail("client TLS handshake", "timed out".into()),
        };
        self.note_client(client_addr.ip(), None);

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let proto = negotiated
            .as_deref()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .unwrap_or_else(|| "-".to_string());
        info!("mitm #{}: {} -> {}:{} ({}) alpn={}", id, client_addr, host, req_port, server_addr, proto);

        let capture = self
            .pcap
            .as_ref()
            .map(|tx| Capture::open(tx.clone(), client_addr, server_addr));
        let session = match (&self.recorder, negotiated.as_deref()) {
            (Some(_), Some(b"h2")) => None,
            (Some(rec), _) => Some(H1Session::new(
                rec.clone(),
                ConnMeta {
                    client: addr_string(client_addr),
                    server: addr_string(server_addr),
                    scheme: "https",
                    default_host: if req_port == 443 { host.clone() } else { format!("{host}:{req_port}") },
                },
            )),
            (None, _) => None,
        };
        let tapped = Tap { inner: client_tls, capture, session };
        let res = crate::tcp_proxy::run_pumps_io(tapped, upstream_tls, buf_size, client_ip).await;
        debug!("mitm #{}: closed, {} bytes up / {} bytes down (plaintext)", id, res.0, res.1);
        res
    }
}

/// Whether a tunnel's first bytes are the start of an HTTP/1.x request.
fn looks_like_http(first: &[u8]) -> bool {
    const METHODS: [&[u8]; 8] =
        [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE "];
    METHODS.iter().any(|m| first.starts_with(m))
}

/// `host:port` → (`host`, port). Brackets around IPv6 literals are dropped.
fn split_authority(authority: &str) -> (String, u16) {
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(443)),
        None => (authority, 443),
    };
    (host.trim_start_matches('[').trim_end_matches(']').to_string(), port)
}

/* ------------------------------- CA ------------------------------- */

/// Load the CA from `dir`, generating one only when none exists there —
/// or when `force` is set, in which case the old pair is kept as `*.old`.
/// Returns the signing issuer and the certificate PEM.
fn load_or_create_ca(dir: &Path, force: bool) -> Result<(Issuer<'static, KeyPair>, String), String> {
    let cert_path = dir.join("ca.crt");
    let key_path = dir.join("ca.key");

    let load = || -> Result<(Issuer<'static, KeyPair>, String), String> {
        let cert_pem = fs::read_to_string(&cert_path)
            .map_err(|e| format!("reading {}: {e}", cert_path.display()))?;
        let key_pem = fs::read_to_string(&key_path)
            .map_err(|e| format!("reading {}: {e}", key_path.display()))?;
        let key = KeyPair::from_pem(&key_pem)
            .map_err(|e| format!("parsing {}: {e}", key_path.display()))?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)
            .map_err(|e| format!("parsing {}: {e}", cert_path.display()))?;
        Ok((issuer, cert_pem))
    };

    if force {
        // Keep the previous pair: clients may still trust it, and deleting a
        // CA key cannot be undone.
        for path in [&cert_path, &key_path] {
            if path.exists() {
                let mut old = path.clone().into_os_string();
                old.push(".old");
                fs::rename(path, &old).map_err(|e| format!("moving {} aside: {e}", path.display()))?;
                warn!("mitm: --mitm-regen-ca: previous {} kept as {}", path.display(), PathBuf::from(old).display());
            }
        }
    } else {
        if cert_path.exists() && key_path.exists() {
            let ca = load()?;
            info!("mitm: using existing CA certificate {} (not regenerated)", cert_path.display());
            return Ok(ca);
        }
        // Half a pair is never silently replaced: regenerating would orphan
        // whatever clients already trust.
        if cert_path.exists() != key_path.exists() {
            return Err(format!(
                "{} has only one of ca.crt / ca.key; restore the missing file, or pass --mitm-regen-ca to generate a new CA",
                dir.display()
            ));
        }
    }

    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;

    let key = KeyPair::generate().map_err(|e| format!("CA key generation: {e}"))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "rustproxy MITM CA");
    params.distinguished_name.push(DnType::OrganizationName, "rustproxy");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(3650);
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("CA certificate generation: {e}"))?;

    // The key file is created exclusively: if another rustproxy sharing this
    // directory won the race, adopt its CA instead of overwriting it (two
    // different CAs under one ca.crt would break whichever lost).
    match write_private(&key_path, key.serialize_pem().as_bytes()) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let mut last = String::new();
            for _ in 0..40 {
                match load() {
                    Ok(ca) => {
                        info!("mitm: using existing CA certificate {} (not regenerated)", cert_path.display());
                        return Ok(ca);
                    }
                    Err(e) => last = e,
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            return Err(last);
        }
        Err(e) => return Err(format!("writing {}: {e}", key_path.display())),
    }
    let cert_pem = cert.pem();
    fs::write(&cert_path, &cert_pem).map_err(|e| format!("writing {}: {e}", cert_path.display()))?;
    info!(
        "mitm: generated new CA — install {} as a trusted root on the client",
        cert_path.display()
    );
    Ok((Issuer::new(params, key), cert_pem))
}

/// Create a file readable only by the owner (the CA private key). Fails
/// with `AlreadyExists` rather than overwriting.
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

/* --------------------------- rustls glue --------------------------- */

struct FixedCert(Arc<CertifiedKey>);

impl fmt::Debug for FixedCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixedCert")
    }
}

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// `--mitm-insecure`: accept any upstream certificate (signatures are still
/// checked so the handshake itself stays well-formed).
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// NSS key log format (`SSLKEYLOGFILE`), covering both TLS legs.
struct FileKeyLog(Mutex<File>);

impl fmt::Debug for FileKeyLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileKeyLog")
    }
}

impl rustls::KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        let line = format!("{} {} {}\n", label, hex(client_random), hex(secret));
        if let Ok(mut f) = self.0.lock() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/* ----------------------------- IO shims ----------------------------- */

/// Replays already-read bytes before continuing with the inner stream.
struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let pos = self.pos;
            buf.put_slice(&self.prefix[pos..pos + n]);
            self.pos += n;
            if self.pos == self.prefix.len() {
                self.prefix = Vec::new();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Wraps the plaintext client leg and mirrors every byte into the pcap
/// capture and the flow recorder: reads are client→server, writes are
/// server→client.
struct Tap<S> {
    inner: S,
    capture: Option<Capture>,
    session: Option<H1Session>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let this = &mut *self;
            let fresh = &buf.filled()[before..];
            if let Some(cap) = this.capture.as_mut() {
                cap.data(true, fresh);
            }
            if let Some(session) = this.session.as_mut() {
                session.client_data(fresh);
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &res {
            let this = &mut *self;
            if let Some(cap) = this.capture.as_mut() {
                cap.data(false, &data[..*n]);
            }
            if let Some(session) = this.session.as_mut() {
                session.server_data(&data[..*n]);
            }
        }
        res
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/* ------------------------------- pcap ------------------------------- */

fn pcap_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
    h[4..6].copy_from_slice(&2u16.to_le_bytes());
    h[6..8].copy_from_slice(&4u16.to_le_bytes());
    // thiszone, sigfigs = 0
    h[16..20].copy_from_slice(&262_144u32.to_le_bytes());
    h[20..24].copy_from_slice(&PCAP_LINKTYPE_RAW.to_le_bytes());
    h
}

/// Open (or append to) the capture file and start the writer thread.
/// File I/O stays off the async runtime; records arrive over a channel.
fn spawn_pcap_writer(path: &Path) -> Result<mpsc::Sender<Vec<u8>>, String> {
    let err = |e: io::Error| format!("pcap file {}: {e}", path.display());
    let header = pcap_header();

    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
        .map_err(err)?;
    let len = file.metadata().map_err(err)?.len();
    if len == 0 {
        file.write_all(&header).map_err(err)?;
    } else {
        // Appending is only valid onto a capture of the same format.
        let mut existing = [0u8; 24];
        let same = file.read_exact(&mut existing).is_ok()
            && existing[0..4] == header[0..4]
            && existing[20..24] == header[20..24];
        if !same {
            return Err(format!(
                "pcap file {} exists and is not a rustproxy capture; refusing to append",
                path.display()
            ));
        }
    }

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::Builder::new()
        .name("mitm-pcap".into())
        .spawn(move || {
            let mut out = BufWriter::with_capacity(64 * 1024, file);
            loop {
                match rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(rec) => {
                        if out.write_all(&rec).is_err() {
                            break;
                        }
                    }
                    // Idle: flush so the file can be opened / tailed live.
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let _ = out.flush();
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            let _ = out.flush();
        })
        .map_err(|e| format!("pcap writer thread: {e}"))?;
    Ok(tx)
}

/// One intercepted connection rendered as a synthetic TCP conversation:
/// three-way handshake on open, data segments with consistent seq/ack
/// numbers, FINs on drop.
struct Capture {
    tx: mpsc::Sender<Vec<u8>>,
    client: SocketAddr,
    server: SocketAddr,
    client_seq: u32,
    server_seq: u32,
    ip_id: u16,
}

impl Capture {
    fn open(tx: mpsc::Sender<Vec<u8>>, client: SocketAddr, server: SocketAddr) -> Self {
        let (client, server) = capture_endpoints(client, server);
        let mut cap = Self { tx, client, server, client_seq: 0, server_seq: 0, ip_id: 0 };
        cap.segment(true, TCP_SYN, &[]);
        cap.segment(false, TCP_SYN | TCP_ACK, &[]);
        cap.segment(true, TCP_ACK, &[]);
        cap
    }

    fn data(&mut self, from_client: bool, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let (head, rest) = bytes.split_at(bytes.len().min(PCAP_SEGMENT));
            self.segment(from_client, TCP_PSH | TCP_ACK, head);
            bytes = rest;
        }
    }

    fn segment(&mut self, from_client: bool, flags: u8, payload: &[u8]) {
        let (src, dst, seq, ack) = if from_client {
            (self.client, self.server, self.client_seq, self.server_seq)
        } else {
            (self.server, self.client, self.server_seq, self.client_seq)
        };
        self.ip_id = self.ip_id.wrapping_add(1);
        let packet = build_packet(src, dst, seq, ack, flags, self.ip_id, payload);

        // SYN and FIN each occupy one sequence number.
        let mut advance = payload.len() as u32;
        if flags & (TCP_SYN | TCP_FIN) != 0 {
            advance = advance.wrapping_add(1);
        }
        if from_client {
            self.client_seq = self.client_seq.wrapping_add(advance);
        } else {
            self.server_seq = self.server_seq.wrapping_add(advance);
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let mut rec = Vec::with_capacity(16 + packet.len());
        rec.extend_from_slice(&(now.as_secs() as u32).to_le_bytes());
        rec.extend_from_slice(&now.subsec_micros().to_le_bytes());
        rec.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        rec.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        rec.extend_from_slice(&packet);
        let _ = self.tx.send(rec);
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.segment(true, TCP_FIN | TCP_ACK, &[]);
        self.segment(false, TCP_FIN | TCP_ACK, &[]);
        self.segment(true, TCP_ACK, &[]);
    }
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

/// Addresses as they appear in the capture. Both ends are put in the same
/// address family, and server port 443 is recorded as 80: Wireshark binds
/// 443 to its TLS dissector, which would show the already-decrypted stream
/// as opaque "continuation data" instead of HTTP.
fn capture_endpoints(client: SocketAddr, server: SocketAddr) -> (SocketAddr, SocketAddr) {
    let mut client = SocketAddr::new(client.ip().to_canonical(), client.port());
    let server_port = if server.port() == 443 { 80 } else { server.port() };
    let mut server = SocketAddr::new(server.ip().to_canonical(), server_port);
    if client.is_ipv4() != server.is_ipv4() {
        let v6 = |ip: IpAddr| match ip {
            IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
            v6 => v6,
        };
        client.set_ip(v6(client.ip()));
        server.set_ip(v6(server.ip()));
    }
    (client, server)
}

/// A raw IPv4/IPv6 + TCP packet. `src` and `dst` must share a family.
fn build_packet(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, flags: u8, ip_id: u16, payload: &[u8]) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut p = Vec::with_capacity(40 + tcp_len);

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            p.extend_from_slice(&[0x45, 0x00]);
            p.extend_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
            p.extend_from_slice(&ip_id.to_be_bytes());
            p.extend_from_slice(&[0x40, 0x00, 64, 6, 0, 0]); // DF, TTL 64, TCP, checksum
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            let sum = ipv4_checksum(&p[..20]);
            p[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        (s, d) => {
            let to_v6 = |ip: IpAddr| match ip {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            p.extend_from_slice(&[0x60, 0, 0, 0]);
            p.extend_from_slice(&(tcp_len as u16).to_be_bytes());
            p.extend_from_slice(&[6, 64]); // next header TCP, hop limit
            p.extend_from_slice(&to_v6(s).octets());
            p.extend_from_slice(&to_v6(d).octets());
        }
    }

    p.extend_from_slice(&src.port().to_be_bytes());
    p.extend_from_slice(&dst.port().to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    // A bare SYN carries no acknowledgement.
    let ack = if flags & TCP_ACK != 0 { ack } else { 0 };
    p.extend_from_slice(&ack.to_be_bytes());
    p.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]); // 20-byte header, window, checksum, urgent
    p.extend_from_slice(payload);
    p
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/* ------------------------------ Tests ------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustproxy-mitm-{}-{}-{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config(dir: &Path) -> MitmConfig {
        MitmConfig {
            ca_dir: dir.join("ca"),
            regen_ca: false,
            pcap: Some(dir.join("out.pcap")),
            keylog: Some(dir.join("keys.log")),
            insecure: false,
            bypass: Vec::new(),
            record: true,
            store_mb: 16,
            keep_h2: false,
        }
    }

    /// A TLS origin with its own throwaway CA. Returns (addr, CA cert DER).
    /// Replies to anything with a fixed HTTP response.
    async fn tls_origin(alpn: Vec<Vec<u8>>) -> (SocketAddr, CertificateDer<'static>) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["origin.test".to_string()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        cfg.alpn_protocols = alpn;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { break };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else { return };
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nsecret-answer")
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (addr, ca_cert.der().clone())
    }

    /// Accept one tunnel on a local listener and hand it to `Mitm::relay`,
    /// the way the HTTP/SOCKS5 front ends do. Returns the listener address.
    async fn front(mitm: Arc<Mitm>, origin: SocketAddr, authority: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (client, client_addr) = listener.accept().await.unwrap();
            let upstream = TcpStream::connect(origin).await.unwrap();
            mitm.relay(client, client_addr, &authority, upstream, 0).await;
        });
        addr
    }

    /// A TLS client that trusts only the proxy's CA.
    fn client_trusting(ca_pem_path: &Path, alpn: Vec<Vec<u8>>) -> TlsConnector {
        let pem = fs::read_to_string(ca_pem_path).unwrap();
        let der = pem::parse(pem).unwrap().into_contents();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(der)).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = alpn;
        TlsConnector::from(Arc::new(cfg))
    }

    async fn wait_for_file(path: &Path, needle: &[u8]) -> Vec<u8> {
        for _ in 0..50 {
            let data = fs::read(path).unwrap_or_default();
            if data.windows(needle.len()).any(|w| w == needle) {
                return data;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{} never contained {:?}", path.display(), String::from_utf8_lossy(needle));
    }

    #[tokio::test]
    async fn intercepts_tls_and_captures_plaintext() {
        let dir = temp_dir("intercept");
        let (origin, origin_ca) = tls_origin(vec![b"http/1.1".to_vec()]).await;
        let mitm = Arc::new(Mitm::new(config(&dir), Some(vec![origin_ca])).unwrap());
        let mitm_for_flows = mitm.clone();
        let proxy = front(mitm, origin, format!("origin.test:{}", origin.port())).await;

        // The client only trusts the proxy CA, so a successful handshake
        // proves it was served a minted leaf for the requested name.
        let connector = client_trusting(&dir.join("ca/ca.crt"), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let tcp = TcpStream::connect(proxy).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("origin.test").unwrap(), tcp)
            .await
            .expect("client handshake against minted certificate");
        // ALPN mirrors what the origin picked, not the client's first choice.
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));

        tls.write_all(b"GET /private HTTP/1.1\r\nHost: origin.test\r\n\r\n").await.unwrap();
        let mut body = Vec::new();
        tls.read_to_end(&mut body).await.unwrap();
        assert!(body.ends_with(b"secret-answer"));
        drop(tls);

        let pcap = wait_for_file(&dir.join("out.pcap"), b"secret-answer").await;
        assert_eq!(&pcap[0..4], &PCAP_MAGIC.to_le_bytes());
        assert_eq!(&pcap[20..24], &PCAP_LINKTYPE_RAW.to_le_bytes());
        assert!(pcap.windows(21).any(|w| w == b"GET /private HTTP/1.1"));

        // The exchange is listed for the traffic browser. The client asked
        // for h2 first, but recording steers the tunnel to HTTP/1.1.
        let flows = mitm_for_flows.recorder().unwrap().snapshot("");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].url(), format!("https://origin.test/private"));
        assert_eq!((flows[0].status, flows[0].resp_body.as_slice()), (Some(200), &b"secret-answer"[..]));
        assert_eq!(flows[0].state, "done");

        // Both legs log their secrets.
        let keys = fs::read_to_string(dir.join("keys.log")).unwrap();
        assert!(keys.contains("CLIENT_TRAFFIC_SECRET_0") || keys.contains("CLIENT_RANDOM"));

        // The CA key must not be world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("ca/ca.key")).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ca_is_reused_across_restarts() {
        let dir = temp_dir("reuse");
        let first = Mitm::new(config(&dir), None).unwrap();
        let ca_before = fs::read(dir.join("ca/ca.crt")).unwrap();
        drop(first);
        let second = Mitm::new(config(&dir), None).unwrap();
        assert_eq!(ca_before, fs::read(dir.join("ca/ca.crt")).unwrap());

        // A leaf minted after reload still chains to the CA file on disk.
        let leaf = second.cert_for("example.test").unwrap();
        let der = pem::parse(&ca_before).unwrap().into_contents();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(der)).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        verifier
            .verify_server_cert(
                &leaf.cert[0],
                &[],
                &ServerName::try_from("example.test").unwrap(),
                &[],
                UnixTime::now(),
            )
            .expect("leaf verifies against reloaded CA");

        // Half a pair is an error, never a silent regeneration.
        drop(second);
        fs::rename(dir.join("ca/ca.key"), dir.join("ca/ca.key.hidden")).unwrap();
        let err = Mitm::new(config(&dir), None).err().expect("missing key must not regenerate");
        assert!(err.contains("--mitm-regen-ca"), "{err}");
        assert_eq!(ca_before, fs::read(dir.join("ca/ca.crt")).unwrap());
        fs::rename(dir.join("ca/ca.key.hidden"), dir.join("ca/ca.key")).unwrap();

        // Only an explicit force replaces it, and the old pair is kept.
        let mut forced = config(&dir);
        forced.regen_ca = true;
        let third = Mitm::new(forced, None).unwrap();
        let ca_after = fs::read(dir.join("ca/ca.crt")).unwrap();
        assert_ne!(ca_before, ca_after);
        assert_eq!(ca_before, fs::read(dir.join("ca/ca.crt.old")).unwrap());
        assert!(dir.join("ca/ca.key.old").exists());
        assert_eq!(third.ca_pem().as_bytes(), &ca_after[..]);
        assert_eq!(third.ca_fingerprint().len(), 32 * 3 - 1);
        assert_eq!(pem::parse(&ca_after).unwrap().into_contents(), third.ca_der());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn untrusted_upstream_is_refused_unless_insecure() {
        let dir = temp_dir("untrusted");
        let (origin, _unknown_ca) = tls_origin(vec![]).await;

        // Strict (default): the origin's CA is unknown, so the client leg is
        // dropped rather than vouching for an unverified server.
        let mitm = Arc::new(Mitm::new(config(&dir), None).unwrap());
        let proxy = front(mitm, origin, format!("origin.test:{}", origin.port())).await;
        let connector = client_trusting(&dir.join("ca/ca.crt"), vec![]);
        let tcp = TcpStream::connect(proxy).await.unwrap();
        assert!(connector
            .connect(ServerName::try_from("origin.test").unwrap(), tcp)
            .await
            .is_err());

        let mut cfg = config(&dir);
        cfg.insecure = true;
        let mitm = Arc::new(Mitm::new(cfg, None).unwrap());
        let proxy = front(mitm, origin, format!("origin.test:{}", origin.port())).await;
        let tcp = TcpStream::connect(proxy).await.unwrap();
        connector
            .connect(ServerName::try_from("origin.test").unwrap(), tcp)
            .await
            .expect("insecure mode intercepts anyway");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn non_tls_and_bypassed_tunnels_pass_through_untouched() {
        let dir = temp_dir("passthrough");

        // Plain echo origin: bytes must arrive unmodified, prefix included.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
        });
        let mitm = Arc::new(Mitm::new(config(&dir), None).unwrap());
        let proxy = front(mitm, echo_addr, echo_addr.to_string()).await;
        let mut plain = TcpStream::connect(proxy).await.unwrap();
        plain.write_all(b"SSH-2.0-not-tls\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        let n = plain.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"SSH-2.0-not-tls\r\n");

        // Bypassed by SNI suffix: the client sees the origin's own
        // certificate (signed by the origin CA, not the proxy CA).
        let (origin, origin_ca) = tls_origin(vec![]).await;
        let mut cfg = config(&dir);
        cfg.bypass = vec!["*.Test".to_string()];
        let mitm = Arc::new(Mitm::new(cfg, None).unwrap());
        assert!(mitm.is_bypassed("origin.test"));
        assert!(!mitm.is_bypassed("origin.nottest"));
        // Authority is an IP (as with SOCKS5 clients that resolve locally),
        // so only the SNI can trigger the rule.
        let proxy = front(mitm, origin, origin.to_string()).await;
        let mut roots = RootCertStore::empty();
        roots.add(origin_ca).unwrap();
        let client_cfg = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tcp = TcpStream::connect(proxy).await.unwrap();
        let mut tls = TlsConnector::from(Arc::new(client_cfg))
            .connect(ServerName::try_from("origin.test").unwrap(), tcp)
            .await
            .expect("bypassed tunnel presents the origin's real certificate");
        tls.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut body = Vec::new();
        tls.read_to_end(&mut body).await.unwrap();
        assert!(body.ends_with(b"secret-answer"));

        // Nothing from either tunnel may reach the capture.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let pcap = fs::read(dir.join("out.pcap")).unwrap();
        assert_eq!(pcap.len(), 24, "only the pcap header is expected");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn synthetic_packets_are_well_formed() {
        let (tx, rx) = mpsc::channel();
        let client: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let server: SocketAddr = "93.184.216.34:443".parse().unwrap();
        {
            let mut cap = Capture::open(tx, client, server);
            cap.data(true, b"hello");
            cap.data(false, &vec![7u8; PCAP_SEGMENT + 10]);
        }
        let recs: Vec<Vec<u8>> = rx.try_iter().collect();
        // SYN, SYN-ACK, ACK, 1 client segment, 2 server segments, FIN, FIN, ACK
        assert_eq!(recs.len(), 9);

        let ip = |r: &Vec<u8>| r[16..].to_vec();
        for r in &recs {
            let pkt = ip(r);
            assert_eq!(u32::from_le_bytes(r[8..12].try_into().unwrap()) as usize, pkt.len());
            assert_eq!(pkt[0], 0x45);
            assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, pkt.len());
            assert_eq!(ipv4_checksum(&pkt[..20]), 0, "IPv4 header checksum must verify");
        }

        // 443 is recorded as 80 so Wireshark picks the HTTP dissector.
        let syn = ip(&recs[0]);
        assert_eq!(u16::from_be_bytes([syn[22], syn[23]]), 80);
        assert_eq!(syn[33], TCP_SYN);

        // Client data: seq 1 (after SYN), 5 bytes.
        let data = ip(&recs[3]);
        assert_eq!(u32::from_be_bytes(data[24..28].try_into().unwrap()), 1);
        assert_eq!(&data[40..], b"hello");

        // Second server segment continues where the first ended and acks
        // the client's 5 bytes.
        let seg2 = ip(&recs[5]);
        assert_eq!(u32::from_be_bytes(seg2[24..28].try_into().unwrap()), 1 + PCAP_SEGMENT as u32);
        assert_eq!(u32::from_be_bytes(seg2[28..32].try_into().unwrap()), 6);
        assert_eq!(seg2.len(), 40 + 10);

        // Mixed families are normalised to IPv6.
        let (c, s) = capture_endpoints("[2001:db8::1]:1234".parse().unwrap(), "1.2.3.4:8443".parse().unwrap());
        assert!(c.is_ipv6() && s.is_ipv6());
        assert_eq!(s.port(), 8443);
        let pkt = build_packet(c, s, 0, 0, TCP_SYN, 1, &[]);
        assert_eq!(pkt[0], 0x60);
        assert_eq!(pkt.len(), 60);
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(split_authority("example.com:8443"), ("example.com".to_string(), 8443));
        assert_eq!(split_authority("[::1]:443"), ("::1".to_string(), 443));
    }
}
