//! NyaTerm Plus: Hysteria2 / Trojan proxies through a local `sing-box` process.
//!
//! sing-box is spawned on demand with a SOCKS5 inbound bound to `127.0.0.1` and a single
//! outbound pointing at the configured node. SSH (and every route that honours a proxy) then
//! goes through that SOCKS5 port. Processes are shared between connections that use an
//! identical node configuration and are reference counted: every [`SingBoxStream`] holds a
//! lease, and the process is killed when the last lease drops. On Windows the processes also
//! sit in a kill-on-close job object, so they never outlive the app, even after a crash.
//!
//! sing-box is a separate GPLv3 executable that only talks to the app over a socket; it is
//! not linked in. The Windows installer ships it next to `NyaTerm.exe`.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, LazyLock, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow, bail};
use nyaterm_core::ProxyNodeOptions;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::Child;

use crate::SshProxyConfig;

const LISTEN_ADDR: &str = "127.0.0.1";
const HOP_INTERVAL: &str = "30s";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const LOG_SETTLE: Duration = Duration::from_millis(500);
const MAX_LOG_LINES: usize = 40;
const MAX_LOG_CHARS: usize = 1500;
/// Lets users point at a sing-box binary outside the default search locations.
const BINARY_ENV: &str = "NYATERM_SING_BOX";

pub fn is_singbox_protocol(protocol: &str) -> bool {
    nyaterm_core::proxy_link::is_node_protocol(protocol)
}

pub fn protocol_label(protocol: &str) -> &'static str {
    match protocol {
        "hysteria2" => "Hysteria2",
        "trojan" => "Trojan",
        _ => "sing-box",
    }
}

/// Connects to `target_host:target_port` through a sing-box process for `proxy`.
///
/// The target host is passed to the proxy unresolved so DNS happens on the node side.
pub async fn connect(
    proxy: &SshProxyConfig,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<SingBoxStream> {
    let lease = acquire(proxy).await?;
    let proxy_addr = format!("{LISTEN_ADDR}:{}", lease.port);
    let result = tokio_socks::tcp::Socks5Stream::connect_with_password(
        proxy_addr.as_str(),
        (target_host, target_port),
        &lease.username,
        &lease.password,
    )
    .await;
    match result {
        Ok(stream) => Ok(SingBoxStream {
            inner: stream.into_inner(),
            _lease: lease,
        }),
        Err(error) => {
            // sing-box writes the real reason (TLS, auth, obfs, port) to its log slightly after
            // replying to the SOCKS request, so give it a moment before reading.
            tokio::time::sleep(LOG_SETTLE).await;
            let log = lease.recent_log();
            let label = protocol_label(&proxy.protocol);
            let node = node_address(proxy);
            if log.is_empty() {
                bail!("{label} proxy {node} could not reach {target_host}:{target_port}: {error}")
            }
            bail!(
                "{label} proxy {node} could not reach {target_host}:{target_port}: {error}\n{log}"
            )
        }
    }
}

/// Kills every running sing-box process.
pub fn shutdown_all() {
    let mut registry = REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (_, mut running) in registry.drain() {
        let _ = running.child.start_kill();
    }
}

/// A TCP stream to the local sing-box SOCKS port that keeps the process alive while open.
pub struct SingBoxStream {
    inner: TcpStream,
    _lease: SingBoxLease,
}

impl AsyncRead for SingBoxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SingBoxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type SharedLog = Arc<Mutex<VecDeque<String>>>;

struct Running {
    generation: u64,
    port: u16,
    username: String,
    password: String,
    child: Child,
    log: SharedLog,
    refs: usize,
}

static REGISTRY: LazyLock<Mutex<HashMap<String, Running>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Serializes process startup so two connections to the same node share one process.
static STARTUP: LazyLock<tokio::sync::Mutex<u64>> = LazyLock::new(|| tokio::sync::Mutex::new(0));

struct SingBoxLease {
    key: String,
    generation: u64,
    port: u16,
    username: String,
    password: String,
    log: SharedLog,
}

impl SingBoxLease {
    fn recent_log(&self) -> String {
        join_log(&self.log)
    }
}

impl Drop for SingBoxLease {
    fn drop(&mut self) {
        let mut registry = REGISTRY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(running) = registry.get_mut(&self.key) else {
            return;
        };
        if running.generation != self.generation {
            return;
        }
        running.refs = running.refs.saturating_sub(1);
        if running.refs == 0
            && let Some(mut running) = registry.remove(&self.key)
        {
            let _ = running.child.start_kill();
            tracing::info!(port = running.port, "Stopped sing-box proxy");
        }
    }
}

async fn acquire(proxy: &SshProxyConfig) -> anyhow::Result<SingBoxLease> {
    let outbound = build_outbound(proxy)?;
    // The outbound JSON fully describes the node, so an edited node never reuses a process
    // started with the old settings.
    let key = outbound.to_string();
    let mut generation = STARTUP.lock().await;

    {
        let mut registry = REGISTRY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(running) = registry.get_mut(&key) {
            if matches!(running.child.try_wait(), Ok(None)) {
                running.refs += 1;
                return Ok(SingBoxLease {
                    key,
                    generation: running.generation,
                    port: running.port,
                    username: running.username.clone(),
                    password: running.password.clone(),
                    log: running.log.clone(),
                });
            }
            registry.remove(&key);
        }
    }

    *generation += 1;
    let generation = *generation;
    let running = spawn(proxy, outbound, generation).await?;
    let lease = SingBoxLease {
        key: key.clone(),
        generation,
        port: running.port,
        username: running.username.clone(),
        password: running.password.clone(),
        log: running.log.clone(),
    };
    REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, running);
    Ok(lease)
}

async fn spawn(
    proxy: &SshProxyConfig,
    outbound: Value,
    generation: u64,
) -> anyhow::Result<Running> {
    let binary = locate_binary()?;
    let port = free_port()?;
    let username = uuid::Uuid::new_v4().simple().to_string();
    let password = uuid::Uuid::new_v4().simple().to_string();
    let config = build_config(&outbound, port, &username, &password);

    let config_path =
        std::env::temp_dir().join(format!("nyaterm-singbox-{}.json", uuid::Uuid::new_v4()));
    write_private_file(&config_path, config.to_string().as_bytes())
        .context("write sing-box config")?;

    let mut command = tokio::process::Command::new(&binary);
    command
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .arg("--disable-color")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    tracing::info!(
        protocol = %proxy.protocol,
        node = %node_address(proxy),
        binary = %binary.display(),
        port,
        "Starting sing-box proxy"
    );
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = std::fs::remove_file(&config_path);
            bail!("Failed to start sing-box ({}): {error}", binary.display());
        }
    };
    #[cfg(windows)]
    windows_job::adopt(&child);

    let log: SharedLog = Arc::new(Mutex::new(VecDeque::new()));
    if let Some(stdout) = child.stdout.take() {
        pump_log(stdout, log.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        pump_log(stderr, log.clone());
    }

    let started = await_listening(&mut child, port).await;
    // sing-box has read its config by now (or failed to); the file holds the node password.
    let _ = std::fs::remove_file(&config_path);
    if let Err(reason) = started {
        let _ = child.start_kill();
        tokio::time::sleep(LOG_SETTLE).await;
        let said = join_log(&log);
        if said.is_empty() {
            bail!("sing-box {reason}");
        }
        bail!("sing-box {reason}:\n{said}");
    }

    Ok(Running {
        generation,
        port,
        username,
        password,
        child,
        log,
        refs: 1,
    })
}

async fn await_listening(child: &mut Child, port: u16) -> Result<(), String> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("exited during startup ({status})"));
        }
        if TcpStream::connect((LISTEN_ADDR, port)).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Err("did not start listening in time".to_string())
}

fn pump_log<R>(reader: R, log: SharedLog)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = strip_ansi(&line);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            tracing::debug!(message = %line, "sing-box");
            let mut log = log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            log.push_back(line.to_string());
            while log.len() > MAX_LOG_LINES {
                log.pop_front();
            }
        }
    });
}

fn join_log(log: &SharedLog) -> String {
    let log = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let joined = log.iter().cloned().collect::<Vec<_>>().join("\n");
    let skip = joined.chars().count().saturating_sub(MAX_LOG_CHARS);
    joined.chars().skip(skip).collect()
}

fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn free_port() -> anyhow::Result<u16> {
    // Racy in theory (the port is released before sing-box binds it), but a fixed port would
    // collide as soon as two nodes run at once.
    let listener =
        std::net::TcpListener::bind((LISTEN_ADDR, 0)).context("no free local port for sing-box")?;
    Ok(listener.local_addr()?.port())
}

fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)
}

fn binary_name() -> &'static str {
    if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    }
}

/// Search order: `$NYATERM_SING_BOX`, next to the app executable, `~/.nyaterm-plus/bin`, `PATH`.
fn locate_binary() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os(BINARY_ENV).map(PathBuf::from)
        && path.is_file()
    {
        return Ok(path);
    }

    let name = binary_name();
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(ToOwned::to_owned))
    {
        candidates.push(dir.join(name));
    }
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".nyaterm-plus").join("bin").join(name));
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|dir| dir.join(name)));
    }

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            anyhow!(
                "sing-box is required for Hysteria2 / Trojan proxies but was not found. \
                 Put {name} next to NyaTerm.exe or in ~/.nyaterm-plus/bin, or set {BINARY_ENV} \
                 to its path."
            )
        })
}

fn node_address(proxy: &SshProxyConfig) -> String {
    let hop = proxy
        .node
        .as_ref()
        .and_then(|node| node.hop_ports.as_deref())
        .map(str::trim)
        .filter(|hop| !hop.is_empty() && proxy.protocol == "hysteria2");
    match hop {
        Some(hop) => format!("{}:{hop}", proxy.host),
        None => format!("{}:{}", proxy.host, proxy.port),
    }
}

fn build_config(outbound: &Value, listen_port: u16, username: &str, password: &str) -> Value {
    json!({
        "log": { "level": "info", "timestamp": false },
        "inbounds": [{
            "type": "socks",
            "tag": "in",
            "listen": LISTEN_ADDR,
            "listen_port": listen_port,
            // Without credentials any local process could use the tunnel while it is up.
            "users": [{ "username": username, "password": password }],
        }],
        "outbounds": [outbound],
    })
}

fn build_outbound(proxy: &SshProxyConfig) -> anyhow::Result<Value> {
    let default_node = ProxyNodeOptions::default();
    let node = proxy.node.as_ref().unwrap_or(&default_node);
    let password = proxy
        .password
        .as_ref()
        .map(|password| password.expose_secret())
        .unwrap_or_default();
    if proxy.host.trim().is_empty() {
        bail!("Proxy server address is empty");
    }
    if password.is_empty() {
        bail!(
            "{} proxy password is empty",
            protocol_label(&proxy.protocol)
        );
    }

    let mut tls = json!({ "enabled": true, "insecure": node.allow_insecure });
    if let Some(sni) = non_empty(node.sni.as_deref()) {
        // Leaving server_name out makes sing-box use the server address; an empty string would
        // send an empty SNI and get rejected.
        tls["server_name"] = json!(sni);
    }

    let mut outbound = json!({
        "tag": "out",
        "server": proxy.host.trim(),
        "password": password,
        "tls": tls,
    });

    match proxy.protocol.as_str() {
        "hysteria2" => {
            outbound["type"] = json!("hysteria2");
            match hop_ports(node.hop_ports.as_deref()) {
                // Hopping nodes only listen inside the range, so the fixed port is left out.
                Some(ports) => {
                    outbound["server_ports"] = json!(ports);
                    outbound["hop_interval"] = json!(HOP_INTERVAL);
                }
                None => outbound["server_port"] = json!(proxy.port),
            }
            // 0 would be taken literally and throttle the connection to nothing.
            if let Some(up) = node.up_mbps.filter(|value| *value > 0) {
                outbound["up_mbps"] = json!(up);
            }
            if let Some(down) = node.down_mbps.filter(|value| *value > 0) {
                outbound["down_mbps"] = json!(down);
            }
            if let Some(obfs) = node
                .obfs_password
                .as_ref()
                .map(|obfs| obfs.expose_secret())
                .filter(|obfs| !obfs.trim().is_empty())
            {
                outbound["obfs"] = json!({ "type": "salamander", "password": obfs });
            }
        }
        "trojan" => {
            outbound["type"] = json!("trojan");
            outbound["server_port"] = json!(proxy.port);
        }
        other => bail!("Unsupported sing-box proxy protocol '{other}'"),
    }
    Ok(outbound)
}

/// `20000-50000, 40000` → `["20000:50000", "40000"]`; `None` when nothing usable is left.
fn hop_ports(raw: Option<&str>) -> Option<Vec<String>> {
    let normalized = nyaterm_core::proxy_link::normalize_hop_ports(raw?);
    let ports: Vec<String> = normalized
        .split(',')
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.replace('-', ":"))
        .collect();
    (!ports.is_empty()).then_some(ports)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(windows)]
mod windows_job {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::OnceLock;

    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };

    /// One job for the app's lifetime: its handle is never closed, so Windows kills every
    /// sing-box in it when the app process ends, however it ends.
    static JOB: OnceLock<Option<OwnedHandle>> = OnceLock::new();

    fn create() -> Option<OwnedHandle> {
        // SAFETY: unnamed, non-inheritable job; the returned handle is owned here.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return None;
        }
        // SAFETY: raw is a fresh job handle that nothing else owns.
        let job = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: limits has the layout/size required by this information class.
        let applied = unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        };
        (applied != 0).then_some(job)
    }

    pub(super) fn adopt(child: &tokio::process::Child) {
        let (Some(job), Some(process)) = (JOB.get_or_init(create), child.raw_handle()) else {
            return;
        };
        // SAFETY: both handles are live for the duration of the call.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process) } == 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "Could not tie sing-box to the app's lifetime"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use nyaterm_core::ProxyNodeOptions;
    use serde_json::json;

    use crate::SshProxyConfig;
    use crate::singbox::{
        HOP_INTERVAL, LISTEN_ADDR, build_config, build_outbound, hop_ports, strip_ansi,
    };

    fn proxy(protocol: &str, node: ProxyNodeOptions) -> SshProxyConfig {
        SshProxyConfig {
            protocol: protocol.to_string(),
            host: "node.example.com".to_string(),
            port: 443,
            command: None,
            username: None,
            password: Some("secret".to_string().into()),
            node: Some(node),
        }
    }

    #[test]
    fn hysteria2_outbound_uses_fixed_port_without_hopping() {
        let outbound = build_outbound(&proxy("hysteria2", ProxyNodeOptions::default())).unwrap();
        assert_eq!(outbound["type"], "hysteria2");
        assert_eq!(outbound["server"], "node.example.com");
        assert_eq!(outbound["server_port"], 443);
        assert_eq!(outbound["password"], "secret");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["insecure"], false);
        assert!(outbound["tls"].get("server_name").is_none());
        assert!(outbound.get("server_ports").is_none());
        assert!(outbound.get("obfs").is_none());
        assert!(outbound.get("up_mbps").is_none());
    }

    #[test]
    fn hysteria2_outbound_includes_optional_fields() {
        let outbound = build_outbound(&proxy(
            "hysteria2",
            ProxyNodeOptions {
                sni: Some(" cdn.example.com ".to_string()),
                allow_insecure: true,
                obfs_password: Some("obfs".to_string().into()),
                hop_ports: Some("20000-50000, 40000".to_string()),
                up_mbps: Some(50),
                down_mbps: Some(0),
            },
        ))
        .unwrap();
        assert_eq!(outbound["tls"]["server_name"], "cdn.example.com");
        assert_eq!(outbound["tls"]["insecure"], true);
        assert_eq!(outbound["obfs"]["type"], "salamander");
        assert_eq!(outbound["obfs"]["password"], "obfs");
        assert_eq!(outbound["server_ports"], json!(["20000:50000", "40000"]));
        assert_eq!(outbound["hop_interval"], HOP_INTERVAL);
        assert!(outbound.get("server_port").is_none());
        assert_eq!(outbound["up_mbps"], 50);
        assert!(outbound.get("down_mbps").is_none());
    }

    #[test]
    fn trojan_outbound_ignores_hysteria_only_fields() {
        let outbound = build_outbound(&proxy(
            "trojan",
            ProxyNodeOptions {
                obfs_password: Some("obfs".to_string().into()),
                hop_ports: Some("20000-50000".to_string()),
                up_mbps: Some(10),
                ..ProxyNodeOptions::default()
            },
        ))
        .unwrap();
        assert_eq!(outbound["type"], "trojan");
        assert_eq!(outbound["server_port"], 443);
        assert!(outbound.get("obfs").is_none());
        assert!(outbound.get("server_ports").is_none());
        assert!(outbound.get("up_mbps").is_none());
    }

    #[test]
    fn outbound_requires_password() {
        let mut settings = proxy("trojan", ProxyNodeOptions::default());
        settings.password = None;
        assert!(build_outbound(&settings).is_err());
    }

    #[test]
    fn hop_ports_drop_invalid_segments() {
        assert_eq!(
            hop_ports(Some("1000:2000,abc,3000-2000,0,443")),
            Some(vec!["1000:2000".to_string(), "443".to_string()])
        );
        assert_eq!(hop_ports(Some(" , ")), None);
        assert_eq!(hop_ports(None), None);
    }

    #[test]
    fn config_wraps_outbound_with_authenticated_socks_inbound() {
        let config = build_config(&json!({ "type": "trojan" }), 23456, "user", "pass");
        let inbound = &config["inbounds"][0];
        assert_eq!(inbound["type"], "socks");
        assert_eq!(inbound["listen"], LISTEN_ADDR);
        assert_eq!(inbound["listen_port"], 23456);
        assert_eq!(inbound["users"][0]["username"], "user");
        assert_eq!(inbound["users"][0]["password"], "pass");
        assert_eq!(config["outbounds"][0]["type"], "trojan");
    }

    #[test]
    fn strip_ansi_removes_color_codes() {
        assert_eq!(strip_ansi("\u{1b}[31mERROR\u{1b}[0m dial"), "ERROR dial");
    }
}
