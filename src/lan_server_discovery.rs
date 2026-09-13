//! Discover the xdesk server which is announced on the local network.
//!
//! The server periodically broadcasts a JSON message to `255.255.255.255:8888`, e.g.
//! `{"service":"xdesk_server","id_server_port":25556,"relay_server_port":25557,"pub_key":"...","ver":"1.0"}`.
//!
//! When the option `lan-server-priority` is enabled, the client listens on the same UDP port,
//! applies the announced ID server, relay server and public key, and reports the result to the
//! UI. The client can therefore match the server without any manual configuration.

use hbb_common::{
    anyhow::anyhow,
    config::{keys, Config},
    log, ResultType,
};
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

/// UDP port which the server broadcasts to and the client listens on.
pub const ANNOUNCE_PORT: u16 = 8888;

/// The `service` field expected in an announcement.
const SERVICE_NAME: &str = "xdesk_server";

/// Name of the global event pushed to the UI, keep it in sync with `kLanServerDiscovered`
/// in `flutter/lib/consts.dart`.
pub const EVENT_LAN_SERVER: &str = "lan_server";

/// Blocking read timeout of the listening socket, only used to check for a lost server.
const READ_TIMEOUT: Duration = Duration::from_millis(500);

/// The server is considered gone when nothing is received for this long.
const SERVER_LOST_TIMEOUT: Duration = Duration::from_secs(10);

/// Do not refresh the UI more often than this when the announced data does not change.
const MIN_UI_PUSH_INTERVAL: Duration = Duration::from_secs(5);

/// The server found in the local network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanServerInfo {
    pub ip: String,
    pub id_server_port: u16,
    pub relay_server_port: u16,
    pub pub_key: String,
}

static LAN_SERVER: OnceLock<Mutex<Option<LanServerInfo>>> = OnceLock::new();

/// Whether the discovery is enabled by the option `lan-server-priority`.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether the listening thread is running.
static RUNNING: AtomicBool = AtomicBool::new(false);

fn lan_server() -> &'static Mutex<Option<LanServerInfo>> {
    LAN_SERVER.get_or_init(|| Mutex::new(None))
}

/// Whether the user enabled the discovery with the option `lan-server-priority`.
pub fn is_enabled() -> bool {
    Config::get_option(keys::OPTION_LAN_SERVER_PRIORITY) == "Y"
}

/// Start or stop the discovery according to the option `lan-server-priority`.
///
/// It is called when the client initializes and every time the option changes, so that the
/// client only listens while the user enabled it.
pub fn apply_option() {
    set_enabled(is_enabled());
}

/// Enable or disable the discovery.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::SeqCst);
    if enabled {
        log::info!("LAN server discovery enabled");
        spawn_if_needed();
    } else {
        log::info!("LAN server discovery disabled");
    }
}

/// Start listening for server announcements in a background thread.
///
/// Repeated calls are ignored. Errors are logged instead of being propagated, because the
/// broadcast discovery is a best effort feature and must never break the application.
fn spawn_if_needed() {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        let res = listen();
        RUNNING.store(false, Ordering::SeqCst);
        match res {
            // Only stopped because the discovery was disabled, it may be enabled again
            // while the thread is quitting.
            Ok(()) => {
                if ENABLED.load(Ordering::SeqCst) {
                    spawn_if_needed();
                }
            }
            // Do not retry in a loop, the UDP port may be used by another window.
            Err(err) => log::error!("LAN server discovery stopped: {err}"),
        }
    });
}

fn listen() -> ResultType<()> {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, ANNOUNCE_PORT));
    let socket = UdpSocket::bind(addr)
        .map_err(|err| anyhow!("failed to bind UDP socket on {addr}: {err}"))?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;
    log::info!("LAN server discovery listening on UDP {ANNOUNCE_PORT}");

    let mut buf = [0u8; 4096];
    let mut last_seen: Option<Instant> = None;
    let mut last_push: Option<Instant> = None;
    while ENABLED.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((len, addr)) => {
                if let Some(info) = parse_announcement(&buf[..len], addr.ip()) {
                    let now = Instant::now();
                    last_seen = Some(now);
                    let changed = update_server(info.clone());
                    if changed {
                        log::info!(
                            "LAN server found: {} (ID server port {}, relay server port {})",
                            info.ip,
                            info.id_server_port,
                            info.relay_server_port
                        );
                        apply_config(&info);
                    }
                    // The UI may not be ready when the first announcement arrives, so the
                    // unchanged announcements are pushed again from time to time.
                    let push = changed
                        || last_push
                            .map(|last| now.duration_since(last) >= MIN_UI_PUSH_INTERVAL)
                            .unwrap_or(true);
                    if push {
                        last_push = Some(now);
                        notify_ui(Some(&info));
                    }
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => {
                log::error!("failed to receive LAN server announcement: {err}");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        if last_seen
            .map(|last| last.elapsed() >= SERVER_LOST_TIMEOUT)
            .unwrap_or(false)
        {
            last_seen = None;
            last_push = None;
            if update_server_lost() {
                log::info!("LAN server is gone");
                notify_ui(None);
            }
        }
    }
    // The applied options are kept, only the discovered server is forgotten.
    if update_server_lost() {
        notify_ui(None);
    }
    Ok(())
}

/// Parse an announcement, the source address is used as the server address.
fn parse_announcement(data: &[u8], ip: IpAddr) -> Option<LanServerInfo> {
    let v: Value = serde_json::from_slice(data).ok()?;
    if v.get("service")?.as_str()? != SERVICE_NAME {
        return None;
    }
    let id_server_port = u16::try_from(v.get("id_server_port")?.as_u64()?).ok()?;
    let relay_server_port = u16::try_from(v.get("relay_server_port")?.as_u64()?).ok()?;
    if id_server_port == 0 || relay_server_port == 0 {
        return None;
    }
    Some(LanServerInfo {
        ip: ip.to_string(),
        id_server_port,
        relay_server_port,
        pub_key: v
            .get("pub_key")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_owned(),
    })
}

/// Remember the announced server, returns true if it changed.
fn update_server(info: LanServerInfo) -> bool {
    let mut guard = match lan_server().lock() {
        Ok(guard) => guard,
        Err(err) => err.into_inner(),
    };
    if guard.as_ref() == Some(&info) {
        return false;
    }
    *guard = Some(info);
    true
}

/// Forget the announced server, returns true if there was one.
fn update_server_lost() -> bool {
    let mut guard = match lan_server().lock() {
        Ok(guard) => guard,
        Err(err) => err.into_inner(),
    };
    guard.take().is_some()
}

/// Apply the announced server to the configuration, so that the client matches the server
/// automatically.
///
/// Only the given ports and the public key are taken over, everything else is kept as is.
fn apply_config(info: &LanServerInfo) {
    apply_option(
        keys::OPTION_CUSTOM_RENDEZVOUS_SERVER,
        &format!("{}:{}", info.ip, info.id_server_port),
    );
    apply_option(
        keys::OPTION_RELAY_SERVER,
        &format!("{}:{}", info.ip, info.relay_server_port),
    );
    if !info.pub_key.is_empty() {
        apply_option(keys::OPTION_KEY, &info.pub_key);
    }
}

/// Apply a single option if it is not set to `value` yet.
///
/// The same path as the settings UI is used, which shares the options with the server process,
/// so a changed ID server restarts the rendezvous mediator automatically.
fn apply_option(key: &str, value: &str) {
    if Config::get_option(key) == value {
        return;
    }
    log::info!("Apply LAN server option: {key}={value}");
    crate::ui_interface::set_option(key.to_owned(), value.to_owned());
}

/// Send the announced server to the UI, `None` clears it.
fn notify_ui(info: Option<&LanServerInfo>) {
    #[cfg(feature = "flutter")]
    {
        let (ip, id_server_port, relay_server_port, pub_key) = match info {
            Some(info) => (
                info.ip.as_str(),
                info.id_server_port,
                info.relay_server_port,
                info.pub_key.as_str(),
            ),
            None => ("", 0, 0, ""),
        };
        let evt = serde_json::json!({
            "name": EVENT_LAN_SERVER,
            "ip": ip,
            "id_server_port": id_server_port,
            "relay_server_port": relay_server_port,
            "pub_key": pub_key,
        });
        match serde_json::to_string(&evt) {
            Ok(data) => {
                let _ = crate::flutter::push_global_event(crate::flutter::APP_TYPE_MAIN, data);
            }
            Err(err) => log::error!("failed to serialize LAN server event: {err}"),
        }
    }
    #[cfg(not(feature = "flutter"))]
    let _ = info;
}
