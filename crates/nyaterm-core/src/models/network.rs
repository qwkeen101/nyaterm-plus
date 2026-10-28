use serde::{Deserialize, Serialize};

use crate::SecretString;

use super::{
    default_proxy_host, default_proxy_port, default_proxy_protocol, default_true,
    default_tunnel_target_host, default_tunnel_type, uuid_v4,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ConnectionNetwork {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_jump_id: Option<String>,
    /// OpenSSH lookup identity used instead of the network destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelConfig {
    #[serde(default = "uuid_v4")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_tunnel_type")]
    pub tunnel_type: String,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default = "default_tunnel_target_host")]
    pub target_host: String,
    #[serde(default)]
    pub target_port: u16,
    #[serde(default)]
    pub is_open: bool,
    #[serde(default)]
    pub auto_open: bool,
    #[serde(default = "default_true")]
    pub bind_localhost: bool,
    #[serde(default)]
    pub group_id: Option<String>,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            id: uuid_v4(),
            name: String::new(),
            tunnel_type: default_tunnel_type(),
            connection_id: None,
            listen_port: 0,
            target_host: default_tunnel_target_host(),
            target_port: 0,
            is_open: false,
            auto_open: false,
            bind_localhost: true,
            group_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelGroup {
    #[serde(default = "uuid_v4")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub sort_order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TunnelsConfig {
    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TunnelGroupsConfig {
    #[serde(default)]
    pub groups: Vec<TunnelGroup>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyConfig {
    #[serde(default = "uuid_v4")]
    pub id: String,
    pub name: String,
    #[serde(default = "default_proxy_protocol")]
    pub protocol: String,
    #[serde(default = "default_proxy_host")]
    pub host: String,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretString>,
    #[serde(default)]
    pub password_id: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    /// NyaTerm Plus: Hysteria2 / Trojan node options (run through a local sing-box). Left out
    /// of the stored JSON for every other protocol, so upstream's format is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<ProxyNodeOptions>,
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyConfig")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("command", &self.command.as_ref().map(|_| "<redacted>"))
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("password_id", &self.password_id)
            .field("group_id", &self.group_id)
            .field("node", &self.node)
            .finish()
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            id: uuid_v4(),
            name: String::new(),
            protocol: default_proxy_protocol(),
            host: default_proxy_host(),
            port: default_proxy_port(),
            command: None,
            username: None,
            password: None,
            password_id: None,
            group_id: None,
            node: None,
        }
    }
}

/// NyaTerm Plus: the extra settings of a Hysteria2 / Trojan node. The node password itself is
/// [`ProxyConfig::password`].
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyNodeOptions {
    /// TLS server name; empty means the node address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Accept self-signed certificates.
    #[serde(default)]
    pub allow_insecure: bool,
    /// Hysteria2 salamander obfuscation password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<SecretString>,
    /// Hysteria2 port hopping, e.g. `20000-50000` or `20000-30000,40000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_ports: Option<String>,
    /// Hysteria2 bandwidth hints; empty lets the protocol probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
}

impl std::fmt::Debug for ProxyNodeOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyNodeOptions")
            .field("sni", &self.sni)
            .field("allow_insecure", &self.allow_insecure)
            .field(
                "obfs_password",
                &self.obfs_password.as_ref().map(|_| "<redacted>"),
            )
            .field("hop_ports", &self.hop_ports)
            .field("up_mbps", &self.up_mbps)
            .field("down_mbps", &self.down_mbps)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyGroup {
    #[serde(default = "uuid_v4")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub sort_order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ProxyGroupsConfig {
    #[serde(default)]
    pub groups: Vec<ProxyGroup>,
}
