#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkTab {
    Tunnels,
    Proxies,
}

impl NetworkTab {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Tunnels => "Tunnels",
            Self::Proxies => "Proxies",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkGroupEditorState {
    pub(crate) tab: NetworkTab,
    pub(crate) id: Option<String>,
    pub(crate) name: String,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkMovePickerState {
    pub(crate) tab: NetworkTab,
    pub(crate) id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkTunnelEditorField {
    Name,
    ListenPort,
    TargetHost,
    TargetPort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkTunnelEditorState {
    pub(crate) id: Option<String>,
    pub(crate) is_open: bool,
    pub(crate) name: String,
    pub(crate) tunnel_type: String,
    pub(crate) connection_id: Option<String>,
    pub(crate) listen_port: String,
    pub(crate) target_host: String,
    pub(crate) target_port: String,
    pub(crate) auto_open: bool,
    pub(crate) bind_localhost: bool,
    pub(crate) group_id: Option<String>,
    pub(crate) focused_field: NetworkTunnelEditorField,
    pub(crate) error: Option<String>,
}

impl NetworkTunnelEditorState {
    pub(crate) fn is_dynamic(&self) -> bool {
        self.tunnel_type == "dynamic"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkProxyEditorField {
    Name,
    Host,
    Port,
    Command,
    Username,
    Password,
    // NyaTerm Plus: Hysteria2 / Trojan node fields.
    Link,
    Sni,
    ObfsPassword,
    HopPorts,
    UpMbps,
    DownMbps,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NetworkProxyEditorState {
    pub(crate) id: Option<String>,
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) host: String,
    pub(crate) port: String,
    pub(crate) command: String,
    pub(crate) username: String,
    pub(crate) password: nyaterm_core::SecretString,
    pub(crate) existing_password: Option<nyaterm_core::SecretString>,
    pub(crate) password_id: Option<String>,
    pub(crate) group_id: Option<String>,
    pub(crate) focused_field: NetworkProxyEditorField,
    pub(crate) error: Option<String>,
    /// NyaTerm Plus: a pasted share link and the Hysteria2 / Trojan node fields.
    pub(crate) link: String,
    pub(crate) sni: String,
    pub(crate) allow_insecure: bool,
    pub(crate) obfs_password: String,
    pub(crate) hop_ports: String,
    pub(crate) up_mbps: String,
    pub(crate) down_mbps: String,
}

impl std::fmt::Debug for NetworkProxyEditorState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkProxyEditorState")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("command", &"<redacted>")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("existing_password", &"<redacted>")
            .field("password_id", &self.password_id)
            .field("group_id", &self.group_id)
            .field("focused_field", &self.focused_field)
            .field("error", &self.error)
            .field("link", &"<redacted>")
            .field("sni", &self.sni)
            .field("allow_insecure", &self.allow_insecure)
            .field("obfs_password", &"<redacted>")
            .field("hop_ports", &self.hop_ports)
            .field("up_mbps", &self.up_mbps)
            .field("down_mbps", &self.down_mbps)
            .finish()
    }
}

impl NetworkProxyEditorState {
    pub(crate) fn is_proxy_command(&self) -> bool {
        self.protocol == "proxycommand"
    }

    /// NyaTerm Plus: a Hysteria2 / Trojan node, run through sing-box.
    pub(crate) fn is_node(&self) -> bool {
        nyaterm_core::proxy_link::is_node_protocol(&self.protocol)
    }

    pub(crate) fn is_hysteria2(&self) -> bool {
        self.protocol == "hysteria2"
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkProxyEditorField, NetworkProxyEditorState};

    #[test]
    fn proxy_editor_debug_output_redacts_password_and_command() {
        let secret = "nya-proxy-secret-never-log";
        let state = NetworkProxyEditorState {
            id: None,
            name: "Test".to_string(),
            protocol: "proxycommand".to_string(),
            host: "localhost".to_string(),
            port: "22".to_string(),
            command: secret.to_string(),
            username: "tester".to_string(),
            password: secret.to_string().into(),
            existing_password: Some(secret.to_string().into()),
            password_id: None,
            group_id: None,
            focused_field: NetworkProxyEditorField::Name,
            error: None,
            link: format!("hy2://{secret}@example.com"),
            sni: String::new(),
            allow_insecure: false,
            obfs_password: secret.to_string(),
            hop_ports: String::new(),
            up_mbps: String::new(),
            down_mbps: String::new(),
        };
        let output = format!("{state:?}");

        assert!(!output.contains(secret));
        assert!(output.contains("<redacted>"));
    }
}
