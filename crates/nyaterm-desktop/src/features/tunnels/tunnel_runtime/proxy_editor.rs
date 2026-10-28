use rust_i18n::t;

use gpui::{Context, Window};
use nyaterm_core::proxy_link::{normalize_hop_ports, parse_proxy_link};
use nyaterm_core::{ProxyConfig, ProxyNodeOptions, uuid};
use nyaterm_store::StoreDomain;

use super::helpers::parse_port;
use crate::features::NyaTermApp;
use crate::models::{NetworkProxyEditorField, NetworkProxyEditorState};

impl NyaTermApp {
    pub(in crate::features) fn open_network_proxy_editor(
        &mut self,
        proxy_id: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let editing = proxy_id.is_some();
        let proxy = match proxy_id.as_deref() {
            Some(id) => self
                .tunnel_state
                .proxies()
                .iter()
                .find(|proxy| proxy.id == id)
                .cloned(),
            None => Some(ProxyConfig::default()),
        };
        let Some(proxy) = proxy else {
            self.shell
                .set_status("proxy profile is no longer available".to_string());
            cx.notify();
            return;
        };

        let node = proxy.node.unwrap_or_default();
        self.connection_state
            .begin_network_proxy_edit(NetworkProxyEditorState {
                id: proxy_id,
                name: proxy.name,
                protocol: match proxy.protocol.as_str() {
                    "http" | "proxycommand" | "hysteria2" | "trojan" => proxy.protocol,
                    _ => "socks5".to_string(),
                },
                host: if proxy.host.trim().is_empty() {
                    "127.0.0.1".to_string()
                } else {
                    proxy.host
                },
                port: if proxy.port == 0 {
                    String::new()
                } else {
                    proxy.port.to_string()
                },
                command: proxy.command.unwrap_or_default(),
                username: proxy.username.unwrap_or_default(),
                password: nyaterm_core::SecretString::default(),
                existing_password: proxy.password,
                password_id: proxy.password_id,
                group_id: proxy.group_id,
                focused_field: NetworkProxyEditorField::Name,
                error: None,
                link: String::new(),
                sni: node.sni.unwrap_or_default(),
                allow_insecure: node.allow_insecure,
                obfs_password: node
                    .obfs_password
                    .map(|secret| secret.expose_secret().to_string())
                    .unwrap_or_default(),
                hop_ports: node.hop_ports.unwrap_or_default(),
                up_mbps: node
                    .up_mbps
                    .map(|mbps| mbps.to_string())
                    .unwrap_or_default(),
                down_mbps: node
                    .down_mbps
                    .map(|mbps| mbps.to_string())
                    .unwrap_or_default(),
            });
        // The dialog's boxes own their text, so they have to be dropped for
        // the next proxy to seed from its own values.
        self.forget_text_inputs("network.proxy-editor.");
        self.shell.set_status("proxy editor opened".to_string());
        cx.notify();
        self.open_form_dialog(
            (
                if editing {
                    t!("network.editProxy").to_string()
                } else {
                    t!("network.newProxy").to_string()
                },
                520.,
                t!("common.save").to_string(),
                |app, _, cx| app.network_proxy_editor_dialog_content(cx),
                |app, _, cx| {
                    app.save_network_proxy_editor(cx);
                    let saved = app.connection_state.active_network_proxy_editor().is_none();
                    if saved {
                        app.forget_text_inputs("network.proxy-editor.");
                    }
                    saved
                },
                |app, cx| app.close_network_proxy_editor(cx),
            ),
            window,
            cx,
        );
    }

    pub(in crate::features) fn close_network_proxy_editor(&mut self, cx: &mut Context<Self>) {
        self.connection_state.close_network_proxy_editor();
        self.forget_text_inputs("network.proxy-editor.");
        self.shell.set_status("proxy editor closed".to_string());
        cx.notify();
    }

    /// Apply an edit from one of the proxy dialog's inputs.
    pub(in crate::features) fn apply_network_proxy_editor_input(
        &mut self,
        field: &str,
        text: String,
        cx: &mut Context<Self>,
    ) {
        let field = match field {
            "name" => NetworkProxyEditorField::Name,
            "host" => NetworkProxyEditorField::Host,
            "port" => NetworkProxyEditorField::Port,
            "command" => NetworkProxyEditorField::Command,
            "username" => NetworkProxyEditorField::Username,
            "password" => NetworkProxyEditorField::Password,
            "link" => NetworkProxyEditorField::Link,
            "sni" => NetworkProxyEditorField::Sni,
            "obfs" => NetworkProxyEditorField::ObfsPassword,
            "hop-ports" => NetworkProxyEditorField::HopPorts,
            "up-mbps" => NetworkProxyEditorField::UpMbps,
            "down-mbps" => NetworkProxyEditorField::DownMbps,
            _ => return,
        };
        let link = (field == NetworkProxyEditorField::Link).then(|| text.clone());
        if self
            .connection_state
            .set_network_proxy_editor_field(field, text)
        {
            cx.notify();
        }
        if let Some(link) = link {
            self.apply_network_proxy_link(&link, cx);
        }
    }

    /// NyaTerm Plus: fill the node form from a pasted `hy2://` / `trojan://` share link.
    fn apply_network_proxy_link(&mut self, link: &str, cx: &mut Context<Self>) {
        let Some(mut editor) = self.connection_state.active_network_proxy_editor() else {
            return;
        };
        let Some(parsed) = parse_proxy_link(link) else {
            if link.contains("://") {
                self.set_network_proxy_editor_error(t!("network.proxyNodeLinkInvalid"), cx);
            }
            return;
        };
        if editor.name.trim().is_empty() && !parsed.name.trim().is_empty() {
            editor.name = parsed.name.trim().to_string();
        }
        editor.protocol = parsed.protocol.to_string();
        editor.host = parsed.host;
        editor.port = parsed.port.to_string();
        editor.password = parsed.password.into();
        editor.sni = parsed.node.sni.unwrap_or_default();
        editor.allow_insecure = parsed.node.allow_insecure;
        editor.obfs_password = parsed
            .node
            .obfs_password
            .map(|secret| secret.expose_secret().to_string())
            .unwrap_or_default();
        editor.hop_ports = parsed.node.hop_ports.unwrap_or_default();
        editor.up_mbps = parsed
            .node
            .up_mbps
            .map(|mbps| mbps.to_string())
            .unwrap_or_default();
        editor.down_mbps = parsed
            .node
            .down_mbps
            .map(|mbps| mbps.to_string())
            .unwrap_or_default();
        editor.error = None;
        let values = [
            ("name", editor.name.clone()),
            ("host", editor.host.clone()),
            ("port", editor.port.clone()),
            ("password", editor.password.expose_secret().to_string()),
            ("sni", editor.sni.clone()),
            ("obfs", editor.obfs_password.clone()),
            ("hop-ports", editor.hop_ports.clone()),
            ("up-mbps", editor.up_mbps.clone()),
            ("down-mbps", editor.down_mbps.clone()),
        ];
        self.connection_state.begin_network_proxy_edit(editor);
        for (key, value) in values {
            self.reset_text_input(&format!("network.proxy-editor.{key}"), &value, cx);
        }
        self.shell
            .set_status("proxy fields filled from share link".to_string());
        cx.notify();
    }

    pub(in crate::features) fn toggle_network_proxy_insecure(&mut self, cx: &mut Context<Self>) {
        let Some(mut editor) = self.connection_state.active_network_proxy_editor() else {
            return;
        };
        editor.allow_insecure = !editor.allow_insecure;
        self.connection_state.begin_network_proxy_edit(editor);
        cx.notify();
    }

    pub(in crate::features) fn set_network_proxy_protocol(
        &mut self,
        protocol: &str,
        cx: &mut Context<Self>,
    ) {
        if let Some(protocol) = self.connection_state.set_network_proxy_protocol(protocol) {
            self.shell
                .set_status(format!("proxy protocol set to {protocol}"));
        }
        cx.notify();
    }

    pub(in crate::features) fn set_network_proxy_group(
        &mut self,
        group_id: Option<String>,
        cx: &mut Context<Self>,
    ) {
        let group_id = group_id.filter(|id| {
            self.tunnel_state
                .proxy_groups()
                .iter()
                .any(|group| group.id == *id)
        });
        if self.connection_state.set_network_proxy_group(group_id) {
            self.shell.set_status("proxy group changed".to_string());
        }
        cx.notify();
    }

    pub(in crate::features) fn save_network_proxy_editor(&mut self, cx: &mut Context<Self>) {
        let Some(editor) = self.connection_state.active_network_proxy_editor() else {
            self.shell
                .set_status("no proxy editor is active".to_string());
            cx.notify();
            return;
        };

        let name = editor.name.trim().to_string();
        if name.is_empty() {
            self.set_network_proxy_editor_error("Proxy name is required", cx);
            return;
        }
        let is_command = editor.is_proxy_command();
        let command = if is_command {
            let command = editor.command.trim().to_string();
            if command.is_empty() {
                self.set_network_proxy_editor_error("ProxyCommand is required", cx);
                return;
            }
            Some(command)
        } else {
            None
        };
        let host = if is_command {
            editor.host.trim().to_string()
        } else {
            let host = editor.host.trim().to_string();
            if host.is_empty() {
                self.set_network_proxy_editor_error("Proxy host is required", cx);
                return;
            }
            host
        };
        let port = if is_command {
            editor.port.trim().parse::<u16>().unwrap_or(0)
        } else {
            let Some(port) = parse_port(&editor.port) else {
                self.set_network_proxy_editor_error("Proxy port must be 1-65535", cx);
                return;
            };
            port
        };
        let is_node = editor.is_node();
        if is_node && editor.password.is_empty() && editor.existing_password.is_none() {
            self.set_network_proxy_editor_error(t!("network.proxyNodePasswordRequired"), cx);
            return;
        }
        let node = is_node.then(|| {
            let text = |value: &str| {
                let value = value.trim();
                (!value.is_empty()).then(|| value.to_string())
            };
            let hysteria2 = editor.is_hysteria2();
            ProxyNodeOptions {
                sni: text(&editor.sni),
                allow_insecure: editor.allow_insecure,
                obfs_password: text(&editor.obfs_password)
                    .filter(|_| hysteria2)
                    .map(Into::into),
                hop_ports: Some(normalize_hop_ports(&editor.hop_ports))
                    .filter(|ports| hysteria2 && !ports.is_empty()),
                up_mbps: editor
                    .up_mbps
                    .trim()
                    .parse()
                    .ok()
                    .filter(|mbps| hysteria2 && *mbps > 0),
                down_mbps: editor
                    .down_mbps
                    .trim()
                    .parse()
                    .ok()
                    .filter(|mbps| hysteria2 && *mbps > 0),
            }
        });
        let username = if is_node || editor.username.trim().is_empty() {
            None
        } else {
            Some(editor.username.trim().to_string())
        };
        let password = if editor.password.is_empty() {
            editor.existing_password
        } else {
            Some(editor.password)
        };
        let password_id = if password.is_some() {
            None
        } else {
            editor.password_id
        };
        let group_id = editor
            .group_id
            .filter(|id| self.tunnel_state.has_proxy_group(id));

        let id = editor.id.clone().unwrap_or_else(uuid);
        let proxy = ProxyConfig {
            id: id.clone(),
            name: name.clone(),
            protocol: editor.protocol,
            host,
            port,
            command,
            username,
            password,
            password_id,
            group_id,
            node,
        };
        let next_proxies = self.tunnel_state.proxies_with_upsert(proxy);

        let persisted = next_proxies.clone();
        self.submit_store_request(
            0,
            nyaterm_store::store_mutation(StoreDomain::Tunnels, move |store| {
                store.replace_proxies(&persisted)
            }),
            move |this, event, cx| {
                match event.outcome {
                    Ok(()) => {
                        this.tunnel_state.commit_proxies(next_proxies);
                        this.connection_state.close_network_proxy_editor();
                        this.shell.set_status(format!("proxy '{name}' saved"));
                        this.settings
                            .update_store_status(this.shell.status().to_string(), true);
                    }
                    Err(error) => {
                        this.shell
                            .set_status(format!("failed to save proxy: {error}"));
                        this.settings
                            .update_store_status(this.shell.status().to_string(), false);
                        this.connection_state
                            .set_network_proxy_editor_error(this.shell.status().to_string());
                    }
                }
                cx.notify();
            },
            cx,
        );
    }

    pub(in crate::features) fn set_network_proxy_editor_error(
        &mut self,
        error: impl Into<String>,
        cx: &mut Context<Self>,
    ) {
        let error = error.into();
        self.connection_state
            .set_network_proxy_editor_error(error.clone());
        self.shell.set_status(error);
        cx.notify();
    }
}
