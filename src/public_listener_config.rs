//! File-owned public HTTP listener definitions.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub id: String,
    pub listen: SocketAddr,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<crate::certificates::CertificateFiles>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    /// Externally visible port used as the default forwarded port when no
    /// trusted `X-Forwarded-Port` is present (for example behind a port
    /// forward that adds no headers). Absent means the local port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertised_port: Option<u16>,
}

fn enabled_default() -> bool {
    true
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl Listener {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_id(&self.id) && self.id != "default",
            "invalid public HTTP listener id"
        );
        ensure!(
            self.listen.port() != 0,
            "public HTTP listener port must be nonzero"
        );
        ensure!(
            self.advertised_port != Some(0),
            "public HTTP listener advertised_port must be 1-65535"
        );
        ensure!(
            self.trusted_proxy_cidrs.len() <= 1024,
            "too many public HTTP trusted proxy CIDRs"
        );
        crate::certificates::validate_set(&self.certificates)
    }
}
