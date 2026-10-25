//! Bounded native service address. DNS is discovery; TLS remains the peer identity.
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, net::SocketAddr, str::FromStr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint(String);
impl Endpoint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.0.parse().ok()
    }
    pub fn is_loopback(&self) -> bool {
        self.socket_addr().is_some_and(|a| a.ip().is_loopback())
    }
    pub fn port(&self) -> u16 {
        self.0.rsplit_once(':').unwrap().1.parse().unwrap()
    }
    pub fn dns_name(&self) -> Option<&str> {
        if self.socket_addr().is_some() {
            None
        } else {
            Some(self.0.rsplit_once(':').unwrap().0)
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.0.parse::<Self>().map(|_| ())
    }
}
impl From<SocketAddr> for Endpoint {
    fn from(address: SocketAddr) -> Self {
        Self(address.to_string())
    }
}
impl FromStr for Endpoint {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        ensure!(
            !value.is_empty() && value.len() <= 260,
            "invalid native service address"
        );
        if let Ok(address) = value.parse::<SocketAddr>() {
            ensure!(
                address.port() != 0
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast(),
                "invalid native service address"
            );
            return Ok(Self(address.to_string()));
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("native service port required"))?;
        ensure!(
            !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|p| p != 0),
            "invalid native service port"
        );
        ensure!(
            !host.is_empty()
                && host.len() <= 253
                && !host.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
            "invalid native service DNS name"
        );
        for label in host.split('.') {
            ensure!(
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "invalid native service DNS name"
            );
        }
        Ok(Self(format!(
            "{}:{}",
            host.to_ascii_lowercase(),
            port.parse::<u16>()?
        )))
    }
}
impl fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
impl Serialize for Endpoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_is_never_a_plaintext_loopback_claim() {
        for valid in [
            "sumunjang.world.svc:9081",
            "localhost:9081",
            "[::1]:9081",
            "127.0.0.1:9081",
        ] {
            let endpoint: Endpoint = valid.parse().unwrap();
            assert_eq!(endpoint.is_loopback(), endpoint.socket_addr().is_some());
            assert_eq!(endpoint.port(), 9081);
            assert_eq!(
                serde_json::from_str::<Endpoint>(&serde_json::to_string(&endpoint).unwrap())
                    .unwrap(),
                endpoint
            );
        }
        for invalid in [
            "http://service:9081",
            "user@service:9081",
            "service:0",
            "service:65536",
            "service: 9081",
            "service",
            "service.:9081",
            "-service:9081",
            "a..b:9081",
            "127.1:9081",
            "0.0.0.0:9081",
            "[::]:9081",
            "224.0.0.1:9081",
            "service/path:9081",
        ] {
            assert!(invalid.parse::<Endpoint>().is_err(), "{invalid}");
        }
    }
}
