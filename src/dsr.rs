//! Strict, standalone IPVS direct-routing configuration for `hangang-dsr`.
//!
//! This module deliberately does not integrate with the gateway's route
//! configuration.  A DSR service is an explicitly owned VIP/port tuple and
//! reconciliation never uses the destructive `ipvsadm -C` operation.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::Ipv4Addr, process::Command};

pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_SERVICES: usize = 64;
pub const MAX_BACKENDS: usize = 256;
const SCHEDULERS: &[&str] = &["rr", "wrr", "lc", "wlc", "sh", "dh", "nq", "sed"];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn ipvs_flag(&self) -> &'static str {
        match self {
            Self::Tcp => "-t",
            Self::Udp => "-u",
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub address: Ipv4Addr,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub vip: Ipv4Addr,
    pub port: u16,
    pub protocol: Protocol,
    #[serde(default = "default_scheduler")]
    pub scheduler: String,
    pub backends: Vec<Backend>,
}

fn default_scheduler() -> String {
    "rr".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub services: Vec<Service>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub services: Vec<ServicePlan>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServicePlan {
    pub service: String,
    pub protocol: &'static str,
    pub scheduler: String,
    pub backends: usize,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.services.is_empty(), "services must not be empty");
        ensure!(self.services.len() <= MAX_SERVICES, "too many services");
        let mut services = HashSet::new();
        let mut backend_count = 0usize;
        for service in &self.services {
            ensure!(service.port != 0, "service port must not be zero");
            ensure!(
                !service.vip.is_unspecified() && !service.vip.is_loopback(),
                "VIP must be a non-loopback, non-unspecified IPv4 address"
            );
            ensure!(
                !service.vip.is_multicast() && service.vip != Ipv4Addr::new(255, 255, 255, 255),
                "VIP must not be multicast or broadcast"
            );
            ensure!(
                !service.scheduler.is_empty() && service.scheduler.len() <= 32,
                "scheduler must be 1..32 bytes"
            );
            ensure!(
                SCHEDULERS.contains(&service.scheduler.as_str()),
                "unsupported IPVS scheduler"
            );
            let key = (service.protocol.name(), service.vip, service.port);
            ensure!(services.insert(key), "duplicate protocol/VIP/port service");
            ensure!(!service.backends.is_empty(), "service must have a backend");
            ensure!(service.backends.len() <= MAX_BACKENDS, "too many backends");
            let mut backends = HashSet::new();
            for backend in &service.backends {
                ensure!(backend.port != 0, "backend port must not be zero");
                ensure!(
                    !backend.address.is_unspecified() && !backend.address.is_loopback(),
                    "backend must be a non-loopback, non-unspecified IPv4 address"
                );
                ensure!(
                    !backend.address.is_multicast()
                        && backend.address != Ipv4Addr::new(255, 255, 255, 255),
                    "backend must not be multicast or broadcast"
                );
                ensure!(
                    backend.port == service.port,
                    "direct-routing backend port must equal the virtual service port"
                );
                ensure!(
                    backend.address != service.vip,
                    "backend must not be the virtual service address"
                );
                ensure!(backend.weight <= 1_000_000, "backend weight is too large");
                ensure!(
                    backends.insert((backend.address, backend.port)),
                    "duplicate backend address/port"
                );
            }
            backend_count += service.backends.len();
        }
        ensure!(backend_count <= MAX_BACKENDS, "too many backends total");
        Ok(())
    }

    pub fn plan(&self) -> Plan {
        Plan {
            services: self
                .services
                .iter()
                .map(|s| ServicePlan {
                    service: endpoint(s.vip, s.port),
                    protocol: s.protocol.name(),
                    scheduler: s.scheduler.clone(),
                    backends: s.backends.len(),
                })
                .collect(),
        }
    }
}

fn endpoint(address: Ipv4Addr, port: u16) -> String {
    format!("{address}:{port}")
}

fn capability() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "IPVS direct routing requires Linux"
    );
    ensure!(
        std::path::Path::new("/proc/net/ip_vs").is_file(),
        "kernel IPVS is unavailable: /proc/net/ip_vs is missing"
    );
    let output = Command::new("ipvsadm")
        .arg("--version")
        .output()
        .context("execute ipvsadm")?;
    ensure!(output.status.success(), "ipvsadm is unavailable");
    Ok(())
}

fn command(args: &[&str]) -> Result<std::process::Output> {
    Command::new("ipvsadm")
        .args(args)
        .output()
        .context("execute ipvsadm")
}

fn service_exists(service: &Service) -> Result<bool> {
    let output = command(&["-Ln", "--exact"])?;
    ensure!(
        output.status.success(),
        "ipvsadm list failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(service_exists_text(
        service,
        &String::from_utf8_lossy(&output.stdout),
    ))
}

fn service_exists_text(service: &Service, listing: &str) -> bool {
    let expected = endpoint(service.vip, service.port);
    listing.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.first() == Some(&service.protocol.name())
            && fields.get(1) == Some(&expected.as_str())
    })
}

fn service_matches(service: &Service) -> Result<bool> {
    let output = command(&["-Ln", "--exact"])?;
    ensure!(
        output.status.success(),
        "ipvsadm list failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(service_matches_text(
        service,
        &String::from_utf8_lossy(&output.stdout),
    ))
}

fn service_matches_text(service: &Service, listing: &str) -> bool {
    let expected_service = endpoint(service.vip, service.port);
    let mut found = false;
    let mut scheduler_ok = false;
    let mut destinations = Vec::new();
    for line in listing.lines() {
        let header: Vec<_> = line.split_whitespace().collect();
        if header.first() == Some(&service.protocol.name())
            && header.get(1) == Some(&expected_service.as_str())
        {
            found = true;
            scheduler_ok = header.len() == 3 && header[2] == service.scheduler;
        } else if found && line.trim_start().starts_with("->") {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return false;
            }
            let Ok(weight) = fields[3].parse::<u32>() else {
                return false;
            };
            destinations.push((fields[1].to_string(), fields[2].to_string(), weight));
        } else if found && !line.starts_with(' ') && !line.starts_with('\t') {
            break;
        }
    }
    let expected: HashSet<_> = service
        .backends
        .iter()
        .map(|backend| (endpoint(backend.address, backend.port), backend.weight))
        .collect();
    let actual: HashSet<_> = destinations.into_iter().collect();
    let expected_with_method: HashSet<_> = expected
        .into_iter()
        .map(|(address, weight)| (address, "Route".to_string(), weight))
        .collect();
    found && scheduler_ok && actual == expected_with_method
}

fn delete_service(service: &Service) -> Result<()> {
    if !service_exists(service)? {
        return Ok(());
    }
    let output = command(&[
        "-D",
        service.protocol.ipvs_flag(),
        &endpoint(service.vip, service.port),
    ])?;
    ensure!(
        output.status.success(),
        "could not remove owned service {}: {}",
        endpoint(service.vip, service.port),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn delete_service_force(service: &Service) -> Result<()> {
    if !service_exists(service)? {
        return Ok(());
    }
    let output = command(&[
        "-D",
        service.protocol.ipvs_flag(),
        &endpoint(service.vip, service.port),
    ])?;
    ensure!(
        output.status.success(),
        "could not remove newly created service {}: {}",
        endpoint(service.vip, service.port),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Add only services that are absent. Existing services are refused so an
/// operator cannot accidentally overwrite an unowned IPVS entry. If adding a
/// backend fails, only services created by this invocation are rolled back.
pub fn apply(config: &Config) -> Result<()> {
    config.validate()?;
    capability()?;
    let mut added = Vec::new();
    for service in &config.services {
        let result = (|| -> Result<()> {
            if service_exists(service)? {
                bail!(
                    "owned service {} already exists; inspect it and run cleanup explicitly before reapplying",
                    endpoint(service.vip, service.port)
                );
            }
            let service_address = endpoint(service.vip, service.port);
            let output = command(&[
                "-A",
                service.protocol.ipvs_flag(),
                &service_address,
                "-s",
                &service.scheduler,
            ])?;
            ensure!(
                output.status.success(),
                "could not add owned service {service_address}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            added.push(service.clone());
            for backend in &service.backends {
                let backend_address = endpoint(backend.address, backend.port);
                let weight = backend.weight.to_string();
                let output = command(&[
                    "-a",
                    service.protocol.ipvs_flag(),
                    &service_address,
                    "-r",
                    &backend_address,
                    "-g",
                    "-w",
                    &weight,
                ])?;
                ensure!(
                    output.status.success(),
                    "could not add owned backend {backend_address}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            Ok(())
        })();
        if let Err(error) = result {
            let mut rollback_errors = Vec::new();
            for created in &added {
                if let Err(rollback) = delete_service_force(created) {
                    rollback_errors.push(rollback.to_string());
                }
            }
            if rollback_errors.is_empty() {
                return Err(error);
            }
            bail!(
                "{error}; rollback also failed: {}",
                rollback_errors.join("; ")
            );
        }
    }
    Ok(())
}

/// Remove only the configured VIP/port services. It never clears global IPVS.
pub fn cleanup(config: &Config) -> Result<()> {
    config.validate()?;
    capability()?;
    for service in &config.services {
        ensure!(
            service_matches(service)?,
            "refusing cleanup of {} because the existing service does not exactly match the configured ownership shape",
            endpoint(service.vip, service.port)
        );
    }
    for service in &config.services {
        delete_service(service)?;
    }
    Ok(())
}

pub fn check_runtime() -> Result<()> {
    capability()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(port: u16) -> Service {
        Service {
            vip: Ipv4Addr::new(192, 0, 2, 10),
            port,
            protocol: Protocol::Tcp,
            scheduler: "rr".into(),
            backends: vec![Backend {
                address: Ipv4Addr::new(192, 0, 2, 21),
                port,
                weight: 1,
            }],
        }
    }

    #[test]
    fn listing_matches_exact_port_not_prefix() {
        let one = service(80);
        let listing = "TCP 192.0.2.10:8080 rr\n  -> 192.0.2.21:80 Route 1 0 0\n";
        assert!(!service_exists_text(&one, listing));
        assert!(!service_matches_text(&one, listing));
    }

    #[test]
    fn cleanup_shape_rejects_extra_nat_or_tunnel_destination() {
        let one = service(80);
        let listing =
            "TCP 192.0.2.10:80 rr\n  -> 192.0.2.21:80 Route 1 0 0\n  -> 192.0.2.22:80 Masq 1 0 0\n";
        assert!(!service_matches_text(&one, listing));
        let listing = "TCP 192.0.2.10:80 rr\n  -> 192.0.2.21:80 Tunnel 1 0 0\n";
        assert!(!service_matches_text(&one, listing));
    }

    #[test]
    fn cleanup_shape_requires_scheduler_and_weight() {
        let one = service(80);
        assert!(!service_matches_text(
            &one,
            "TCP 192.0.2.10:80 wrr\n  -> 192.0.2.21:80 Route 1 0 0\n"
        ));
        assert!(!service_matches_text(
            &one,
            "TCP 192.0.2.10:80 rr\n  -> 192.0.2.21:80 Route 2 0 0\n"
        ));
        assert!(!service_matches_text(
            &one,
            "TCP 192.0.2.10:80 rr persistent 50\n  -> 192.0.2.21:80 Route 1 0 0\n"
        ));
        assert!(service_matches_text(
            &one,
            "TCP 192.0.2.10:80 rr\n  -> 192.0.2.21:80 Route 1 0 0\n"
        ));
    }
}
