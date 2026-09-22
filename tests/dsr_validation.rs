use hangang::dsr::{Config, Protocol};
use std::net::Ipv4Addr;

fn valid() -> Config {
    serde_json::from_value(serde_json::json!({
        "services": [{"vip":"192.0.2.10","port":443,"protocol":"tcp",
          "scheduler":"rr","backends":[{"address":"192.0.2.21","port":443}]}]
    }))
    .unwrap()
}

#[test]
fn validates_direct_routing_service() {
    let config = valid();
    config.validate().unwrap();
    assert_eq!(config.services[0].protocol, Protocol::Tcp);
    assert_eq!(config.plan().services[0].service, "192.0.2.10:443");
}

#[test]
fn rejects_duplicate_owned_service() {
    let mut config = valid();
    config.services.push(config.services[0].clone());
    assert!(config.validate().is_err());
}

#[test]
fn rejects_unsafe_or_ambiguous_values() {
    let mut config = valid();
    config.services[0].vip = Ipv4Addr::LOCALHOST;
    assert!(config.validate().is_err());
    let mut config = valid();
    config.services[0].scheduler = "rr; rm -rf /".into();
    assert!(config.validate().is_err());
    let mut config = valid();
    config.services[0].backends[0].port = 8443;
    assert!(config.validate().is_err());
}

#[test]
fn accepts_udp_as_a_separate_owned_service() {
    let mut config = valid();
    config.services[0].protocol = Protocol::Udp;
    config.validate().unwrap();
}
