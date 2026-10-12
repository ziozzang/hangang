//! Route-owned scope for the embedded authorization manager.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub service_id: String,
    pub information_class: String,
    pub permissions: BTreeMap<String, Vec<String>>,
}
impl Gate {
    pub fn validate(&self, policy: &pumgye_core::Policy) -> Result<()> {
        let service = policy
            .services
            .get(&self.service_id)
            .ok_or_else(|| anyhow::anyhow!("unknown Pumgye service"))?;
        ensure!(
            policy.information_classes.contains(&self.information_class),
            "unknown information class"
        );
        ensure!(
            !self.permissions.is_empty() && self.permissions.len() <= 16,
            "invalid method count"
        );
        for (method, permissions) in &self.permissions {
            ensure!(
                !method.is_empty()
                    && method.len() <= 32
                    && method.bytes().all(|b| b.is_ascii_uppercase()),
                "invalid permission method"
            );
            ensure!(
                !permissions.is_empty() && permissions.len() <= 64,
                "invalid permissions"
            );
            let mut seen = std::collections::BTreeSet::new();
            for permission in permissions {
                ensure!(
                    service.permissions.contains(permission) && seen.insert(permission),
                    "unknown or duplicate permission"
                );
            }
        }
        Ok(())
    }
}

/// Only call with authenticated native Hopae response headers.
pub fn identity(headers: &hyper::HeaderMap) -> Option<(&str, u8)> {
    let mut subjects = headers.get_all("x-forwarded-user").iter();
    let subject = subjects.next()?.to_str().ok()?;
    if subjects.next().is_some() || subject.is_empty() {
        return None;
    }
    let mut assurances = headers.get_all("x-hopae-aal").iter();
    let assurance = match assurances.next()?.as_bytes() {
        b"1" => 1,
        b"2" => 2,
        b"3" => 3,
        _ => return None,
    };
    if assurances.next().is_some() {
        return None;
    }
    Some((subject, assurance))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_scope_rejects_undefined_rights_and_empty_methods() {
        let policy: pumgye_core::Policy = serde_json::from_value(serde_json::json!({
            "version":1,"information_classes":["internal"],"services":{"orders":{
                "permissions":["read"],"roles":{},"users":{},"networks":[]
            }}
        }))
        .unwrap();
        let mut gate = Gate {
            service_id: "orders".into(),
            information_class: "internal".into(),
            permissions: BTreeMap::from([("GET".into(), vec!["read".into()])]),
        };
        assert!(gate.validate(&policy).is_ok());
        gate.permissions.insert("POST".into(), vec!["write".into()]);
        assert!(gate.validate(&policy).is_err());
        gate.permissions.remove("POST");
        gate.information_class = "unknown".into();
        assert!(gate.validate(&policy).is_err());
        gate.information_class = "internal".into();
        gate.permissions.clear();
        assert!(gate.validate(&policy).is_err());
    }
}
