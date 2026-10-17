//! Stable reason-code registry with EN/KO messages (ADR 0019/0020).
//!
//! Codes are append-only. Renaming or removing a code is a breaking change;
//! adding one requires a schema minor version and both messages.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Allow,
    Deny,
    Challenge,
    Error,
    Unavailable,
}

#[derive(Debug, Clone, Copy)]
pub struct Reason {
    pub code: &'static str,
    pub class: Class,
    pub en: &'static str,
    pub ko: &'static str,
}

macro_rules! reasons {
    ($(($code:literal, $class:ident, $en:literal, $ko:literal)),* $(,)?) => {
        pub const REGISTRY: &[Reason] = &[
            $(Reason { code: $code, class: Class::$class, en: $en, ko: $ko }),*
        ];
    };
}

reasons![
    // Network (Sumunjang).
    (
        "sumunjang.network_denied",
        Deny,
        "Sumunjang refused the client network.",
        "수문장이 클라이언트 네트워크를 거부했습니다."
    ),
    (
        "sumunjang.unavailable",
        Unavailable,
        "Sumunjang network evidence was unavailable and the gateway failed closed.",
        "수문장 네트워크 판단을 받을 수 없어 게이트웨이가 차단했습니다."
    ),
    // Identity (Hopae or the configured authentication service).
    (
        "hopae.authentication_required",
        Challenge,
        "Authentication is required.",
        "인증이 필요합니다."
    ),
    (
        "hopae.authentication_redirect",
        Challenge,
        "The client was sent to sign in.",
        "로그인 페이지로 안내했습니다."
    ),
    (
        "hopae.authentication_denied",
        Deny,
        "The identity provider refused the request.",
        "인증 기관이 요청을 거부했습니다."
    ),
    (
        "hopae.unavailable",
        Unavailable,
        "The authentication authority was unavailable.",
        "인증 기관에 연결할 수 없었습니다."
    ),
    (
        "hopae.native_context_unavailable",
        Unavailable,
        "Native authentication context could not be prepared.",
        "네이티브 인증 문맥을 준비할 수 없었습니다."
    ),
    // Authorization (Pumgye): exact pumgye_core::Decision variants.
    (
        "pumgye.unknown_service",
        Deny,
        "The service is not defined in Pumgye policy.",
        "품계 정책에 정의되지 않은 서비스입니다."
    ),
    (
        "pumgye.guest",
        Deny,
        "The subject has no assignment for this service.",
        "이 서비스에 대한 할당이 없는 주체입니다."
    ),
    (
        "pumgye.network_guest",
        Deny,
        "The client network is not permitted for this service.",
        "이 서비스에 허용되지 않은 네트워크입니다."
    ),
    (
        "pumgye.permission_denied",
        Deny,
        "No assigned role grants the required permission.",
        "필요한 권한을 부여하는 역할이 없습니다."
    ),
    (
        "pumgye.class_denied",
        Deny,
        "No assigned role may access this information class.",
        "이 정보 등급에 접근할 수 있는 역할이 없습니다."
    ),
    (
        "pumgye.assurance_denied",
        Deny,
        "The authentication assurance level is too low.",
        "인증 보증 수준(AAL)이 부족합니다."
    ),
    (
        "pumgye.guard_denied",
        Deny,
        "Pumgye refused because Sumunjang denied the network.",
        "수문장이 네트워크를 거부하여 품계가 거부했습니다."
    ),
    (
        "pumgye.guard_unavailable",
        Unavailable,
        "Pumgye refused because network evidence was unavailable.",
        "네트워크 판단을 받을 수 없어 품계가 거부했습니다."
    ),
    (
        "pumgye.unknown_resource",
        Deny,
        "The resource is not defined in Pumgye policy.",
        "품계 정책에 정의되지 않은 리소스입니다."
    ),
    (
        "pumgye.unknown_action",
        Deny,
        "The action is not defined for this resource.",
        "이 리소스에 정의되지 않은 동작입니다."
    ),
    (
        "pumgye.method_not_mapped",
        Deny,
        "The HTTP method is not mapped to a Pumgye permission.",
        "HTTP 메서드가 품계 권한에 연결되어 있지 않습니다."
    ),
    (
        "pumgye.identity_missing",
        Deny,
        "No authenticated identity was available for authorization.",
        "권한 판단에 사용할 인증된 주체가 없습니다."
    ),
    (
        "pumgye.unavailable",
        Unavailable,
        "The Pumgye authority was unavailable.",
        "품계 권한 기관에 연결할 수 없었습니다."
    ),
    // Hangang enforcement and gateway-owned policy.
    (
        "hangang.allowed",
        Allow,
        "The request was allowed and forwarded.",
        "요청이 허용되어 전달되었습니다."
    ),
    (
        "hangang.redirected",
        Allow,
        "The request was redirected by route policy.",
        "경로 정책에 따라 리다이렉트되었습니다."
    ),
    (
        "hangang.ip_banned",
        Deny,
        "The client address is temporarily banned.",
        "클라이언트 주소가 일시적으로 차단되었습니다."
    ),
    (
        "hangang.url_not_allowlisted",
        Deny,
        "The URL is outside the route allowlist.",
        "경로 허용 목록에 없는 URL입니다."
    ),
    (
        "hangang.rate_limited",
        Deny,
        "The request exceeded a rate limit.",
        "요청 한도를 초과했습니다."
    ),
    (
        "hangang.request_blocked",
        Deny,
        "The request matched a request block rule.",
        "요청 차단 규칙에 해당했습니다."
    ),
    (
        "hangang.resource_namespace_refused",
        Deny,
        "The path is reserved for another protected resource.",
        "다른 보호 리소스에 예약된 경로입니다."
    ),
    (
        "hangang.workload_denied",
        Deny,
        "The workload identity is not allowed on this route.",
        "이 경로에 허용되지 않은 워크로드 신원입니다."
    ),
    (
        "hangang.jwt_denied",
        Challenge,
        "A valid bearer token is required.",
        "유효한 Bearer 토큰이 필요합니다."
    ),
    (
        "hangang.basic_denied",
        Challenge,
        "Valid basic credentials are required.",
        "유효한 기본 인증 정보가 필요합니다."
    ),
    (
        "hangang.resource_policy_denied",
        Deny,
        "The resource policy does not allow this principal.",
        "리소스 정책이 이 주체를 허용하지 않습니다."
    ),
    (
        "hangang.service_scope_mismatch",
        Deny,
        "The service identity is not bound to this route's permission gate.",
        "서비스 신원이 이 경로의 권한 게이트에 연결되어 있지 않습니다."
    ),
    (
        "hangang.native_permission_denied",
        Deny,
        "The native resource permit was refused.",
        "네이티브 리소스 허가가 거부되었습니다."
    ),
    (
        "hangang.native_unavailable",
        Unavailable,
        "The native resource authority was unavailable.",
        "네이티브 리소스 권한 기관에 연결할 수 없었습니다."
    ),
    (
        "hangang.authorization_retired",
        Unavailable,
        "The route's authorization changed while the request was in flight.",
        "요청 처리 중 경로 권한 설정이 바뀌었습니다."
    ),
    (
        "hangang.route_authorization_unavailable",
        Unavailable,
        "The route's authorization could not be prepared on this node.",
        "이 노드에서 경로 권한 설정을 준비할 수 없었습니다."
    ),
    (
        "hangang.upstream_unavailable",
        Error,
        "No upstream was available after authorization.",
        "권한 확인 후 사용할 수 있는 업스트림이 없었습니다."
    ),
    (
        "hangang.refused",
        Deny,
        "The gateway refused the request.",
        "게이트웨이가 요청을 거부했습니다."
    ),
    (
        "hangang.error",
        Error,
        "The gateway failed while processing the request.",
        "게이트웨이가 요청 처리 중 실패했습니다."
    ),
    (
        "hangang.suppressed",
        Deny,
        "Repeated refusals were summarized by the event rate limit.",
        "반복된 거부가 이벤트 한도에 따라 요약되었습니다."
    ),
];

pub fn lookup(code: &str) -> Option<&'static Reason> {
    REGISTRY.iter().find(|reason| reason.code == code)
}

/// Console message key; unregistered codes from a newer emitter map to the
/// generic unknown-reason key and are displayed with the raw code.
pub fn message_key(code: &str) -> String {
    if lookup(code).is_some() {
        format!("decision.reason.{code}")
    } else {
        "decision.reason.unknown".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_unique_valid_and_bilingual() {
        let mut seen = std::collections::BTreeSet::new();
        for reason in REGISTRY {
            assert!(crate::valid_reason(reason.code), "{}", reason.code);
            assert!(seen.insert(reason.code), "duplicate {}", reason.code);
            assert!(!reason.en.is_empty() && reason.en.is_ascii());
            assert!(
                reason
                    .ko
                    .chars()
                    .any(|c| ('\u{ac00}'..='\u{d7a3}').contains(&c)),
                "missing Korean for {}",
                reason.code
            );
        }
    }

    #[test]
    fn every_pumgye_decision_variant_has_a_reason() {
        use crate::v1::AuthorizationDecision as D;
        for variant in [
            D::UnknownService,
            D::Guest,
            D::NetworkGuest,
            D::PermissionDenied,
            D::ClassDenied,
            D::AssuranceDenied,
            D::GuardDenied,
            D::GuardUnavailable,
            D::UnknownResource,
            D::UnknownAction,
            D::Unavailable,
        ] {
            let name = crate::authorization_text(variant as i32);
            let mut code = String::from("pumgye.");
            for (index, ch) in name.chars().enumerate() {
                if ch.is_ascii_uppercase() && index > 0 {
                    code.push('_');
                }
                code.push(ch.to_ascii_lowercase());
            }
            assert!(lookup(&code).is_some(), "{code}");
        }
    }
}
