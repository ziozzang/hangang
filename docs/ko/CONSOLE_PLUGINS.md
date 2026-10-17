# 신뢰 콘솔 패키지와 호패 네이티브 전송

[문서](../README.ko.md) · [English](../CONSOLE_PLUGINS.md)

네이티브 콘솔은 운영자가 설치한 패키지를 ZERO TRUST 사이드바에 불러옵니다.
Guard·Hopae는 각 관리 API와 데이터를 소유하고 Hangang은 콘솔 인증을 소유합니다.
패키지는 동일 출처의 신뢰 JavaScript이며 sandbox가 아닙니다. 검토하지 않은 코드를
설치하지 않습니다. 별도 콘솔 계정 DB를 생성하지 않습니다.
플러그인 화면에는 이름이 연결된 페이지 제목이 있으며 공통 DB-IP 출처 표기 푸터 위에
배치됩니다. 활성 화면 아래에서 출처 링크를 계속 확인할 수 있습니다.

## 패키지 불러오기

Hangang의 --admin-plugins /private/console-plugins.json 또는 기존 네이티브 관리자
앞의 hangang-console --listen 127.0.0.1:19080 --upstream http://127.0.0.1:49000
--plugins /private/console-plugins.json을 사용합니다. 어댑터는 현재 네이티브 UI를 제공하고
설정·계정은 해당 권위에 위임합니다. 공개 평문은 명시적 --allow-insecure-public이
필요합니다. 인증된 TLS 게이트웨이와 직접 접근 제한으로 보호하고 생성된 forwarding
context는 로컬 relay만 제공하도록 합니다.

권위의 관리자 리스너를 TLS 전용(`--admin-tls-cert`/`--admin-tls-key`)으로 두려면 어댑터가
HTTPS로 연결하고 비공개 CA를 신뢰하게 합니다:
`--upstream https://127.0.0.1:49000 --upstream-ca /private/admin-ca.pem`.
`--upstream-ca`를 주면 그 CA(PEM 인증서 1–16개, 최대 64 KiB)만 신뢰하며, 권위의 인증서는
upstream 호스트를 이름으로 가져야 합니다(`127.0.0.1`이면 IP SAN). 파일은 10초마다 다시 읽어
새 연결부터 적용하고, 깨진 파일이면 현재 신뢰를 유지합니다. `--upstream-ca`에는 HTTPS
upstream이 필요합니다. 검증: `tests/console_upstream_tls_smoke.py`.

설정 예제의 pin은 실제 검토한 manifest digest로 교체합니다.

```json
{
  "audit_database": "/private/console-audit.sqlite3",
  "plugins": [
    {"id":"guard","directory":"/opt/console/guard",
     "manifest_sha256":"<reviewed SHA-256>","backend":"http://127.0.0.1:19082",
     "token_env":"CONSOLE_GUARD_TOKEN"},
    {"id":"hopae","directory":"/opt/console/hopae",
     "manifest_sha256":"<reviewed SHA-256>","backend":"http://127.0.0.1:8702",
     "token_env":"CONSOLE_HOPAE_DELEGATION_KEY","delegate_actor":true,
     "delegation_cookie":"__Host-hopae"}
  ]
}
```

각 컴포넌트의 tools/build_console_plugin.py로 패키지를 만들고 manifest.json 해시를
고정합니다. 파일은 group/world 쓰기를 허용하지 않습니다. 제한된 manifest·assets를
해시 검증 후 불변 startup registry에 복사합니다. 수정은 새 pin으로 검증된 reload/restart
후 적용합니다. --check는 콘솔 시작 없이 검사합니다. registry·감사 저장소는 비공개입니다. registry 파일(`--plugins`, `--admin-plugins`)도 아래 SSO
설정과 같은 파일 규칙(프로세스 전용 또는 Kubernetes 볼륨 파일)을 따릅니다.

GET /v1/plugins는 이름·entry만 공개하며 backend origin·자격을 공개하지 않습니다.
GET /ui/plugins/<id>/<asset>는 pin한 목록만 제공합니다. 활성 관리자만 manifest의
명시적 /v1/plugins/<id>/<operation> allowlist를 호출하고 viewer는 거절합니다. 브라우저
자격은 mount에 전달하지 않으며 host API가 현재 권위를 붙입니다. 숨기면 pause하고
로그아웃 시 늦은 async 응답을 포함해 dispose합니다.

공개·로그인·일반·SSE에는 독립 admission·본문 제한·기한이 있습니다. plugin 호출은
별도 한도와 제한된 JSON 응답을 사용합니다. dispatch와 응답 공개 전에 parent 신원을
재검증합니다. 변경 의도/결과·actor·본문 digest를 제한된 비공개 SQLite 감사에 기록하고
원문·비밀값은 제외합니다. 감사 admission 실패 시 dispatch하지 않습니다. 불명확한
결과를 자동 재시도하지 않습니다. backend가 이미 수락한 작업의 회수를 서로 다른
권위 사이에서 원자적으로 보장하지 않습니다.

dispatch한 변경 응답은 parent 권한 회수로 최종 403이 되어도
`x-hangang-plugin-operation`을 유지합니다. 비밀정보가 아닌 이 ID는 이미 수락한
해당 작업만 연결하며 감사 조회 권한이나 재시도 권한을 주지 않습니다. 403은 보호된
backend 본문을 버리고 결과가 불확실함을 알립니다. 비공개 감사에는 이미 commit됐을
수 있는 실제 backend 결과를 유지합니다. dispatch 전 권한 검사에서 거부한 요청에는 새 작업
참조를 부여하지 않습니다.

## 경로와 경로 패턴

매니페스트는 일반 경로 `{"path", "method", "mutation"}`를 나열합니다. `path`는 `/`로
구분한 식별자(영문 소문자, 숫자, `-`, 각 32바이트 이하, 전체 128바이트 이하)이고,
`method`는 `GET`, `POST`, `PUT`, `DELETE`입니다. `GET`은 변경일 수 없고 `PUT`/`DELETE`는
항상 변경입니다. 패키지는 일반 경로를 **64개**까지 선언할 수 있습니다(계약 v2 이전은 32개).
조회는 짧은 문자열의 선형 비교이고 매니페스트는 운영자가 검토하는 64 KiB 이하 파일이므로,
늘어난 한도로도 검토가 현실적이면서 소유자 API를 빠짐없이 내보낼 수 있습니다.

계약 v2(`"api_version": 2`)는 식별자로 지정하는 소유자 API를 위해 제한된 **경로 패턴**을
추가합니다.

```json
"route_patterns": [
  {"path": "zones/*", "method": "GET", "mutation": false},
  {"path": "zones/*", "method": "DELETE", "mutation": true, "max_depth": 1}
]
```

- `path`는 유효한 경로 이름 뒤에 `/*`가 붙은 형태이며, `max_depth`(1–4, 기본 1)는 `*`가
  차지할 수 있는 구간 수입니다. `zones/*`는 `zones/corp`와 일치하고 `zones`, `zones/a/b`
  (깊이 1), `zones/`와는 일치하지 않습니다.
- 일치한 각 구간은 위와 같은 유효한 식별자여야 합니다. `..`, 빈 구간, 퍼센트 인코딩 문자
  (따라서 인코딩된 `/`나 `.`), 대문자, 너무 긴 구간은 일치하지 않습니다. 중계는 경로를
  디코딩하지 않습니다.
- 패턴마다 메서드 하나와 자체 변경 플래그를 정하며 일반 경로와 같은 규칙으로 검증합니다.
  다른 메서드 요청은 `404`입니다. 변경 패턴은 변경 경로와 똑같이 실제 경로로 작업 기록에
  남습니다.
- 일반 경로가 먼저 일치합니다. 패턴 접두사 아래에 같은 메서드의 일반 경로가 있으면(모호함)
  중복 패턴과 마찬가지로 불러올 때 거부됩니다.
- 패턴은 패키지당 16개, 일반 경로와 패턴을 합쳐 64개까지입니다. `api_version: 1`
  매니페스트는 패턴을 선언할 수 없고 의미가 그대로 유지됩니다. 검색 응답은 `routes` 옆에
  `route_patterns`를 나열합니다.

중계는 일치한 요청을 정확히 `<backend>/v1/<path>`로 전달합니다. 위임 패키지의 서명된
수행자 주장은 그 전달 경로, 메서드, 본문 SHA-256에 묶이므로, 주장을 검증하는 백엔드를 다른
자원으로 돌릴 수 없습니다(보안 검토: 경로 혼동 — 식별자만 허용하고 디코딩·정규화 없음,
메서드 밀반입 — 항목당 메서드 하나, `HEAD`/`OPTIONS` 등은 불일치, 변경 플래그 우회 — 플래그는
일치한 항목에서 오며 일반 경로를 패턴이 가릴 수 없음).

## 마운트된 패키지의 언어 수명주기

언어는 호스트가 소유합니다. mount는
`const unsubscribe = context.onLocaleChange?.(() => render(context.locale()));`로
구독할 수 있습니다. 선택적 hook은 mount마다 최대 8개 listener를 허용하고 구독 해제
함수를 반환합니다. pause 중에도 알림을 받으며 abort/로그아웃 시 listener를 제거하고
이전 mount 세대의 callback을 차단합니다. 이벤트 payload를 언어 권위로 사용하지
않습니다. hook 존재를 확인하는 패키지는 기존 호스트도 지원합니다.

언어 callback은 화면 표현만 제자리에서 변경합니다. draft·진행 중 변경·선택 상태·
캐시된 관측 시각을 유지하며 조회 요청·권위 신선도 갱신·remount를 수행하지 않습니다.
호패와 수문장은 이 계약으로 마운트된 label과 상태 합성 문구를 갱신합니다. 브라우저
회귀는 실제 패키지 asset과 모의 소유 API로 검증하며 실제 4개 서비스 배포와 검토된
패키지 pin 적용은 별도 검증이 필요합니다.

실제 패키지 브라우저 검사는 `HANGANG_TEST_HOPAE_PLUGIN`과
`HANGANG_TEST_SUMUNJANG_PLUGIN`에 검토한 패키지 디렉터리를 명시해야 합니다.
누락하면 `plugin_locale.spec.js`는 성공 검증 대신 skip을 표시합니다. 파일 누락·손상과
manifest asset 해시 불일치는 실패합니다. 재현 명령과 검토한 원문 commit은
[영문 문서](../CONSOLE_PLUGINS.md#mounted-package-locale-lifecycle)를 참고하며
실행 증거에는 두 manifest pin을 함께 기록합니다. 패키지 버전은 호패 **0.1.6**,
수문장 **0.1.4**이며 독립 패키지 갱신은 standalone runtime 버전을 변경하지 않습니다.

## 호패 관리와 로그인

기본 native 위임은 Hopae handle 인증·grant/role·assurance·신선도·CSRF·트랜잭션 변경
fence를 유지합니다. Hopae의 HANGANG_NATIVE.md를 참고합니다. 별도 위임 키가
actor ID/name·timestamp·nonce·method/path·본문 digest·handle/client 근거를 서명합니다.
일반 검증 caller key와 다릅니다. provider/session 비밀은 Hopae에 남습니다. 브라우저
모드에는 Hangang admin과 유효한 Hopae admin handle/grant 모두 필요합니다.
Hangang admin 역할만으로 Hopae grant를 생성하지 않습니다.

브라우저 모드에서 Hopae admin origin을 콘솔 origin으로 설정합니다. /_hopae/ 예약
경로를 forward_response:true·terminal_response:true와 요청 cookie/navigation 및
고정 caller-key/contract 헤더로 Hopae에 forward-auth합니다. /_hopae/login·/_hopae/logout
네이티브 handler를 사용하며 Lua로 구현하지 않습니다. 로그아웃 확인·CSRF를 유지하고
Hopae cookie는 앱 upstream 요청에서 제거합니다. 콘솔 API 자격/cookie를 다른 앱에
전달하지 않습니다.

## 네이티브 검증 풀

기존 라우트 external auth에 다음을 추가합니다.

```json
"native": {"address":"127.0.0.1:8703","pool_size":32}
```

auth URL은 /_hopae/verify를 지정해야 합니다. 고정 x-hopae-gateway-key를 설정하고
해당 주소의 Hopae listen.native_gateway를 켭니다. HOP1은 제한된 인증 지속 연결이며
원격에는 mTLS가 필요합니다. 세션 판정 캐시·provider 내장은 없고 실패 시 HTTP fallback/
replay 없이 거절합니다. 두 전송은 동일한 forwarding/result 처리를 사용합니다. idle
socket은 서버 기한 전에 회수하고 취소 시 폐기합니다. 포화는 즉시 거절하며 변경 없는
prepared route는 풀을 재사용합니다.

codec 한도·중복 cookie·잘못되거나 재사용된 ID·키 거절·취소/재연결/포화·실제 세션과
entry parity·native grant 회수·서명 actor 감사·콘솔 lifecycle을 검증합니다. 전체 신원
성능은 배포별 측정이 필요하며 Guard 전송 수치를 Hopae 세션 성능으로 쓰지 않습니다.

예약 Hopae 경로는 넓은 콘솔 /보다 먼저 매칭해야 합니다. 높은 priority를 쓰거나 동일
priority에서 먼저 배치합니다. Hangang은 priority 후 설정 순서이며 자동 최장 prefix가 아닙니다.

## 통합 한강 권위와 SSO

Hangang 로그인/역할을 따르려면 Hopae binding에 delegation_authority:"hangang"을
설정하고 delegation_cookie를 제거합니다. Hopae admin.hangang_delegation.authority도
hangang으로 설정하고 같은 별도 키를 사용합니다. 이 명시적 모드는 기존의 좁은 allowlist에서
서명된 Hangang 관리자 요청만 받습니다. assertion은 권위 모드·요청에 바인딩하며 1회용,
최대 5초이고 변경 트랜잭션에서 다시 확인합니다. 독립 Hopae와 기본 native 모드는 native
grant·세션·신선도·assurance를 유지합니다. 통합 패키지는 별도 로그인/로그아웃 링크를
숨깁니다. 콘솔 권위는 Hangang, provider 자격·신원·세션은 Hopae 소유입니다.

--hopae-sso /private/console-sso.json으로 계정 로그인 아래 SSO 로그인 버튼을 추가합니다.
설정은 비공개 regular file입니다. 콘솔 사용자 소유이고 그룹·기타 권한이 없거나(0600,
0400), `fsGroup`을 쓰는 Kubernetes ConfigMap·Secret 볼륨처럼 root 소유이고 프로세스
그룹 중 하나에 속하며 쓰기·기타 권한이 없어야 합니다(0440, 0400). 누구나 읽거나 쓸 수 있는
파일은 거부합니다. 심볼릭 링크는 Kubernetes atomic writer 구조(`sso.json` ->
`..data/sso.json`, `..data` -> 같은 디렉터리의 `..<version>` 디렉터리)에서만 받고 그 밖의
링크는 거부합니다.

```json
{
  "public_url": "https://console.example.test/",
  "native_address": "127.0.0.1:8703",
  "gateway_key_env": "CONSOLE_HOPAE_GATEWAY_KEY",
  "upstream_token_env": "CONSOLE_HANGANG_SYSTEM_TOKEN",
  "cookie": "__Host-hopae",
  "accounts": {"u_example": "operator"}
}
```

검증되지 않은 이메일/이름 대신 불투명 Hopae user ID를 계정에 매핑합니다. 기존 활성
Hangang 계정만 현재 역할로 로그인하며 계정/특권을 자동 생성하지 않습니다. broker system
자격은 브라우저에 주지 않습니다. Hopae provider login은 /_hopae/login에서 처리하고
native cookie가 /ui/?sso=hopae에 돌아오면 same-origin POST로 불투명 콘솔 bearer로
교환합니다. 브라우저에는 upstream lease/provider token을 주지 않습니다. 모든 SSO 요청은
Hopae cookie·client IP/UA·현재 세션을 검증하고 비공개 5초 lease(재사용 최대 1초)를
얻습니다. Hangang은 로컬 계정/역할도 다시 확인합니다. 로그아웃은 콘솔 세션과 현재
lease를 회수하며 다른 Hopae 앱까지 전역 로그아웃하지 않습니다. 어댑터 재시작은 불투명
SSO 세션을 무효화하며 남아 있는 Hopae 세션으로 다시 로그인합니다. discovery는 provider
이름과 고정 entry URL만 공개합니다.

요청별 회수·same-origin 교환·명시적 매핑·bearer 격리·로컬 계정 disable/만료·브라우저
callback·Hangang 권위의 Hopae 읽기/변경/replay/감사는 테스트로 검증합니다.

원격 HOP1에는 native.tls의 server_name·ca·certificate·key(절대 PEM 경로)를 추가하고
Hopae listen.native_gateway_tls를 켭니다. 고정 native.address만 접속하고 명시적 CA·서버
신원을 검증하며 client 인증서와 ALPN hop1을 사용합니다. TLS 실패 시 평문/HTTP로
fallback하지 않습니다. 연결은 Hopae 300초보다 빠른 240초에 회수합니다. TLS 파일은 변경된
설정을 prepare할 때만 읽으므로 회전 시 native.tls 설정(예: 새 버전 PEM 경로)을 게시합니다.

선택적 콘솔 SSO 설정의 native_tls도 같은 server_name·ca·certificate·key를 지원합니다.
공유 native client·고정 native_address를 사용하고 명시적 Hopae→Hangang 계정 매핑과
세션/lease 검사를 유지합니다. 원격은 mTLS이며 이전 과정의 loopback 평문은 지원합니다.

## 운영자 보증(패스키)과 비상 접근

호패의 `console_operators` 정책(호패 ADR-0021)을 쓰면 콘솔은 운영자가 피싱에 강한
인증 요소로 로그인했는지 요구할 수 있습니다. SSO 설정에 `operator_policy`를 추가하고,
호패 운영자 단언 공개 키(`console_operators.assertion_public_key`)를 그 키 ID
(`console_operators.assertion_key_id`)로 고정합니다.

```json
"operator_policy": {
  "assertion_public_keys": { "op-2026-10": "<base64 Ed25519 공개 키>" },
  "minimum_aal": 2,
  "require_factor": "webauthn",
  "accept_enrollment_grace": false,
  "sensitive_max_age_seconds": 300,
  "step_up_path": "/ui/step-up"
}
```

- 모든 SSO 요청(교환과 이후 각 요청)에는 호패가 전용 Ed25519 키로 서명한 운영자
  단언(`x-hopae-operator-assertion`)이 필요합니다. 콘솔은 공개 키만 가지며, 단언의
  `kid`가 고정된 키를 가리켜야 합니다. 없거나 위조되었거나 만료되었거나 다른
  사용자·호스트의 단언, 또는 고정되지 않은 키의 단언이면 요청을 거부합니다.
- **키 교체.** 현재 키 옆에 다음 키를 고정하고(최대 두 개), 호패를 다음 시드·키 ID·공개
  키로 바꾼 뒤, 이전 키 고정을 지웁니다.
- **로그인과 읽기**에는 단언의 정책 충족(`satisfied`), `minimum_aal`(1–3) 이상, 그리고
  `require_factor: webauthn`이면 패스키가 필요합니다. `accept_enrollment_grace`를 켜면
  호패의 등록 유예로 들어온 운영자도 로그인과 읽기는 할 수 있지만 변경은 할 수 없습니다.
- **모든 변경**에는 유예 없는 정책 충족이 필요합니다. **민감한 변경**(경로에
  `/publish`, `/activate`, `/factors/reset`, `/bulk-disable`가 있거나 `/v1/admin-users`,
  `/v1/users`, `/v1/config`, `/v1/plugins`, `/v1/audit/policy` 아래. `sensitive_paths`로
  목록을 바꿀 수 있음)에는 `sensitive_max_age_seconds`(30–3600) 안에 사용한 인증 요소도
  필요합니다.
- 거부는 `403`과 `operator_step_up_required` 또는 `operator_reauthentication_required`,
  그리고 `step_up_url`로 답합니다. 콘솔 UI는 그곳으로 이동하고, 콘솔 호스트의
  게이트웨이 라우트(`/_hopae/login`처럼 호패가 보호)가 `step_up_path`에서 호패의 패스키
  단계 상승을 실행한 뒤, 콘솔은 원래 화면(`/ui/?sso=hopae`, `/ui/` 안으로만)으로 돌아가
  바뀐 호패 세션으로 다시 로그인합니다. 호패가 직접 단계 상승을 요구하면
  (`x-hopae-reason: step_up_required`) 같은 방식으로 답합니다.
- 헤더는 운영자의 수준과 인증 요소(`AAL2 · 패스키`)를, 로컬 관리자 세션이면
  **비상 접근(로컬)**을 보여 줍니다. `GET /v1/auth/sso/session`도 같은 정보를 돌려줍니다.

**비상 접근.** 로컬 관리자 로그인(`/v1/auth/login`)은 비상 경로로 남습니다.
`--disable-local-login`(`--hopae-sso` 필요)은 이것과 모든 로컬 세션을 거부합니다.

**콘솔 운영자 감사.** 기록: `console.sso_login`(보증 정보 또는 거부),
`console.step_up_required`, `console.change`(수준과 인증 요소가 있는 SSO 변경),
`console.break_glass_login`(`success`, `refused`, `disabled`와 계정),
`console.break_glass_change`, `console.local_login`(콘솔 SSO가 없을 때의 로컬 로그인).
콘솔은 이를 권위의 계정 감사와 분리된 자체 한정 저장소에 둡니다.
`--operator-audit-max-records`(기본 10000, 100–1000000)개까지,
`--operator-audit-retention-days`(기본 90, 1–3650)일보다 오래되지 않은 기록만 남기는
링이며 기록할 때마다 정리합니다. `--operator-audit-db <path>`는 SQLite 파일(0600으로 생성,
심볼릭 링크는 따르지 않음)에 저장하고, 없으면 메모리에 두어 재시작하면 사라집니다.
관리자는 `GET /v1/console/operator-audit?limit=&before=`(최신순, `limit` 1–500, 기본
100, `before`는 이전 페이지의 `next_before` 커서)로 읽고, 통합 감사 화면은 이를 **콘솔
운영자** 출처로 보여 줍니다(콘솔에 이 엔드포인트가 없으면 연결 안 됨).
`--audit-log <path>`(JSON 줄, 0600)는 선택적인 추가 기록처입니다.

검증: `tests/console_operator_aal_smoke.py`(실제 권위와 콘솔, Ed25519 서명 단언
픽스처, 운영자 감사 API), `web/tests/operator_assurance.spec.js`(헤더 배지, 단계 상승
이동, 비상 접근 표시)와 호패의
브라우저 검증(`tools/browser-qual/run-operator.sh`: 실제 호패, 실제 한강 권위와 콘솔,
가상 인증기를 쓰는 Chrome).

## 백엔드 mTLS

바인딩의 tls에 server_name·ca·certificate·key를 설정할 수 있습니다. 파일 경로는
절대 경로이며 읽기 크기를 제한합니다. HTTPS와 DNS 서버 이름이 필수입니다.
Service DNS 백엔드는 호스트와 서버 이름이 일치해야 합니다. 리터럴 IP는 설정한
IP로 연결하면서 지정한 DNS 이름으로 인증서를 검증합니다. 바인딩의 사설 CA는
기본 루트 대신 사용하며 플러그인마다 클라이언트 신원과 연결 풀을 분리합니다.
자격·TLS 경로는 브라우저 발견 응답에 포함하지 않고 TLS/역할 실패에 평문으로
우회하지 않습니다. 이 설정이 없는 기존 HTTPS/리터럴 루프백 HTTP 동작은 유지합니다.

수문장 --management-tls가 대응하는 네이티브 관리 서버를 활성화합니다. 격리된
실제 프로세스에서 고정한 플러그인의 정책 조회·변경을 mTLS로 검증했습니다.
전체 브라우저/K8s 콘솔 적용은 별도 검증 대상입니다.
