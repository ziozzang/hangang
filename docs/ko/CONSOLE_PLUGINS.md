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
후 적용합니다. --check는 콘솔 시작 없이 검사합니다. registry·감사 저장소는 비공개입니다.

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
설정은 비공개 regular file(0600)입니다.

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
