# Domain response security

[Documentation](../README.ko.md) · [English](../RESPONSE_SECURITY.md)

관리자 설정 메뉴의 **응답 보안** 규칙에서 명시적인 호스트 패턴, 같은 호스트의 HTTPS 다운그레이드 방지 여부, 보안 헤더 목록을 편집합니다. 규칙을 추가하고 도메인을 선택한 뒤 보수적인 예시를 적용하세요. 규칙은 선택적으로 적용하며 빈 목록은 아무것도 변경하지 않습니다. 기존 리비전 확인 전체 설정 게시 흐름으로 반영합니다.

## Configuration

```json
{
  "settings": {
    "response_security": [{
      "hosts": ["example.test", "www.example.test"],
      "upgrade_same_host_redirect": true,
      "headers": {
        "strict-transport-security": "max-age=300",
        "x-content-type-options": "nosniff",
        "x-frame-options": "SAMEORIGIN",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=(), microphone=(), geolocation=()"
      }
    }]
  }
}
```

프로필은 공개 HTTP 응답의 최종 경계에서 리다이렉트와 초기 정책·인증 거부를 포함한 모든 상태에 적용합니다. 별도 관리자 응답에는 영향을 주지 않습니다. 필수 `hosts`에는 기존 호스트·IP 패턴을 1–16개 지정하며 `*`와 `?`는 호스트 이름의 한 레이블 안에서만 일치합니다. 최대 128개 규칙과 전체 호스트·헤더 텍스트 32 KiB를 허용합니다. 일치하는 프로필은 설정 순서대로 처리합니다. 뒤의 헤더 값이 앞의 값을 대체하며, 일치하는 프로필 중 하나라도 리다이렉트 변경을 활성화하면 적용합니다.

헤더 이름은 대소문자를 구분하지 않으며 `strict-transport-security`, `x-content-type-options`, `referrer-policy`, `x-frame-options`, `content-security-policy`, `content-security-policy-report-only`, `permissions-policy`만 허용합니다. 값은 최대 4,096바이트이며 제어 바이트를 포함할 수 없습니다. 정규화된 헤더 이름의 중복도 거부합니다. `headers` 생략은 빈 객체, `upgrade_same_host_redirect` 생략은 false입니다. 다른 헤더는 기존 응답 헤더 설정으로 관리합니다.

## HTTPS and application compatibility

HSTS는 검증된 HTTPS에서만 전송하며, 설정한 신뢰 프록시의 전달 근거도 포함합니다. 짧은 호스트 전용 `max-age=300` 예시로 시작하세요. `includeSubDomains`와 `preload`는 포함하지 않습니다. 유지 시간을 늘리기 전에 TLS 적용 범위와 애플리케이션 동작을 검토하세요. 게이트웨이는 다른 도메인으로 정책을 자동 확장하지 않습니다.

다운그레이드 방지 체크박스는 요청이 검증된 HTTPS이고, 목적지 호스트 이름이 같으며 HTTP 포트가 기본 80인 절대 `http://` Location만 변경합니다. 외부 호스트, 상대 리다이렉트, 명시적인 비기본 포트는 유지합니다. 들어오는 평문 요청을 처리하는 **TLS 필수**나 정규 도메인 설정을 대체하지 않습니다.

예시는 CSP를 추가하지 않습니다. 운영자가 여기서 CSP를 직접 설정하지 않으면 기존 원본 CSP를 유지하며, 직접 설정하면 해당 헤더를 대체합니다. 실제 애플리케이션 콘텐츠를 기준으로 정책을 검토하세요. 프레임 제한, 브라우저 권한 비활성화, 리퍼러 억제도 연동에 영향을 줄 수 있습니다. 예시는 선택한 도메인 규칙에만 적용하며 그 규칙에 이미 입력한 CSP는 유지합니다.

## Metadata and file exposure

응답 보안 헤더는 애플리케이션 콘텐츠를 제거하지 않습니다. 알려진 메타데이터 엔드포인트나 불필요한 파일은 해당 도메인에 한정하여 [URL 차단](PATH_BLOCKS.md)을 설정하세요. WordPress 배포의 `/readme.html`이나 `/license.txt`가 예입니다. DSM이나 다른 제품의 차단 규칙을 추가하기 전에 실제 애플리케이션 경로를 확인하세요. 차단은 정확한 디렉터리와 슬래시로 구분된 하위 경로에 일치하며 접미사·정규식·제품 이름 일치를 암묵적으로 수행하지 않습니다. 필요한 인증·상태 점검·연동 엔드포인트는 유지하세요.
