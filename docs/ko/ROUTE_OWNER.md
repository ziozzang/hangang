# 네이티브 라우팅 관측 서비스

[문서](../README.ko.md) · [English](../ROUTE_OWNER.md) · [개요](../../README.ko.md) · [계약](../../crates/hangang-route-grpc/README.ko.md)

선택적인 --route-owner-config가 실제 요청별 네이티브 라우팅 참조를 바탕으로
별도의 읽기 전용 mTLS gRPC 리스너를 시작합니다. 주체의 권한 허가·권한 서명·
upstream 자격 발급을 수행하지 않습니다. 품계로 참조 전달과 permit/투영 경로는
계속 연결해야 합니다.

## 비공개 설정

파일·자격 환경 변수·개인키는 운영자가 통제해야 합니다. 별도의 32–256바이트 표시
가능 ASCII 자격을 쓰며 한강 관리자 자격과 같으면 거부합니다. 문서에 토큰이나
인라인 개인키를 넣지 않습니다. TLS 신원과 클라이언트 CA는 필수입니다.

```json
{
  "listen": "0.0.0.0:19086",
  "certificate": "/private/tls/route.pem",
  "key": "/private/tls/route.key",
  "client_ca": "/private/tls/decision-ca.pem",
  "token_env": "HANGANG_ROUTE_OWNER_TOKEN"
}
```

JSON은 16 KiB로 제한하고 알 수 없는 필드를 거부합니다. 공용 런타임의 TLS 파일
제한을 적용합니다. 다른 프로세스/public HTTP/workload HTTP/TCP 리스너와 주소가
겹치면 거부합니다. 감독 모드는 고정된 0 이외의 포트가 필요합니다.

## 검사와 시작

참조 자격은 비공개 프로세스 환경으로 제공합니다. 검사는 자격·인증서·CA와 선언된
주소 충돌을 확인하되 route 소켓을 열지 않습니다. 따라서 기존 세대가 포트를
보유한 상태에서도 교체 후보를 검사할 수 있습니다.

```sh
hangang --config /private/config.json --route-owner-config /private/route-owner.json --check
hangang --config /private/config.json --route-owner-config /private/route-owner.json --supervised
```

신뢰한 클라이언트 인증서와 별도 Bearer 자격을 모두 요구합니다. 관리자/브라우저
인증으로 fallback하지 않습니다. 제한된 공용 gRPC 런타임을 사용하고 잘못된 자원은
거부합니다.

## 재시작과 종료

감독 프로세스가 별도 타입의 descriptor 역할로 리스너를 전달합니다. 후속 세대는
선언된 정확한 주소를 인계받고 활성화 전에 비공개 자원을 다시 읽습니다. 중복/
예상 밖 역할·필요한 인계 리스너 누락은 거부합니다. 후보가 실패하면 기존 세대가
계속 서비스합니다.

요청별 참조 기록은 인계하지 않습니다. 후속 세대는 새 레지스트리를 가지므로 설정
리비전을 재사용해도 이전 참조가 새 참조가 되지 않습니다. 관측은 시점 정보이며
분산 lease를 만들지 않습니다.

종료 시 관측 태스크를 취소하고 제한된 시간 동안 기다립니다. 예상치 못한 리스너
종료는 readiness를 내리고 기존 게이트웨이 종료 절차를 따릅니다. 실제 프로세스
검사는 단독 시작/종료·바인딩 없는 검사·감독 인계·잘못된 후보 거부를 포함합니다.
로컬 기능 검사이며 K8s·처리량 검증이나 새 운영 릴리스는 아닙니다.
