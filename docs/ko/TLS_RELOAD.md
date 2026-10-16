# 인증서 무중단 재적재

[문서](../README.ko.md) · [English](../TLS_RELOAD.md)

Hangang은 교체된 인증서와 키를 재시작 없이 바꿉니다. 파일의 **내용**을 폴링합니다. `--tls-reload-seconds`(기본값 10, `0`이면 폴링 끔)마다 참조된 각 파일을 최대 1 MiB까지 읽고 SHA-256 다이제스트를 사용 중인 자료와 비교합니다. inotify 감시를 쓰지 않으므로 `fs.inotify.max_user_instances` 여유가 적은 호스트에도 영향이 없고, 이름 바꾸기, 심볼릭 링크 교체(Kubernetes Secret 및 cert-manager 볼륨), 제자리 쓰기로 바뀐 파일을 모두 같은 방식으로 감지합니다.

## 재적재 대상

| 자료 | 출처 | 유효한 변경 후 |
| --- | --- | --- |
| `public-listener` | `--tls-cert` / `--tls-key` | 새 핸드셰이크가 새 인증서를 사용 |
| `admin-listener` | `--admin-tls-cert` / `--admin-tls-key` | 새 핸드셰이크가 새 인증서를 사용 |
| `upstream-client` | 경로 `auth.native.tls`(Hopae)와 `pumgye_authority.tls`(Pumgye). `--kubernetes-protection-config`에서 컴파일된 Pumgye 권한 서버 포함 | 활성 설정을 바꾸지 않고 다시 준비하여 이 파일들로 만든 모든 클라이언트를 다시 생성 |
| `guard-decision` | `--guard-decision-ca` / `--guard-decision-cert` / `--guard-decision-key` | 네이티브 TCP 및 gRPC 결정 클라이언트를 다시 생성 |

클라이언트 자료의 CA 파일 변경도 같은 방식으로 재적재됩니다. 클라이언트 신원은 CA, 인증서, 키 세 파일을 한 묶음으로 검증하고 다시 생성합니다.

## 원자적 교체

새 rustls 설정은 단일 원자적 포인터 교체로 이전 설정을 대신합니다. 기존 연결은 수립될 때의 설정을 유지하며 끊기지 않습니다. 리스너 연결은 이전 인증서로 끝나고, 풀에 있는 업스트림 또는 guard 연결은 평소의 유휴 및 수명 제한에 따라 은퇴하며, 새 연결은 새 신원을 제시합니다. 처리 중인 요청은 재시도되거나 취소되지 않습니다.

## 검증과 실패

새 자료가 완전하고 일관되기 전에는 아무것도 교체하지 않습니다. 리스너 쌍은 파싱되어야 하고 키가 인증서와 일치해야 합니다. 클라이언트 자료는 추가로 그 CA로 상호 TLS 클라이언트를 만들 수 있어야 합니다. 새 파일이 검증에 실패하거나 읽을 수 없으면 다음과 같습니다.

- 이전 인증서와 키를 계속 사용합니다.
- 실패는 서로 다른 잘못된 내용마다 한 번씩 `warn`(리스너) 또는 `error`(클라이언트 자료)로 기록됩니다.
- `hangang_tls_reload_rejected_total{material}`은 서로 다른 잘못된 내용마다 한 번 증가하고, `hangang_tls_reload_failing{material}`은 유효한 자료나 이미 사용 중인 자료가 다시 디스크에 놓일 때까지 `1`입니다. `hangang_tls_reload_failing == 1`에 경보를 거세요.

인증서와 키를 두 번의 제자리 쓰기로 나누어 쓰면 그 사이가 폴링에 관찰될 수 있습니다. 그 폴링은 거부되고 다음 폴링이 완전한 쌍을 받아들입니다. 원자적 이름 바꾸기나 심볼릭 링크 교체를 권장합니다.

## 관측

성공한 재적재는 새 리프 인증서의 16진수 일련번호와 함께 `info`로 기록되고(`TLS listener certificate reloaded` 또는 `TLS client material reloaded without restart`), `hangang_tls_reloads_total{material}`로 집계됩니다. material 레이블은 위 표의 이름 중 하나입니다.

## 여기서 다루지 않는 것

- Kubernetes TLS Secret(`--kubernetes-tls`), `--config-tls` 인증서 집합, ACME 인증서는 각자의 감시기를 가지며 같은 원자적 방식으로 교체됩니다.
- 경로의 업스트림 서버 CA(`tls.ca_file`)는 설정을 준비할 때 읽습니다. 갱신하려면 설정을 다시 적용하세요([아웃바운드 연결 정책 · 영문](../UPSTREAM.md) 참조).
- Kubernetes API CA와 서비스 계정 토큰은 API 요청마다 다시 읽습니다.
- 네이티브 route owner 리스너와 콘솔 플러그인 클라이언트는 폴링하지 않습니다. 교체하려면 재시작하세요.
