# 호패 gRPC 게이트웨이 클라이언트

[문서](../README.ko.md) · [English](../HOPAE_GRPC.md)

라우트의 `auth.native.transport`를 `grpc`로 설정하고 address를 호패의
`listen.grpc_gateway`로 지정합니다. 기본값은 `native`(HOP1)입니다. 기존 tls의
서버 이름·CA·클라이언트 인증서·키를 설정하며 루프백에서도 mTLS가 필수입니다.
기존 게이트웨이 키를 민감한 Bearer RPC 자격으로 전달합니다. 공급자 코드는
호패가 소유하고 한강은 고정한 hopae-grpc 계약만 의존합니다.

HTTP/2 채널을 재사용하고 pool_size로 동시 처리를 제한합니다. protobuf는
128KiB 이내이며 HOP1의 헤더·본문 크기, 응답 ID·상태·헤더 검사를 적용합니다.
HTTP 상태·반복 쿠키·검증된 신원·서비스 전달 정보는 기존 인증 응답 처리를 따릅니다.
전송 성공만으로 인증 허용을 판단하지 않습니다. HTTP/네이티브 우회나 판정 캐시는
추가하지 않습니다. RPC 제한 시간은 최대 1초이며 라우트의 더 짧은 제한도 적용됩니다.
자격·인증서 교체와 채널 수명은 별도 검증 대상이고 콘솔 SSO는 이번 변경에서 HOP1을 유지합니다.

격리된 호패 시나리오가 실제 한강 클라이언트를 호출하고 두 요청 사이에 세션을 종료합니다.

```sh
cargo build --example hopae_grpc_qualification
HANGANG_HOPAE_GRPC_CLIENT=/absolute/path/to/hangang/target/debug/examples/hopae_grpc_qualification cargo test --manifest-path /absolute/path/to/hopae/Cargo.toml --test scenarios grpc_mtls_session_revocation_and_http_parity
```

전체 한강 요청 체인·K8s 배포·운영 반영은 별도 검증 대상입니다. 스키마 빌드에 protoc가 필요합니다.

## 공용 자격 변환 요청 바인딩 (미릴리스)

공급자와 독립된 호패 계약을 3121f993으로 고정했습니다. 한강의
`projection_binding::digest`는 같은 구현을 사용하며 origin-form
`Request<Bytes>`와 네이티브 서비스/대상을 입력받습니다. 최종 본문 전체를 해시하고
헤더 주장은 범위의 입력으로 쓰지 않습니다. 경로/본문 변환 이후 호출해야 하며
알 수 없는 스트리밍 본문을 빈 바이트로 대체해서는 안 됩니다. 고정 소유자 벡터·
본문/쿼리/범위 변경·모호한 대상 거부 검사가 통과했습니다. 아직 자격 변환
전달 경로에서 호출하지 않으며 receipt RPC·자격 전달은 활성화하지 않습니다.

## 고정 키 인증 receipt 수신 코드 (미릴리스)

계약을 0225145d로 고정합니다. `projection_receipt::IssuerPin`은 네이티브 설정의
발행자·키 세대·공개 키를 검증하고 약한 키를 거부합니다. 공용 계약으로 인증 용도·
서명·현재 네이티브 문맥 바인딩·유효 시간을 확인합니다. 불투명한 결과는 receipt
바이트·체인 해시·만료를 제공하며 권한 또는 자격 출력 근거가 아닙니다.

어댑터는 문맥 원천 인증·최신 키/신원/정책 재검사·시계 단조성·소유자 재사용 방지를
처리해야 합니다. 오래되거나 호출자가 만든 문맥을 넣는 것은 안전해지지 않습니다.
아직 요청 전달·receipt RPC에 연결하지 않았습니다. 실제 서명으로 전체 바이트
변조·문맥/신원 세대/키 세대 변경·만료를 검증했습니다.

## 네이티브 서비스 receipt 클라이언트 (미릴리스)

호패 계약을 0d8d6860으로 고정합니다.
`hopae_native::Client::issue_service_receipt`는 기존 인증된 mTLS gRPC 채널과
공용 처리 용량을 사용하고 1초 기한·응답 2 KiB 제한을 적용합니다. 검증 전용
전송에서는 receipt 요청을 거부하며 HTTP/HOP1 대체 경로를 사용하지 않습니다.
호출자 인증 metadata는 sensitive로 유지합니다.

네이티브 요청 ID/서비스/대상/digest를 대조하고 Service/AAL0·고정 발행자 키의
서명을 검증합니다. 직렬화하지 않는 결과는 서명 문맥·체인 해시·만료를 권한 단계에
전달합니다. 관측한 profile 리비전 이하로 후퇴하지 않으며 시작 시각+단조 경과
시간으로 로컬 벽시계 후퇴가 수락 시간을 연장하지 않게 합니다. 결과 캐시는 없습니다.

범위/서명/만료와 기존 native client 검사·엄격한 Clippy가 통과했습니다. 실제
receipt 서버와의 클라이언트 검증·경로 설정 선택·권한/자격 전달 연결은 아직
남아 있습니다. 키 회전·소유자 신선도·재사용 방지는 별도 필수 경계입니다.
