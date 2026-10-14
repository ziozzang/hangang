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
