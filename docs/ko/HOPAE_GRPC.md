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
