# 활성화와 비활성화

[문서 목차](../README.ko.md) · [English](../ACTIVATION.md)

HTTP 라우트, TCP 라우트, 파일 인증서 항목, 전역 캐시 정책은 `enabled`를 받습니다. 기본값은 `true`이며 이전 설정 파일과의 호환성을 위해 일반 직렬화에서는 `true`를 생략합니다. `false`는 저장 문서에 남고 reload와 재시작 후에도 유지됩니다. 콘솔은 삭제나 JSON 편집 대신 전용 작업을 제공합니다.

```json
{
  "http": [{
    "id": "shared-site",
    "enabled": false,
    "hosts": ["foo.com", "www.foo.com"],
    "backends": ["http://127.0.0.1:8081"]
  }],
  "tcp": []
}
```

비활성 HTTP 라우트는 매칭이나 본문 검사 전에 건너뜁니다. 정책, 도메인, 백엔드는 설정된 채 남으며 다른 활성 매칭 라우트가 요청을 처리할 수 있습니다. 따라서 라우트 비활성화는 도메인 전체 거부 규칙이 아닙니다. 이미 선택된 요청과 스트림은 완료될 수 있습니다. 비활성 라우트는 새 active-health probe나 Docker discovery 요청을 시작하지 않으며, 진행 중 작업은 새 snapshot을 관찰할 때 완료되거나 취소될 수 있습니다.

비활성 TCP 라우트는 listen 포트를 예약하지 않고 SNI 선택에 참여하지 않습니다. 공유 리스너는 다른 활성 SNI 라우트를 위해 계속 열려 있습니다. 마지막 활성 라우트를 제거하면 기존 스트림이 drain되는 동안 새 연결을 위해 리스너가 닫힙니다. 다시 활성화할 때는 일반적인 리스너 준비 과정을 거칩니다. 다른 프로세스가 포트를 소유하면 activation이 실패하고 이전 설정/revision이 활성 상태로 남습니다. Docker discovery는 재활성화된 Docker 백엔드를 사용할 수 있게 되기 전에 다음 refresh가 필요할 수 있습니다.

비활성 인증서 항목은 해당 인스턴스의 설정된 TLS resolver에서 제외됩니다. 인증서를 revoke하거나 별도 ACME issuer의 갱신을 중지하지 않습니다. 다른 활성/기본 인증서가 선택될 수 있습니다. 인증서 작업은 현재 인스턴스에 영향을 주며 HTTP 전용 인스턴스는 별도 HTTPS 인스턴스의 TLS binding을 바꿀 수 없습니다. 다시 활성화하려면 게시 전에 인증서/키 파일이 검증되어야 합니다.

`cache.enabled`를 `false`로 설정하면 메모리/디스크 한도와 다른 정책은 유지하면서 새 요청에 대한 cache runtime을 비활성화합니다. 다시 활성화하면 그 정책을 복원합니다. 이 작업은 cache purge를 보장하지 않으므로 무효화가 목적이면 purge 작업을 사용하십시오.

모든 변경은 기존 관리자 전용 revision/CAS 쓰기를 사용합니다. viewer 계정은 설정을 전환할 수 없습니다. 비활성 상태에서도 잘못된 메타데이터는 계속 잘못된 값이며 activation은 설정 검증을 우회하는 방법이 아닙니다. Kubernetes 제어 인스턴스는 controller 소유 쓰기 제한을 유지하고, 공유 설정 저장소는 기존 revision 메커니즘으로 이 플래그를 전파합니다.

이전 바이너리는 `enabled:false`를 이해하지 못합니다. rollback에서 이를 조용히 제거하면 트래픽이 다시 활성화될 수 있으므로, 설정을 명시적으로 호환 상태로 만들기 전까지 guarded release 절차가 rollback을 거부합니다.
