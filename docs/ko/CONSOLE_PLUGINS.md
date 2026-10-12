# 콘솔 패키지와 Hopae 네이티브 전송

[English](../CONSOLE_PLUGINS.md)

Hangang의 ZERO TRUST 메뉴에 Guard·Hopae 관리 패키지를 불러옵니다.
동일 출처의 신뢰된 JavaScript이므로 패키지를 검토하고 해시를 고정해야 합니다.
각 서비스의 데이터/변경 권한은 유지하고 콘솔 계정은 Hangang에 위임합니다.

`--admin-plugins`로 설정하거나 `hangang-console` 어댑터를 기존 관리자 API 앞에 배치합니다.
공개 평문 리스닝은 `--allow-insecure-public`이 필요하며 TLS 게이트웨이와 직접 접근 제한을
적용합니다. 생성된 전달 헤더는 로컬 relay에서만 신뢰합니다. 설정 예제는 영어 원문을 참고하세요.
각 서비스의 `tools/build_console_plugin.py`로 패키지를 만들고 manifest SHA-256을 고정합니다.
파일은 그룹/전체 쓰기가 불가능해야 하며 시작 때 크기·해시를 검증해 불변 메모리로 적재합니다.

백엔드 주소/키는 discovery나 mount 객체로 노출하지 않습니다. 활성 관리자만 등록된 API를
사용하고 viewer는 거부합니다. 화면을 숨기면 polling을 중단하고 로그아웃 시 늦은 응답까지
폐기합니다. 요청 종류별 admission, 본문/응답 한도와 기한을 적용합니다.
변경 전 영속 감사 의도와 작업자·본문 해시를 기록하고 결과를 남깁니다. 감사 수락 실패 시
전달하지 않으며, 불확실한 변경은 자동 재시도하지 않습니다. 이미 수락된 백엔드 변경의 회수를
서로 다른 서비스 간 원자적으로 보장하지는 않습니다.

Hopae 관리 위임은 전용 키로 작업자·시각·nonce·메서드/경로·본문 해시와 handle/클라이언트
근거를 서명합니다. 기존 Hopae handle·grant·역할·인증 강도·freshness·CSRF·변경 fence를
유지합니다. Hangang 관리자 역할만으로 Hopae grant를 만들지 않습니다.
브라우저 방식은 두 권한을 모두 요구합니다. Hopae 관리자 origin을 콘솔 origin에 맞추고
`/_hopae/`를 forward-auth로 연결합니다. 로그인/로그아웃은 네이티브 엔트리를 사용하며
Lua가 필요하지 않습니다. 로그아웃 확인/CSRF를 유지하고 앱 upstream에는 Hopae 쿠키를 제거합니다.

외부 인증 설정에 `native:{address:"127.0.0.1:8703",pool_size:32}`를 추가하면 HOP1 지속 연결을
사용합니다. URL은 `/_hopae/verify`, static caller key와 Hopae native listener가 필요합니다.
풀은 1–256, loopback만 허용합니다. 판단 캐시·HTTP 자동 fallback은 없으며 실패는 fail-closed입니다.
취소된 연결은 폐기하고 포화 시 즉시 거부합니다. 프로바이더 코드는 Hopae에 유지합니다.

코덱·쿠키 중복·잘못된/재사용 ID·키 거부·취소·재연결·포화·실제 세션 및 엔트리 parity·
grant 회수·위임 감사·콘솔 수명주기를 검증합니다. Hopae 전체 처리량은 별도 환경 부하 검증이
필요하며 Guard transport 수치를 그대로 가져오지 않습니다.
