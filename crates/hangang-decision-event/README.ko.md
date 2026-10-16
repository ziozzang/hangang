# Hangang Decision Event

[English](README.md) · [한강](../../README.ko.md) · [안내](../../docs/ko/DECISION_EVENTS.md)

제한된 크기의 `hangang.decision.v1` 접근 판단 이벤트 계약(ADR 0019)입니다.
protobuf 스키마(`proto/decision.proto`), 길이 구분 배치 프레이밍, 수신 측 검증,
콘솔 JSON 투영, 영어·한국어 메시지를 가진 안정적인 사유 코드 등록부를 소유합니다.
키, 정책, 저장소는 소유하지 않습니다. 빌드에 `protoc`가 필요합니다.

인코딩된 이벤트는 2 KiB로 제한되며 모든 목록에 고정 최대 길이가 있습니다. 검증은
IP 리터럴 원본, 이메일 주소, 쿼리·인코딩·매개변수가 있는 요청 경로, 자유 형식 사유,
순서가 어긋나거나 중복된 단계, `standard` 프로필이 아닌 봉인 값을 거부합니다. 알 수
없는 열거 값은 받아들이되 허용이 아니라 `unspecified`로 투영합니다. JSON 투영에는
봉인 값이 절대 들어가지 않으며, `without_sealed`는 로컬 저장소가 아닌 싱크로 보낼
사본을 만듭니다.
