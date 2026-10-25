# 유지보수가 끝난 PEM 의존성의 교체

두 Git 의존성의 고정된 원본 코드를 보관하고 필요한 보안 변경만 적용한다. 외부 저장소를 바꾸거나 새 버전을 배포하지 않는다. Cargo의 URL별 patch가 직접·간접 의존성 모두에 적용된다. 패키지 이름과 원본 버전은 유지하며 로컬 변경이라는 사실을 이 문서와 Cargo.lock에 명시한다.

| 패키지 | 원본 |
|---|---|
| hangang-runtime 0.1.2 | https://github.com/ziozzang/hangang-runtime/tree/bf3ba2c0ccfb8603a34b14a30bc52d5112f0677a |
| pumgye-client 0.1.9 | https://github.com/ziozzang/pumgye/tree/98ecfcd5f319c203b35d2e37aee9ce95a040d874/crates/pumgye-client |

공개 API는 유지하고 다음을 바꿨다.

- rustls-pemfile 대신 rustls-pki-types의 PemObject를 사용한다. RUSTSEC-2025-0134의 의존성을 실제로 제거하며 감사 예외를 두지 않는다.
- TLS 자료를 열 때 일반 파일과 1 MiB 상한을 확인한다. Unix에서는 특수 파일 열기를 비차단으로 하고, 읽는 중에도 상한을 검사한다.
- 같은 인증서·키가 정상적으로 읽히는지, 없는 키·큰 파일이 거절되는지, 인증서 압축이 꺼져 있는지 시험한다.
- pumgye-client의 workspace 상속 설정을 원본의 명시 값으로 풀고, pumgye-protocol은 원본과 같은 Git 판으로 연결한다.

원본 src와 Cargo.toml의 SHA-256은 `upstream-sha256.txt`, 원본과의 차이는 `patches/`에 있다. MIT 라이선스를 각 패키지에 함께 보관한다. 원본과 무관한 예제·빌드 산출물은 복사하지 않았다. 상위 저장소에서 같은 수정이 제공되면 이 patch를 없애고 고정 Git 판을 올릴 수 있다.
