# Linux IPVS 직접 라우팅

[문서 목차](../README.ko.md) · [English](../DSR.md)

`hangang-dsr`는 명시적으로 설계한 Linux 직접 라우팅 네트워크를 운영하기
위한 독립 보조 프로그램입니다. 작고 엄격한 JSON을 검증하고 지정된 IPVS
가상 서비스만 설치하거나 제거합니다. Hangang 라우트 설정을 변경하거나
VIP를 광고하거나 라우트를 설치하거나 ARP를 설정하지 않으며, 상태 점검과
장애 조정기를 제공하지 않습니다.

보조 프로그램에는 Linux IPVS(`/proc/net/ip_vs`)와 `ipvsadm` 실행 파일이
필요합니다. 둘 중 하나라도 없으면 안전하게 중단합니다.

예제 설정은 [examples/dsr/config.json](../../examples/dsr/config.json)입니다.
각 서비스는 하나 이상의 IPv4 실제 서버가 있는 IPv4 VIP·포트·프로토콜
튜플입니다. `tcp`와 `udp`를 지원합니다. 실제 서버는 IPVS 직접 라우팅
(`-g`)으로 사용하며, 네트워크에서 VIP 소유, ARP 억제와 직접 반환 경로를
구성해야 합니다. IP 패킷의 클라이언트 출발지 주소와 VIP 목적지 주소는
그대로 유지되므로, 올바르게 설정한 백엔드는 클라이언트로 직접 응답할 수
있습니다.

IPVS를 변경하지 않고 소유 계획을 검증하고 출력합니다.

```sh
cargo run --locked --bin hangang-dsr -- --config /absolute/private/dsr.json --check
```

설정 파일은 소유자만 읽을 수 있는 일반 파일이어야 합니다.

```sh
install -m 600 /path/to/dsr.json /absolute/private/dsr.json
```

지정한 서비스만 적용하거나 제거합니다.

```sh
cargo run --locked --bin hangang-dsr -- --config /absolute/private/dsr.json --apply
cargo run --locked --bin hangang-dsr -- --config /absolute/private/dsr.json --cleanup
```

JSON 파서는 알 수 없는 필드, 중복 서비스·백엔드, 안전하지 않은 스케줄러
문자열, 루프백·미지정 주소, 0 포트, 과도한 목록과 256KiB 초과 파일을
거부합니다. 설정 경로는 절대 경로이고 일반 파일이어야 하며 소유자만
접근할 수 있어야 합니다. 명령은 검증된 인자 배열로 구성하고 셸 문자열
보간은 사용하지 않습니다. `--apply`는 이미 존재하는 IPVS 서비스를 덮어쓰지
않고 정확히 지정된 VIP 서비스와 실제 서버를 추가하며, 이후 추가가 실패하면
그 실행에서 만든 서비스를 롤백합니다. `--cleanup`은 삭제하기 전에 기존
서비스의 스케줄러, 직접 라우팅 방식, 대상과 가중치가 JSON과 정확히 일치하는지
확인합니다. `ipvsadm -C`는 호출하지 않으며 목록에 없는 서비스는 제거하지
않습니다.

이 보조 프로그램은 ARP 소유, 다중 호스트 라우팅, 엔드포인트 세대 제어,
연결 drain, 상태 전환, IPv6, 단편화, TLS 또는 성능에 대한 운영 준비성을
주장하지 않습니다. UDP는 IPVS를 통해 등록되며 Docker 테스트는 보조
프로그램의 `--apply`와 `--cleanup`으로 TCP와 UDP를 실행하고 출발지 IP와
백엔드 Ethernet 소스 MAC을 확인합니다. IPVS 또는 Docker 네트워크가
노출되지 않으면 진단과 함께 실패합니다. 테스트는 호스트 네트워크,
privileged 컨테이너, 호스트 sysctl과 운영 리소스를 사용하지 않습니다.
보조 프로그램은 한 번 실행하는 설치·제거 도구이므로 운영자는 설정된
VIP/포트 튜플의 쓰기 작업을 직렬화해야 합니다. 변경은 커널 전체를 하나의
트랜잭션으로 처리하지 않습니다. 롤백 실패를 보고하며 운영자가 조정해야
합니다. 외부 동시 작성자나 커널 장애가 발생했을 때 복구를 보장하지 않습니다.

## 검증

```sh
make test-dsr
```

이 대상은 설정 검증을 실행하고 보조 프로그램을 빌드한 뒤 로컬 Docker
Unix 소켓을 통해 `tests/dsr_container.py`를 실행합니다. Linux IPVS, Docker와
Debian 테스트 이미지를 위한 네트워크 접근이 필요합니다. 실행기는 자체
컨테이너와 브리지를 만들고 종료 시 정리합니다. TCP와 UDP의 백엔드 분산과
직접 반환 MAC을 확인하고, 설정 형태와 다른 서비스의 cleanup을 거부하는지,
충돌 뒤 apply 롤백이 동작하는지, 성공적인 cleanup에서 무관한 IPVS 서비스가
보존되는지 검증합니다.

미리 빌드한 정적 보조 프로그램을 사용하려면 다음과 같이 실행합니다.

```sh
HANGANG_DSR_BIN="$PWD/target/x86_64-unknown-linux-gnu/release/hangang-dsr" python3 tests/dsr_container.py
```

직접 라우팅에서는 설정된 전달 경로에서 디렉터와 실제 서버가 계층 2로
도달 가능해야 합니다. 격리된 브리지 테스트가 해당 토폴로지를 검증하며,
라우팅된 다중 호스트나 클라우드 네트워크는 별도로 검증해야 합니다.
