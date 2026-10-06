import koDocker from './locales/ko-docker.js';
import koStatic from './locales/ko-static.js';
import koApp from './locales/ko-app.js';
import koConsole from './locales/ko-console.js';
import koOperations from './locales/ko-operations.js';

const STORAGE_KEY = 'hangang-locale';
const urlDefenseKorean = {
"Response transform literal prefix":"응답 변환 리터럴 접두사",
"Optional exact UTF-8 prefix, at most 1,024 bytes, buffered response transforms only. Blank disables the condition. Whitespace is literal. Nonmatching responses stream unchanged without the transform buffer limit or header edits; matching responses use the configured bounded transform. Range requests and partial responses remain rejected on this route.":"선택적인 정확한 UTF-8 접두사입니다. 최대 1,024바이트이며 버퍼링 응답 변환에서만 사용합니다. 빈 값은 조건을 제거하고 공백은 그대로 비교합니다. 불일치 응답은 변환 버퍼 제한이나 헤더 변경 없이 그대로 스트리밍하며, 일치한 응답은 설정한 제한 안에서 변환합니다. 이 라우트의 Range 요청과 부분 응답은 계속 거부합니다.",
"Literal prefix conditions are allowed only for buffered response transforms.":"리터럴 접두사 조건은 버퍼링 응답 변환에서만 허용합니다.",
"Literal prefix conditions are allowed only for buffered response transforms, at most 1,024 UTF-8 bytes.":"리터럴 접두사 조건은 버퍼링 응답 변환에서만 허용하며 최대 1,024 UTF-8바이트입니다.",

  "Response security": "응답 보안",
  "Response security JSON": "응답 보안 JSON",
  "Add response security rule": "응답 보안 규칙 추가",
  "Response security hosts": "응답 보안 호스트",
  "Required explicit host patterns, one per line. No empty all-host scope.": "호스트 패턴을 한 줄에 하나씩 명시해야 합니다. 빈 목록으로 모든 호스트를 선택할 수 없습니다.",
  "Prevent same-host HTTPS downgrade": "같은 호스트의 HTTPS 다운그레이드 방지",
  "On verified HTTPS, upgrade only absolute http:// redirects to the same hostname and default port. External, relative and nondefault-port redirects remain unchanged.": "검증된 HTTPS 요청에서 같은 호스트·기본 포트의 절대 http:// 리다이렉트만 HTTPS로 바꿉니다. 외부 호스트·상대 경로·비기본 포트는 유지합니다.",
  "Security header lines": "보안 헤더 목록",
  "Allowed: HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy and reviewed CSP or CSP Report-Only. One name: value per line.": "HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy 및 검토한 CSP·CSP Report-Only만 허용합니다. 한 줄에 이름: 값을 입력합니다.",
  "Use conservative security headers": "보수적인 보안 헤더 적용",
  "Remove rule": "규칙 제거",
  "Explicit domain rules cover every response status. HSTS is sent only over verified HTTPS. CSP is never added automatically; configured CSP explicitly replaces the existing policy. The preset applies only to the selected rule.": "명시한 도메인의 모든 응답 상태에 적용합니다. HSTS는 검증된 HTTPS에서만 전송합니다. CSP는 자동 추가하지 않으며, 직접 설정하면 기존 정책을 대체합니다. 예시는 선택한 규칙에만 적용합니다.",
  "Response security must be a valid JSON array.": "응답 보안은 유효한 JSON 배열이어야 합니다.",
  "Response security requires at most 128 rules, 1–16 host patterns per rule, seven allowed security headers with values at most 4,096 bytes, and 32 KiB total text.": "응답 보안은 최대 128개 규칙, 규칙당 1–16개 호스트 패턴, 7종의 허용 헤더와 값당 최대 4,096바이트, 전체 텍스트 32 KiB로 제한됩니다.",

  '{seconds}s ago': '{seconds}초 전',
  'Connection error': '연결 오류',
  'Timed out': '시간 초과',
  'Unavailable for routing': '라우팅 제외',
  'Runtime observation snapshot. Unknown means no observation within 60 seconds; availability for routing is separate from network reachability.': '런타임 관측 상태입니다. 알 수 없음은 최근 60초 내 관측이 없다는 의미이며, 라우팅 허용 여부와 네트워크 연결 여부는 별개입니다.',
  'Reachable': '연결 가능',
  'Unreachable': '연결 불가',
  'Unknown': '알 수 없음',
  'Checking': '확인 중',
  'Draining': '종료 대기',
  'Runtime probe snapshot. Unknown means no verified active probe evidence; availability alone does not prove reachability.': '런타임 검사 상태입니다. 알 수 없음은 검증된 활성 검사 결과가 없다는 의미이며, 요청 허용 여부만으로 연결 가능을 판단하지 않습니다.',

  "Security URL controls": "URL 보안 설정",
  "Blocked URL namespaces": "차단할 URL 경로",
  "URL request rate limits": "URL 요청 속도 제한",
  "URL failure bans": "URL 실패 누적 차단",
  "Failure ban scope": "실패 누적 차단 범위",
  "Default: configured URLs only": "기본값: 설정한 URL만",
  "Configured URLs only": "설정한 URL만",
  "Host: all paths, including images": "호스트: 이미지를 포함한 모든 경로",
  "Global: all public HTTP hosts and paths": "전역: 모든 공개 HTTP 호스트와 경로",
  "Choose URL, host or global failure ban scope.": "URL, 호스트 또는 전역 차단 범위를 선택하세요.",
  "JSON array. Blocks each path and its slash-delimited descendants before routing. Optional hosts restrict the rule; blank removes the setting.": "JSON 배열입니다. 라우팅 전에 해당 경로와 슬래시로 구분되는 하위 경로를 차단합니다. hosts로 적용 호스트를 제한할 수 있습니다. 비우면 설정을 제거합니다.",
  "Failures are counted at the configured URLs. URL scope bans only matching paths; host scope also covers images on that host; global scope covers every public HTTP host and path. The admin listener is exempt.": "설정한 URL에서 실패를 집계합니다. URL 범위는 일치하는 경로만 차단합니다. 호스트 범위는 해당 호스트의 이미지까지 포함하며, 전역 범위는 모든 공개 HTTP 호스트와 경로를 차단합니다. 관리자 리스너는 제외합니다.",
  "Security events use bounded, structured private server logs. These controls do not expose a public debug or event endpoint.": "보안 이벤트는 용량이 제한된 비공개 서버 로그에 구조적으로 기록합니다. 이 설정은 공개 디버그 또는 이벤트 엔드포인트를 제공하지 않습니다.",
  "URL defenses must be valid JSON arrays.": "URL 방어 규칙은 유효한 JSON 배열이어야 합니다.",
  "URL defenses allow at most 128 rules per list.": "URL 방어 규칙은 목록당 최대 128개입니다.",
  "URL defense rule {index}: {detail}": "URL 방어 규칙 {index}: {detail}",
  "Use a rule object with supported fields only.": "지원하는 필드만 포함하는 규칙 객체를 사용하세요.",
  "Use a canonical absolute path of at most 2,048 UTF-8 bytes, without escapes, dot segments, repeated slashes or a trailing slash.": "이스케이프, 점 경로, 반복 슬래시 또는 끝 슬래시가 없는 2,048 UTF-8 바이트 이하의 정규 절대 경로를 사용하세요.",
  "Use at most 16 ASCII hostname or IP patterns, each at most 253 characters. Wildcards * and ? match within one label.": "253자 이하의 ASCII 호스트 이름 또는 IP 패턴을 최대 16개 사용하세요. 와일드카드 *와 ?는 한 레이블 안에서 일치합니다.",
  "include_subpaths must be true or false.": "include_subpaths는 true 또는 false여야 합니다.",
  "{field} must be an integer from 1 to {max}.": "{field}는 1부터 {max}까지의 정수여야 합니다.",
  "statuses must contain 1–16 distinct HTTP status codes from 400 to 599.": "statuses에는 400부터 599까지의 서로 다른 HTTP 상태 코드 1~16개를 입력하세요.",
  "Duplicate URL defense rules are not allowed.": "중복된 URL 방어 규칙은 사용할 수 없습니다.",
  "URL defense paths, hosts and allowlist entries allow at most 32 KiB of UTF-8 text per list.": "URL 방어 경로, 호스트와 허용 목록 항목의 UTF-8 텍스트 합계는 목록당 최대 32 KiB입니다.",
  "{count} configured rules": "설정한 규칙 {count}개",
  "limits allows at most 8 windows with requests 1–1,000,000 and window_seconds 1–86,400.": "limits에는 requests 1~1,000,000, window_seconds 1~86,400 범위의 구간을 최대 8개 입력하세요.",
  "Configure TPS or at least one request window.": "TPS 또는 요청 집계 구간을 하나 이상 설정하세요.",
  "Optional limits apply concurrent request windows, such as 100 requests per minute and 1,000 per day. All matching windows and TPS must allow the request; at least TPS or one window is required.": "limits로 분당 100회, 일당 1,000회처럼 여러 집계 구간을 동시에 제한할 수 있습니다. 일치하는 모든 구간과 TPS 제한을 통과해야 요청을 허용합니다. TPS 또는 구간 하나 이상을 설정해야 합니다.",
  "Current IP bans": "현재 IP 차단",
  "Inspect and release one client IP on this instance. Ban state is local, not distributed. The separate admin listener remains available for recovery.": "이 인스턴스의 클라이언트 IP 차단을 조회하고 개별 해제합니다. 차단 상태는 다른 인스턴스와 공유하지 않습니다. 별도 관리자 리스너는 복구 작업을 위해 접근할 수 있습니다.",
  "Search banned IP": "차단된 IP 검색",
  "Remaining ban time": "남은 차단 시간",
  "IP to release": "해제할 IP",
  "Release IP": "IP 차단 해제",
  "Enter a literal IPv4 or IPv6 address.": "IPv4 또는 IPv6 주소를 입력하세요.",
  "Loading current IP bans…": "현재 IP 차단 조회 중…",
  "Current IP ban data is unavailable.": "현재 IP 차단 정보를 확인할 수 없습니다.",
  "{seconds} seconds remaining": "{seconds}초 남음",
  "This instance · {scope} scope · {count} bans shown": "이 인스턴스 · {scope} 범위 · 차단 {count}건 표시",
  "List truncated. Search a specific IP to inspect its bans.": "목록 일부만 표시합니다. 특정 IP를 검색해 해당 차단을 확인하세요.",
  "No current IP bans in this result.": "이 조회 결과에 현재 차단된 IP가 없습니다.",
  "Release this IP ban?": "이 IP의 차단을 해제할까요?",
  "Release current bans for {ip} on this instance. Other clients are unaffected; future matching failures can ban this IP again.": "이 인스턴스에서 {ip}의 현재 차단을 해제합니다. 다른 클라이언트에는 영향을 주지 않습니다. 이후 실패가 누적되면 다시 차단될 수 있습니다.",
  "Releasing…": "차단 해제 중…",
  "Release completed for {ip}.": "{ip}의 차단 해제 요청을 완료했습니다.",
  "Shared security Redis": "공유 보안 Redis",
  "Security state backend": "보안 상태 저장소",
  "Shared Redis": "공유 Redis",
  "Local state": "로컬 상태",
  "Redis settings require an environment reference HANGANG_SECURITY_REDIS_* and a safe ASCII namespace, each at most 128 characters. Never paste a URL or password.": "Redis 설정에는 HANGANG_SECURITY_REDIS_* 환경 변수 참조와 안전한 ASCII 네임스페이스가 필요하며 각각 최대 128자입니다. URL이나 비밀번호를 붙여 넣지 마세요.",
  "Inspect and release one client IP. The response identifies local or shared Redis state. The separate admin listener remains available for recovery.": "클라이언트 IP의 차단을 조회하고 개별 해제합니다. 조회 결과에 로컬 또는 공유 Redis 상태를 표시합니다. 별도 관리자 리스너는 복구 작업을 위해 접근할 수 있습니다.",
  "Shared Redis · {scope} scope · {count} bans shown": "공유 Redis · {scope} 범위 · 차단 {count}건 표시",
  "Search": "검색",
  "Client IP": "클라이언트 IP",
  "Path": "경로",
  "Stage URL defenses here, then validate and apply the configuration. Limits and bans use local state unless shared Redis is configured; hosts omitted or [] match every host. Canonical paths and bounded rules are required.": "여기서 URL 방어 규칙을 작성한 뒤 구성을 검증하고 적용합니다. 공유 Redis를 설정하지 않으면 속도 제한과 차단 상태는 로컬에서 관리합니다. hosts를 생략하거나 []로 설정하면 모든 호스트에 적용합니다. 정규 경로와 제한 범위에 맞는 규칙을 사용하세요.",
  "JSON array. TPS and burst are shared across matching clients through the configured backend. Exact paths by default; include_subpaths enables descendants. Blank removes the setting.": "JSON 배열입니다. 설정한 저장소를 통해 일치하는 모든 클라이언트가 TPS와 burst 한도를 공유합니다. 기본값은 정확한 경로만 일치하며 include_subpaths로 하위 경로를 포함합니다. 비우면 설정을 제거합니다.",
  "JSON array. Repeated matching response failures temporarily ban the client IP through the configured backend. Default statuses: 401 and 403. Exact paths by default. Blank removes the setting.": "JSON 배열입니다. 일치하는 응답 실패가 누적되면 설정한 저장소를 통해 클라이언트 IP를 일시 차단합니다. 기본 실패 상태는 401과 403입니다. 기본값은 정확한 경로만 일치합니다. 비우면 설정을 제거합니다.",
  "JSON object with an environment variable reference and namespace. Never paste a Redis URL or password. Blank uses local state. Remote plaintext Redis requires explicit allow_insecure_remote: true for an operator-approved private server; the default is false. TLS and loopback plaintext do not need this flag.": "환경 변수 참조와 네임스페이스를 입력하는 JSON 객체입니다. Redis URL이나 비밀번호를 붙여 넣지 마세요. 비우면 로컬 상태를 사용합니다. 원격 평문 Redis는 운영자가 승인한 사설 서버에 대해 allow_insecure_remote: true를 명시해야 하며 기본값은 false입니다. TLS와 루프백 평문 연결에는 이 옵션이 필요하지 않습니다.",
  "URL country and IP allowlists": "URL 국가·IP 허용 목록",
  "JSON array. Exact URLs only by default; include_subpaths enables descendants. At least one allow_cidrs or allow_countries entry is required. When both lists are supplied, the client must match both. Unknown countries are denied; country rules require the GeoIP source configured below. Unmatched image URLs are unaffected.": "JSON 배열입니다. 기본값은 정확한 URL만 일치하며 include_subpaths로 하위 경로를 포함합니다. allow_cidrs 또는 allow_countries를 하나 이상 설정하세요. 두 목록이 모두 있으면 클라이언트가 양쪽을 모두 만족해야 합니다. 국가를 알 수 없으면 거부하며, 국가 규칙에는 아래의 GeoIP 소스 설정이 필요합니다. 일치하지 않는 이미지 URL에는 영향을 주지 않습니다.",
  "Country URL allowlists require a configured GeoIP source. Configure it below before staging country rules.": "URL 국가 허용 목록에는 GeoIP 소스가 필요합니다. 국가 규칙을 작성하기 전에 아래에서 소스를 설정하세요.",
  "allow_cidrs must contain at most 1,024 unique valid IPv4 or IPv6 CIDRs.": "allow_cidrs에는 서로 다른 유효한 IPv4 또는 IPv6 CIDR을 최대 1,024개 입력하세요.",
  "allow_countries must contain at most 256 unique uppercase two-letter country codes.": "allow_countries에는 서로 다른 대문자 두 글자 국가 코드를 최대 256개 입력하세요.",
  "Configure at least one allowed CIDR or country.": "허용할 CIDR 또는 국가를 하나 이상 설정하세요.",
  "Attribution": "출처",
  "IP Geolocation by DB-IP": "GeoIP 데이터: DB-IP",
  "ACME HTTP-01 forwarding": "ACME HTTP-01 전달",
  "Use this domain route for HTTP-01 tokens without a separate challenge route. The external issuer still manages certificates; only the narrow GET challenge path is forwarded.": "별도 챌린지 라우트 없이 이 도메인 라우트로 HTTP-01 토큰을 전달합니다. 인증서는 외부 발급 서버가 계속 관리하며 제한된 GET 챌린지 경로만 전달합니다.",
  "Forward HTTP-01 challenges": "HTTP-01 챌린지 전달",
  "Unchecked removes forwarding. Requires exact domain hosts; wildcard and regular-expression host routes are not supported.": "선택을 해제하면 전달 설정을 제거합니다. 정확한 도메인 호스트가 필요하며 와일드카드·정규식 호스트 라우트는 지원하지 않습니다.",
  "HTTP-01 issuer backend": "HTTP-01 발급 서버 백엔드",
  "http://host[:port] with only a root path, or docker://container/network/port. No credentials, query or fragment. Ordinary application traffic keeps its existing backends.": "루트 경로만 있는 http://host[:port] 또는 docker://container/network/port를 사용합니다. 자격 증명·쿼리·fragment는 허용하지 않습니다. 일반 애플리케이션 요청은 기존 백엔드를 사용합니다.",
  "HTTP-01 listener IDs": "HTTP-01 리스너 ID",
  "Optional: one public listener ID per line, at most 64. Must be a subset of this route’s listener coverage. Blank follows the domain route; no standalone ACME rows are created.": "선택 사항이며 공개 리스너 ID를 한 줄에 하나씩 최대 64개 입력합니다. 이 라우트에 포함된 리스너만 사용할 수 있습니다. 비우면 도메인 라우트의 리스너를 따르며 별도 ACME 행을 만들지 않습니다.",
  "HTTP-01 settings must be an object.": "HTTP-01 설정은 객체여야 합니다.",
  "HTTP-01 forwarding requires exact domain hosts without globs or regular expressions.": "HTTP-01 전달에는 glob·정규식이 없는 정확한 도메인 호스트가 필요합니다.",
  "Use an HTTP root origin or canonical Docker reference for the HTTP-01 issuer, without credentials, query or fragment.": "HTTP-01 발급 서버에는 자격 증명·쿼리·fragment가 없는 HTTP 루트 주소 또는 정규 Docker 참조를 사용하세요.",
  "HTTP-01 listener IDs must be distinct members of this route’s public listener coverage, at most 64.": "HTTP-01 리스너 ID는 이 라우트의 공개 리스너에 포함되어야 하며 중복 없이 최대 64개입니다.",
  "HTTP-01 forwarding cannot be combined with route CIDR denials, country, resource or workload policies. Global URL security still applies.": "HTTP-01 전달은 라우트의 CIDR 거부·국가·리소스·워크로드 정책과 함께 사용할 수 없습니다. 전역 URL 보안은 계속 적용됩니다.",
  "URL CSRF origin policy": "URL CSRF 출처 정책",
  "JSON array. Apply only to selected URLs and methods; default methods are POST, PUT, PATCH and DELETE, so safe GET requests and images are unaffected. Same-origin access is allowed by default, based on the verified gateway authority. Configure exact internal HTTP/HTTPS origins explicitly. Missing Origin uses Referer fallback and otherwise is denied by default; Origin: null is denied. This supplements application CSRF tokens.": "선택한 URL과 메서드에만 적용하는 JSON 배열입니다. 기본 메서드는 POST·PUT·PATCH·DELETE이므로 안전한 GET 요청과 이미지에는 영향을 주지 않습니다. 검증한 게이트웨이 주소를 기준으로 같은 출처를 기본 허용합니다. 내부 HTTP·HTTPS 출처를 정확히 지정할 수 있습니다. Origin이 없으면 Referer를 확인하고, 둘 다 없으면 기본 거부합니다. Origin: null도 거부합니다. 애플리케이션의 CSRF 토큰 검증을 보완하는 정책입니다.",
  "CSRF origin flags must be true or false.": "CSRF 출처 옵션은 true 또는 false여야 합니다.",
  "Use at most 128 distinct exact HTTP or HTTPS root origins, without credentials, query, fragment or globs.": "자격 증명·쿼리·fragment·glob이 없는 서로 다른 정확한 HTTP·HTTPS 루트 출처를 최대 128개 사용하세요.",
  "Enable same-origin access or configure at least one allowed origin.": "같은 출처 접근을 허용하거나 허용 출처를 하나 이상 설정하세요.",
  "CSRF methods require 1–8 distinct uppercase standard methods; CONNECT is not supported.": "CSRF 메서드는 중복 없는 대문자 표준 메서드 1~8개여야 합니다. CONNECT는 지원하지 않습니다.",
  "Keep unrelated services in separate certificate groups. A base domain, its www alias, and its matching wildcard share one management group; wildcard authorization requires DNS-01. A wildcard for an internal namespace can avoid listing individual service names, but publicly trusted certificates, including wildcards, are still published in Certificate Transparency logs.": "관련 없는 서비스는 별도 인증서 그룹으로 나누세요. 기본 도메인, www 별칭, 일치하는 와일드카드는 같은 관리 그룹입니다. 와일드카드 인증에는 DNS-01이 필요합니다. 내부 네임스페이스의 와일드카드는 개별 서비스 이름의 나열을 줄일 수 있지만, 와일드카드를 포함한 공개 신뢰 인증서는 여전히 Certificate Transparency 로그에 게시됩니다.",
  "ACME allow": "ACME 허용",
  "HTTP-01 issuer registration (advanced)": "HTTP-01 발급 서버 등록 (고급)",
  "A registered HTTP-01 issuer is allowed by default. Turn ACME allow off to return 404 without contacting it while keeping registration. Unregistered domains need issuer registration in advanced settings; no endpoint is invented. Wildcards require separate DNS-01 authorization.": "등록한 HTTP-01 발급 서버는 기본 허용합니다. ACME 허용을 끄면 등록 정보를 유지하면서 발급 서버에 접근하지 않고 404를 반환합니다. 미등록 도메인은 고급 설정에서 발급 서버를 등록해야 하며 엔드포인트를 임의로 만들지 않습니다. 와일드카드에는 별도의 DNS-01 인증이 필요합니다.",
  "Controls only this domain route’s registered HTTP-01 challenge namespace. Application traffic and certificate files are unchanged.": "이 도메인 라우트에 등록한 HTTP-01 챌린지 경로의 허용 여부만 설정합니다. 애플리케이션 요청과 인증서 파일은 변경하지 않습니다.",
  "ACME allow must be true or false.": "ACME 허용은 true 또는 false여야 합니다."
};
const korean = { ...koStatic, ...koApp, ...koConsole, ...koOperations, ...koDocker, ...urlDefenseKorean };

function preferredLocale() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'en' || saved === 'ko') return saved;
  } catch (_) { /* Storage may be disabled. */ }
  return String(navigator.language || '').toLowerCase().startsWith('ko') ? 'ko' : 'en';
}

let locale = preferredLocale();
let selectorBound = false;

export function getLocale() { return locale; }

export function t(source, params = {}) {
  const key = String(source);
  const message = locale === 'ko' && Object.hasOwn(korean, key) ? korean[key] : key;
  return message.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (whole, name) =>
    Object.hasOwn(params, name) ? String(params[name]) : whole);
}

function translateStatic() {
  document.documentElement.lang = locale;
  for (const select of document.querySelectorAll('#locale-select, [data-locale-select]')) {
    select.value = locale;
  }
  for (const element of document.querySelectorAll('[data-i18n]')) {
    // Mark only leaves (or wrap a mixed parent's translatable text in a
    // dedicated span). Replacing a parent's children could discard controls.
    if (!element.children.length) element.textContent = t(element.dataset.i18n);
  }
  for (const [attribute, key] of [
    ['aria-label', 'i18nAriaLabel'],
    ['title', 'i18nTitle'],
    ['placeholder', 'i18nPlaceholder'],
  ]) {
    for (const element of document.querySelectorAll(`[data-i18n-${attribute}]`)) {
      element.setAttribute(attribute, t(element.dataset[key]));
    }
  }
}

export function initLocale() {
  if (!selectorBound) {
    document.addEventListener('change', (event) => {
      const select = event.target;
      if (select instanceof HTMLSelectElement && select.matches('#locale-select, [data-locale-select]')) {
        setLocale(select.value);
      }
    });
    selectorBound = true;
  }
  translateStatic();
  return locale;
}

export function setLocale(nextLocale) {
  if (nextLocale !== 'en' && nextLocale !== 'ko') throw new RangeError('Unsupported locale');
  const changed = locale !== nextLocale;
  locale = nextLocale;
  try { localStorage.setItem(STORAGE_KEY, locale); } catch (_) { /* Storage may be disabled. */ }
  translateStatic();
  if (changed) window.dispatchEvent(new CustomEvent('hangang:localechange', { detail: { locale } }));
  return locale;
}

export function formatNumberLocale(value, options) {
  return new Intl.NumberFormat(locale === 'ko' ? 'ko-KR' : 'en-US', options).format(value);
}

export function formatDateLocale(value, options) {
  return new Intl.DateTimeFormat(locale === 'ko' ? 'ko-KR' : 'en-US', options).format(value);
}
