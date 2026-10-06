import koDocker from './locales/ko-docker.js';
import koStatic from './locales/ko-static.js';
import koApp from './locales/ko-app.js';
import koConsole from './locales/ko-console.js';
import koOperations from './locales/ko-operations.js';

const STORAGE_KEY = 'hangang-locale';
const urlDefenseKorean = {
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
  "IP Geolocation by DB-IP": "GeoIP 데이터: DB-IP"
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
