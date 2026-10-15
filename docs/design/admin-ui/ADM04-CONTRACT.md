# ADM04 bounded host navigation contract

Status: implementation candidate based on c5610e0; not released or deployed.

The host owns the Zero Trust group and functional names, with stable order
Identity · Hopae, Network trust · Sumunjang, Authorization · Pumgye. Discovery
cannot choose this ordering or rename these known capabilities. Preserve view IDs
`plugin-hopae`, `plugin-guard`, `pumgye` and old hashes. Unknown installed trusted
plugins follow known authorities deterministically by stable ID; no future or
uninstalled capability is fabricated. Discovery duplicates refuse atomically.

Pumgye remains the built-in capability (including existing embedded-policy mode); no remote-authority configuration is fabricated. Discovery accepts at most128 unique entries and validates all entries before publishing any.

Current authorization is unchanged: only administrators discover/mount plugins
or enter Pumgye; viewers retain Status only. Route parsing is presentation only;
every destination continues to load using the session-bound host API. Uninstalled
plugin routes never import modules. Logout abort/dispose and lazy mount,
pause/resume, late-response generation fences remain intact.

This batch adds validated host view hashes/history and host-owned Pumgye section
anchors `#pumgye/services`, `#pumgye/resources`, `#pumgye/policy` onto existing rendered content. These are section locations, not independent business pages. Unknown sections canonicalize to the module root. Plugin internal tabs are not
invented by the host: without an explicit compatible adapter, slash destinations
must normalize explicitly to the installed module root rather than silently claim
the requested tab. No user-provided module URL, API path, credential or query is
accepted as routing metadata. Existing top-level hashes remain compatible.

English primary labels and Korean labels/search aliases cover products and
functions, including Guard. Active links expose aria-current. Localized command search includes the three administrator-only section destinations. Preserve mobile
layout, ordinary anchor keyboard behavior, command-search keyboard navigation,
and existing plugin lifecycle tests. Test shuffled/duplicate discovery, absent
plugins, anonymous/viewer deep links, refresh/Back/Forward, locale/search and
session cleanup. No business API, backend authorization or provider changes.

## 한국어

호스트가 신원 · 호패, 네트워크 신뢰 · 수문장, 권한 · 품계의 순서와 표시명을
소유한다. 설치·관리자 권한이 확인된 모듈만 표시하며 기존 ID와 주소를 보존한다.
주소는 권한이 아니며 목적지는 기존 세션 API로 다시 권한 검사를 받는다.
플러그인 내부 탭은 명시적 어댑터 없이 호스트에서 실행하지 않는다. 이 범위는
메뉴와 안전한 주소/기록 처리이며 전체 하위 페이지나 ADM06/09 완료 주장이 아니다.
