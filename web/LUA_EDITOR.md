# Embedded Lua editor

[Documentation](../docs/README.md)

`npm run build:lua-editor` bundles `lua-editor-src.js` into the same-origin
`lua-editor.js` asset. The build appends full MIT notices for CodeMirror and
its bundled dependencies. The server serves this file and `lua-editor.css`
under `/ui/`; there is no CDN, dynamic import from external origins, Lua
execution, or script evaluation in the browser.

`createLuaEditor(textarea, { context, label, onChange, extensions,
completionSources, translateInfo })` keeps the native textarea's value authoritative.
`context` is `policy` or `body`, and only the corresponding Hangang v1 API
members appear after `hangang.`. Basic Lua keywords are also suggested.
Policy completion includes `select_member(configured_member_id)` for an
object-mode route; the member ID is exact and an unknown/unavailable member
fails closed with 503 without retrying elsewhere. Body-transform completion
does not expose routing selectors. Completion never fabricates an ID or
changes a route's configured member list.
`extensions` is an array of CodeMirror extensions and `completionSources`
is an array of CodeMirror completion functions; each has a 16-entry cap.
`translateInfo(english)` may localize only the static completion explanations;
member names and signatures remain exact Lua API spellings.
These optional hooks are for trusted, imported UI code. Never construct them
from route JSON or user Lua. They compose with the built-in completions, so
new provider modules do not need to fork the widget. Host API suggestions
must match the actual worker API in `src/policy.rs`.

For example, a trusted UI module can add a Lua snippet without adding a
fictional `hangang` host function:

```js
const returnSnippet = (context) => {
  const word = context.matchBefore(/ret$/);
  if (!word) return null;
  return {
    from: word.from,
    options: [{ label: 'return nil', apply: 'return nil', type: 'keyword' }],
  };
};
const editor = createLuaEditor(textarea, {
  context: 'policy',
  completionSources: [returnSnippet],
});
```

The returned handle has `destroy()`, `syncFromTextarea()`,
`setDisabled(boolean)`, `setLabel(string)`, `setTranslateInfo(function)`,
and `focus()`. Editor changes
update the textarea and dispatch bubbling `input`, then `change` on blur;
programmatic textarea writes should call `syncFromTextarea()`. Destroy the
handle before removing its form. A response without the required CSP style
nonce leaves the native textarea visible and editable.

CodeMirror's base styles are injected with `EditorView.cspNonce` from the
server-generated `<meta name="csp-nonce">`; this requires a matching
`style-src` nonce while retaining `script-src 'self'`. The separate CSS
asset provides product styling. No `unsafe-inline` or `unsafe-eval` is needed.

## Editing behavior and limits

Open an HTTP route and expand Lua policy, Request body transform, or Response
body transform. `Ctrl` + `Space` (`Alt` + `i` on macOS) opens suggestions, `Ctrl`/`Cmd` + `Z`
undoes, and `Tab` moves focus out of the editor. Body editors follow their
transform enable checkbox. Labels, help and completion explanations follow
the console's English/Korean selection; Lua identifiers are unchanged.

The widget highlights syntax and offers basic completion. It does not provide
semantic diagnostics, a language server, breakpoints, or browser-side Lua
execution. The existing server-side script size, execution and isolation
limits remain authoritative. Changing the UI language preserves the draft;
closing the route dialog or logging out destroys editor state. Draft scripts
are not separately persisted in browser storage.

Valid advanced JSON edits to policy Lua and body-transform settings synchronize
the corresponding native controls, including transform creation/removal, before
a later native edit. Unknown transform keys remain in the JSON basis. Invalid
JSON remains a draft until corrected. This synchronization is scoped to Lua and
body transforms; it does not redesign every existing native/JSON route field.
