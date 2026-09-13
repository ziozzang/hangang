// Source for the locally bundled CodeMirror editor. Build with npm run build:lua-editor.
// The textarea remains the authoritative form value; no user Lua is run here.
import { Compartment, EditorSelection, EditorState } from '@codemirror/state';
import {
  EditorView, drawSelection, highlightActiveLine, highlightActiveLineGutter,
  highlightSpecialChars, keymap, lineNumbers,
} from '@codemirror/view';
import { bracketMatching, HighlightStyle, StreamLanguage, syntaxHighlighting } from '@codemirror/language';
import { lua } from '@codemirror/legacy-modes/mode/lua';
import { autocompletion, closeBrackets, closeBracketsKeymap, closeCompletion, completionKeymap } from '@codemirror/autocomplete';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { tags } from '@lezer/highlight';

const policyMembers = [
  ['api_version', 'number', 'Current Hangang Lua API version (1).'],
  ['header', '(name)', 'Read one request header value or nil.'],
  ['method', '()', 'Read the request method.'],
  ['path', '()', 'Read the request path.'],
  ['select_backend', '(configured_backend_url)', 'Select a backend already configured on this route.'],
  ['set_header', '(name, value)', 'Set an application request header; authenticator-owned identity names are reserved.'],
  ['reject', '(status_400_to_599)', 'Reject this request with a 4xx or 5xx status.'],
];
const bodyMembers = [
  ['api_version', 'number', 'Current Hangang Lua API version (1).'],
  ['body', '()', 'Read the bounded complete body or record as a binary-safe string.'],
  ['phase', '()', 'Return request or response.'],
  ['set_body', '(bytes)', 'Set the bounded output body.'],
  ['json_decode', '(bytes)', 'Decode JSON, preserving Hangang null and empty-array sentinels.'],
  ['json_encode', '(value)', 'Encode a bounded Lua JSON value.'],
  ['null', 'value', 'JSON null sentinel; Lua nil removes a table field.'],
  ['array', '()', 'Create an empty JSON array.'],
];
const luaKeywords = [
  'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function',
  'goto', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat', 'return',
  'then', 'true', 'until', 'while',
].map((label) => ({ label, type: 'keyword' }));

function memberCompletions(members, translateInfo) {
  return members.map(([label, signature, info]) => ({
    label,
    detail: signature,
    info: translateInfo(info),
    type: signature === 'number' || signature === 'value' ? 'property' : 'function',
    apply(view, _completion, from, to) {
      const inserted = signature === 'number' || signature === 'value'
        ? label
        : `${label}()`;
      const cursor = signature === 'number' || signature === 'value'
        ? inserted.length : inserted.length - 1;
      view.dispatch({
        changes: { from, to, insert: inserted },
        selection: EditorSelection.cursor(from + cursor),
      });
    },
  }));
}

function hostCompletions(context, members, translateInfo) {
  const line = context.state.doc.lineAt(context.pos);
  const before = line.text.slice(0, context.pos - line.from);
  const match = /(?:^|[^\w])hangang\.([A-Za-z_]*)$/.exec(before);
  if (match) {
    return {
      from: context.pos - match[1].length,
      options: memberCompletions(members, translateInfo),
      validFor: /^[A-Za-z_]*$/,
    };
  }
  if (!context.explicit) return null;
  const word = context.matchBefore(/[A-Za-z_]*$/);
  if (!word || !'hangang'.startsWith(word.text)) return null;
  return {
    from: word.from,
    options: [{ label: 'hangang', type: 'variable', info: translateInfo('The bounded Hangang host API.') }],
    validFor: /^[A-Za-z_]*$/,
  };
}

function keywordCompletions(context, translateInfo) {
  const line = context.state.doc.lineAt(context.pos);
  const before = line.text.slice(0, context.pos - line.from);
  if (/hangang\.[A-Za-z_]*$/.test(before)) return null;
  const word = context.matchBefore(/[A-Za-z_]*$/);
  if (!word || (!context.explicit && word.text.length < 2)) return null;
  return {
    from: word.from,
    options: [...luaKeywords, {
      label: 'hangang',
      type: 'variable',
      info: translateInfo('The bounded Hangang host API.'),
    }],
    validFor: /^[A-Za-z_]*$/,
  };
}

const highlight = HighlightStyle.define([
  { tag: tags.keyword, color: 'var(--cyan)' },
  { tag: tags.string, color: 'var(--green)' },
  { tag: tags.number, color: 'var(--amber)' },
  { tag: tags.comment, color: 'var(--muted)', fontStyle: 'italic' },
  { tag: tags.operator, color: 'var(--text)' },
  { tag: tags.variableName, color: 'var(--text)' },
]);

/**
 * Enhance a textarea without changing form serialization or script semantics.
 * extensions, completionSources and translateInfo are for trusted, imported UI
 * modules only, never values supplied by route JSON or user Lua. At most 16 of each array are
 * accepted. Extra completion sources compose with the built-in Hangang API
 * and Lua keyword sources. Caller destroys the editor before removing its form.
 */
export function createLuaEditor(textarea, {
  context, label = 'Lua editor', onChange, extensions = [], completionSources = [],
  translateInfo = (text) => text,
} = {}) {
  if (!(textarea instanceof HTMLTextAreaElement)) throw new TypeError('a textarea is required');
  if (context !== 'policy' && context !== 'body') throw new TypeError('context must be policy or body');
  if (onChange !== undefined && typeof onChange !== 'function') throw new TypeError('onChange must be a function');
  if (typeof translateInfo !== 'function') throw new TypeError('translateInfo must be a function');
  if (!Array.isArray(extensions) || extensions.length > 16) throw new TypeError('extensions must be an array of at most 16 CodeMirror extensions');
  if (!Array.isArray(completionSources) || completionSources.length > 16
    || completionSources.some((source) => typeof source !== 'function')) {
    throw new TypeError('completionSources must be an array of at most 16 functions');
  }
  try {
    EditorState.create({ extensions });
  } catch (error) {
    throw new TypeError('extensions must contain valid CodeMirror extensions', { cause: error });
  }

  const nonce = document.querySelector('meta[name="csp-nonce"]')?.content;
  if (!nonce) {
    // A stale/standalone HTML asset must remain editable under a strict CSP.
    // Do not mount a partly styled editor or hide the authoritative textarea.
    return {
      destroy() {},
      syncFromTextarea() {},
      setDisabled(next) { textarea.disabled = Boolean(next); },
      setLabel() {},
      setTranslateInfo() {},
      focus() { textarea.focus(); },
    };
  }
  const host = document.createElement('div');
  host.className = 'hangang-lua-editor';
  const describedBy = textarea.getAttribute('aria-describedby');
  const editable = new Compartment();
  let disabled = Boolean(textarea.disabled);
  let syncing = false;
  let dirtySinceFocus = false;
  let destroyed = false;
  let infoTranslator = translateInfo;
  const previousHidden = textarea.hidden;
  const members = context === 'policy' ? policyMembers : bodyMembers;

  const view = new EditorView({
    state: EditorState.create({
      doc: textarea.value,
      extensions: [
        EditorView.cspNonce.of(nonce),
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightSpecialChars(),
        drawSelection(),
        highlightActiveLine(),
        history(),
        keymap.of([...defaultKeymap, ...historyKeymap, ...closeBracketsKeymap, ...completionKeymap]),
        StreamLanguage.define(lua),
        syntaxHighlighting(highlight),
        bracketMatching(),
        closeBrackets(),
        autocompletion({
          override: [
            (completionContext) => hostCompletions(completionContext, members, infoTranslator),
            (completionContext) => keywordCompletions(completionContext, infoTranslator),
            ...completionSources,
          ],
        }),
        editable.of([EditorView.editable.of(!disabled), EditorState.readOnly.of(disabled)]),
        EditorView.contentAttributes.of({
          'aria-label': label,
          ...(describedBy ? { 'aria-describedby': describedBy } : {}),
        }),
        EditorView.updateListener.of((update) => {
          if (!update.docChanged || syncing || destroyed) return;
          const value = update.state.doc.toString();
          textarea.value = value;
          dirtySinceFocus = true;
          textarea.dispatchEvent(new Event('input', { bubbles: true }));
          onChange?.(value);
        }),
        ...extensions,
      ],
    }),
    parent: host,
  });
  textarea.insertAdjacentElement('afterend', host);
  textarea.hidden = true;
  host.classList.toggle('is-disabled', disabled);

  const onTextareaInput = () => syncFromTextarea();
  textarea.addEventListener('input', onTextareaInput);
  const onBlur = (event) => {
    if (host.contains(event.relatedTarget) || !dirtySinceFocus) return;
    dirtySinceFocus = false;
    textarea.dispatchEvent(new Event('change', { bubbles: true }));
  };
  host.addEventListener('focusout', onBlur);

  function syncFromTextarea() {
    if (destroyed) return;
    const value = textarea.value;
    if (value === view.state.doc.toString()) return;
    syncing = true;
    try {
      const selection = Math.min(view.state.selection.main.head, value.length);
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: value },
        selection: EditorSelection.cursor(selection),
      });
    } finally {
      syncing = false;
    }
  }
  function setDisabled(next) {
    if (destroyed) return;
    disabled = Boolean(next);
    textarea.disabled = disabled;
    host.classList.toggle('is-disabled', disabled);
    if (disabled) closeCompletion(view);
    view.dispatch({
      effects: editable.reconfigure([
        EditorView.editable.of(!disabled),
        EditorState.readOnly.of(disabled),
      ]),
    });
  }
  function setLabel(next) {
    if (destroyed) return;
    view.contentDOM.setAttribute('aria-label', String(next));
  }
  function setTranslateInfo(next) {
    if (typeof next !== 'function') throw new TypeError('translateInfo must be a function');
    infoTranslator = next;
  }
  return {
    destroy() {
      if (destroyed) return;
      destroyed = true;
      textarea.removeEventListener('input', onTextareaInput);
      host.removeEventListener('focusout', onBlur);
      view.destroy();
      host.remove();
      textarea.hidden = previousHidden;
    },
    syncFromTextarea,
    setDisabled,
    setLabel,
    setTranslateInfo,
    focus() { if (!destroyed) view.focus(); },
  };
}
