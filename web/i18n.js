import koDocker from './locales/ko-docker.js';
import koStatic from './locales/ko-static.js';
import koApp from './locales/ko-app.js';
import koConsole from './locales/ko-console.js';
import koOperations from './locales/ko-operations.js';

const STORAGE_KEY = 'hangang-locale';
const korean = { ...koStatic, ...koApp, ...koConsole, ...koOperations, ...koDocker };

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
