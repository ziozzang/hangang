// Key-based message catalogs for @hangang/console-ui (ADR 0020).
// Messages are looked up by stable keys, never by English sentences, and are
// rendered as text nodes by the caller. Missing keys fall back to English, are
// counted, and fail the catalog lint in CI.
const catalogs = new Map();
const missing = new Set();
const plurals = new Map();

export function registerCatalog(locale, messages) {
  if (!messages || typeof messages !== 'object' || Array.isArray(messages)) throw Error('Invalid message catalog');
  catalogs.set(locale, { ...(catalogs.get(locale) || {}), ...messages });
}

export async function loadCatalogs(base, locales = ['en', 'ko']) {
  await Promise.all(locales.map(async locale => {
    const response = await fetch(`${base}/${locale}.json`, { cache: 'no-store' });
    if (!response.ok) throw Error('Message catalog unavailable');
    registerCatalog(locale, await response.json());
  }));
}

export function missingKeys() { return [...missing]; }

function pluralRule(locale) {
  if (!plurals.has(locale)) plurals.set(locale, new Intl.PluralRules(locale));
  return plurals.get(locale);
}

function lookup(locale, key) {
  const catalog = catalogs.get(locale);
  return catalog && Object.hasOwn(catalog, key) ? catalog[key] : undefined;
}

/** Translator bound to a locale source; `{name}` placeholders, `{count}` plural objects. */
export function createTranslator(currentLocale) {
  return function t(key, params = {}) {
    const locale = currentLocale();
    let message = lookup(locale, key);
    if (message === undefined) {
      missing.add(`${locale}:${key}`);
      message = lookup('en', key);
    }
    if (message === undefined) return key;
    if (typeof message === 'object') {
      const count = Number(params.count ?? 0);
      message = message[pluralRule(locale).select(count)] ?? message.other ?? '';
    }
    return String(message).replace(/\{([a-z_]+)\}/g, (match, name) => Object.hasOwn(params, name) ? String(params[name]) : match);
  };
}
