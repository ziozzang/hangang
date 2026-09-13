import { test, expect } from '@playwright/test';

test('trusted completion hook composes with context API and rejects invalid extensions', async ({ page }) => {
  await page.goto('/ui/');
  await page.evaluate(async () => {
    const { createLuaEditor } = await import('/ui/lua-editor.js');
    const textarea = document.createElement('textarea');
    textarea.id = 'lua-editor-core-fixture';
    document.querySelector('#login-dialog').append(textarea);
    window.coreLuaEditor = createLuaEditor(textarea, {
      context: 'policy',
      label: 'Core policy editor',
      completionSources: [(context) => {
        const word = context.matchBefore(/[A-Za-z_]*/);
        if (word?.text !== 'cu') return null;
        return { from: word.from, options: [{ label: 'customHook', type: 'function' }] };
      }],
    });
  });
  const content = page.getByRole('textbox', { name: 'Core policy editor' });
  await content.click();
  await page.keyboard.type('cu');
  await page.keyboard.press('Control+Space');
  await expect(page.locator('.cm-tooltip-autocomplete')).toContainText('customHook');
  await page.keyboard.press('Escape');

  await content.fill('hangang.hea');
  await page.keyboard.press('Control+Space');
  await expect(page.locator('.cm-tooltip-autocomplete')).toContainText('header');
  await expect(page.locator('#lua-editor-core-fixture')).toHaveValue('hangang.hea');

  const invalid = await page.evaluate(async () => {
    const { createLuaEditor } = await import('/ui/lua-editor.js');
    const textarea = document.createElement('textarea');
    document.body.append(textarea);
    try {
      createLuaEditor(textarea, { context: 'body', extensions: [{}] });
      return false;
    } catch (error) {
      return error instanceof TypeError;
    } finally {
      textarea.remove();
    }
  });
  expect(invalid).toBe(true);
  await page.evaluate(() => window.coreLuaEditor.destroy());
  await expect(page.locator('.hangang-lua-editor')).toHaveCount(0);
  await expect(page.locator('#lua-editor-core-fixture')).toBeVisible();
});

test('missing CSP nonce keeps the native textarea editable and preserves its value on destroy', async ({ page }) => {
  await page.goto('/ui/');
  await page.evaluate(async () => {
    document.querySelector('meta[name="csp-nonce"]').remove();
    const { createLuaEditor } = await import('/ui/lua-editor.js');
    const textarea = document.createElement('textarea');
    textarea.id = 'lua-editor-no-nonce';
    textarea.value = 'return nil';
    document.querySelector('#login-dialog').append(textarea);
    window.noNonceLuaEditor = createLuaEditor(textarea, { context: 'policy' });
  });
  const textarea = page.locator('#lua-editor-no-nonce');
  await expect(textarea).toBeVisible();
  await expect(page.locator('.hangang-lua-editor')).toHaveCount(0);
  await textarea.fill('return hangang.method()');
  await page.evaluate(() => {
    window.noNonceLuaEditor.syncFromTextarea();
    window.noNonceLuaEditor.destroy();
  });
  await expect(textarea).toBeVisible();
  await expect(textarea).toHaveValue('return hangang.method()');
});
