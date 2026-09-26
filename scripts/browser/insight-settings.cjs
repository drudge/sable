const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Opens Insights settings from the bell, switches a kind to Show only with the
// mouse and another off with the keyboard, fixes a refused limit, and saves.
(async () => {
  const [baseURL, cookieName] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900}});
    await context.addCookies([{name: cookieName, value: 'everything', url: baseURL}]);
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));

    await page.goto(`${baseURL}/insights?range=day`);
    // The overview replaces the loading page, bell and all, once it is ready.
    await page.locator('#insight-findings').waitFor();
    const bell = page.getByRole('button', {name: 'Insights settings, alerts off'});
    await bell.click();
    const dialog = page.getByRole('dialog', {name: 'Insights Settings'});
    await dialog.waitFor();
    assert.match(await dialog.locator('.insight-settings-alerts').innerText(), /Alerts are off\s+Nothing is set up to receive them yet\./);
    assert.equal(await dialog.getByRole('link', {name: 'Where alerts go'}).getAttribute('href'), '/settings?tab=alerts');
    // Opening puts the cursor on the first choice, not somewhere down the list.
    assert.equal(await page.evaluate(() => document.activeElement?.name), 'new_device.mode', 'focus starts on the first kind');

    // The mouse: Went quiet to Show only.
    const wentQuiet = dialog.getByRole('radiogroup', {name: 'Went quiet'});
    await wentQuiet.getByText('Show only', {exact: true}).click();
    assert.equal(await wentQuiet.getByRole('radio', {name: 'Show only'}).isChecked(), true, 'Went quiet is set to Show only');

    // The keyboard: arrows move through one kind's choices.
    const newApp = dialog.getByRole('radiogroup', {name: 'Started using a new app'});
    await newApp.getByRole('radio', {name: 'Show and alert'}).focus();
    await page.keyboard.press('ArrowRight');
    await page.keyboard.press('ArrowRight');
    assert.equal(await newApp.getByRole('radio', {name: 'Off'}).isChecked(), true, 'arrows reach Off');
    assert.equal(
      await newApp.locator('.insight-mode-option:has(input:focus-visible)').count(), 1,
      'the focused choice shows its focus ring',
    );

    // Findings that are never news cannot be set to alert.
    const coverage = dialog.getByRole('radiogroup', {name: 'Little unique coverage'});
    assert.equal(await coverage.getByRole('radio', {name: 'Show and alert'}).isDisabled(), true);

    // A limit out of range is refused and marked, and the rest is kept.
    const hourLimit = dialog.getByRole('spinbutton', {name: 'Lookups in the hour'});
    await hourLimit.fill('0');
    await hourLimit.evaluate(input => { input.min = ''; });
    await dialog.getByRole('button', {name: 'Save', exact: true}).click();
    const refused = dialog.getByRole('spinbutton', {name: 'Lookups in the hour'});
    await page.locator('#insight-settings [aria-invalid="true"]').waitFor();
    assert.equal(await refused.getAttribute('aria-invalid'), 'true');
    assert.match(await dialog.locator('.field-error').innerText(), /Lookups in the hour must be between 1 and 100,000\./);
    assert.equal(await page.evaluate(() => document.activeElement?.name), 'unusual_hours.minimum_lookups', 'focus moves to the field to fix');
    assert.equal(await wentQuiet.getByRole('radio', {name: 'Show only'}).isChecked(), true, 'a refused save keeps the other choices');

    await refused.fill('45');
    await dialog.getByRole('button', {name: 'Save', exact: true}).click();
    await page.getByText('Insights settings saved.').waitFor();
    assert.equal(await dialog.locator('[aria-invalid="true"]').count(), 0);
    assert.equal(await wentQuiet.getByRole('radio', {name: 'Show only'}).isChecked(), true, 'the saved form shows Show only');
    assert.equal(await dialog.isVisible(), true, 'the dialog stays open on the result');

    // Saving redraws the page behind the dialog, bell and all, and closing
    // still returns to the bell.
    await page.keyboard.press('Escape');
    await dialog.waitFor({state: 'hidden'});
    await page.waitForLoadState('networkidle');
    await page.waitForFunction(() => document.activeElement?.id === 'insight-settings-bell', null, {timeout: 5000});

    // On a phone the choices and buttons still fit inside the dialog.
    await page.setViewportSize({width: 390, height: 844});
    await page.locator('#insight-settings-bell').click();
    await dialog.waitFor();
    const box = await dialog.boundingBox();
    for (const control of [
      dialog.getByRole('button', {name: 'Save', exact: true}), dialog.getByRole('button', {name: 'Reset to Defaults'}),
      dialog.getByRole('radiogroup', {name: 'New device on the network'}),
    ]) {
      const bounds = await control.boundingBox();
      assert.ok(bounds.x >= box.x && bounds.x + bounds.width <= box.x + box.width + 0.5, `fits the dialog: ${JSON.stringify({bounds, box})}`);
      assert.ok(bounds.height < 60, `keeps its height: ${JSON.stringify(bounds)}`);
    }
    assert.deepEqual(errors, []);
    console.log('PASS Insights settings open from the bell, refuse a bad limit, and save Show only');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
