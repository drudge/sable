const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Turns Insights off from Settings > General: the switch asks first, Cancel
// leaves it on, Turn Off deletes what it collected and takes Insights out of
// the sidebar, and the switch turns it back on.
(async () => {
  const [baseURL, cookieName] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 390, height: 844}});
    await context.addCookies([{name: cookieName, value: 'everything', url: baseURL}]);
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));

    await page.goto(`${baseURL}/settings?tab=general`);
    const card = page.locator('#settings-insights');
    const toggle = card.getByRole('switch', {name: /Insights/});
    assert.equal(await toggle.isChecked(), true, 'Insights starts on');
    assert.match(await card.innerText(), /Device data: 4 addresses and 1 hardware address, back to /);

    // The switch asks first and stays on meanwhile.
    await toggle.click();
    const dialog = page.getByRole('dialog', {name: 'Turn Off Insights?'});
    await dialog.waitFor();
    assert.equal(await toggle.isChecked(), true, 'the switch stays on while the dialog asks');
    const remove = dialog.getByRole('checkbox', {name: 'Also delete what Insights has collected'});
    assert.equal(await remove.isChecked(), true, 'deleting is checked by default');
    // On a phone the main action sits above Cancel.
    const turnOff = dialog.getByRole('button', {name: 'Turn Off'});
    const cancel = dialog.getByRole('button', {name: 'Cancel'});
    assert.ok((await turnOff.boundingBox()).y < (await cancel.boundingBox()).y, 'Turn Off is above Cancel on a phone');
    await cancel.click();
    await dialog.waitFor({state: 'hidden'});
    assert.equal(await toggle.isChecked(), true, 'Cancel leaves Insights on');

    // With the keyboard this time.
    await toggle.focus();
    await page.keyboard.press('Space');
    await dialog.waitFor();
    await Promise.all([page.waitForEvent('load'), turnOff.click()]);
    const off = page.locator('#settings-insights').getByRole('switch', {name: /Insights/});
    assert.equal(await off.isChecked(), false, 'Insights is off after the reload');
    assert.doesNotMatch(await page.locator('#settings-insights').innerText(), /Device data/, 'what Insights collected is gone');
    assert.equal(await page.locator('a.nav-item[href="/insights"]').count(), 0, 'Insights left the sidebar');

    await page.goto(`${baseURL}/insights`);
    await page.getByRole('heading', {name: 'Insights Is Off'}).waitFor();

    // Turning it back on needs no dialog.
    await page.goto(`${baseURL}/settings?tab=general`);
    await Promise.all([page.waitForEvent('load'), page.locator('#settings-insights').getByRole('switch', {name: /Insights/}).click()]);
    assert.equal(await page.locator('#settings-insights').getByRole('switch', {name: /Insights/}).isChecked(), true, 'Insights is back on');
    assert.equal(await page.locator('a.nav-item[href="/insights"]').count(), 1, 'Insights is back in the sidebar');

    assert.deepEqual(errors, []);
    console.log('insights switch: asks first, turns off with delete, and back on');
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exit(1);
});
