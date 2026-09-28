const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Findings, devices, and apps open at their own addresses. Back closes a
// drawer and Forward opens it again, a link opened fresh opens its drawer,
// Copy Link copies the full address, and a drawer opened from another comes
// back when Back leaves the one on top.
(async () => {
  const [baseURL, cookieName] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900}});
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], {origin: baseURL});
    await context.addCookies([{name: cookieName, value: 'everything', url: baseURL}]);
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const here = () => {
      const url = new URL(page.url());
      return url.pathname + url.search;
    };
    const waitForAddress = address => page.waitForFunction(expected => location.pathname + location.search === expected, address);

    // A finding opens at its address; Back closes it and Forward opens it.
    await page.goto(`${baseURL}/insights?range=day`);
    await page.locator('#insight-findings').waitFor();
    const details = page.locator('.insight-evidence-button').first();
    const findingAddress = await details.getAttribute('data-dialog-url');
    const finding = page.locator(`#${await details.getAttribute('data-dialog-open')}`);
    assert.match(findingAddress, /^\/insights\/findings\/[0-9a-f]{12}\?range=day$/);
    await details.click();
    await finding.waitFor();
    await waitForAddress(findingAddress);
    await finding.locator('[data-copy-url]').click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), baseURL + findingAddress, 'Copy Link copies the full address');
    await page.goBack();
    await finding.waitFor({state: 'hidden'});
    assert.equal(here(), '/insights?range=day');
    await page.goForward();
    await finding.waitFor();
    await finding.locator('.dialog-close').click();
    await finding.waitFor({state: 'hidden'});
    await waitForAddress('/insights?range=day');

    // The same address opened fresh opens the finding once the Overview
    // arrives, and closing it leaves Insights at its own address.
    await page.goto(baseURL + findingAddress);
    const linked = page.locator(`dialog[data-dialog-url="${findingAddress}"]`);
    await linked.waitFor();
    assert.equal(await page.locator('#insight-finding-missing').isVisible(), false, 'a finding on the page does not show the stand-in');
    await linked.locator('.dialog-close').click();
    await linked.waitFor({state: 'hidden'});
    await waitForAddress('/insights?range=day');

    // A finding that is not on the page says so.
    await page.goto(`${baseURL}/insights/findings/000000000000?range=day`);
    await page.locator('#insight-finding-missing').waitFor();
    await page.locator('#insight-finding-missing').getByText('Not in the last 24 hours').waitFor();
    await page.locator('#insight-finding-missing').getByRole('link', {name: 'Try Last 7 Days'}).waitFor();

    // A device's address opens on Devices with its drawer loaded.
    const deviceAddress = '/insights/devices/mac:3c:22:fb:01:02:03?range=day';
    await page.goto(baseURL + deviceAddress);
    const device = page.locator('#insight-device-dialog');
    await device.getByRole('heading', {name: 'george-laptop.corp.example'}).waitFor();
    assert.equal(await page.locator('[data-isotope-tab="devices"]').getAttribute('aria-selected'), 'true', 'a device opens on Devices');
    await device.locator('[data-copy-url]').click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), baseURL + deviceAddress);
    await device.locator('.dialog-close').click();
    await device.waitFor({state: 'hidden'});
    await waitForAddress('/insights?range=day&tab=devices');

    // An app, then a device opened from it: Back leaves the device for the
    // app, and Back again leaves the app.
    await page.goto(`${baseURL}/insights?range=day`);
    await page.locator('#insight-findings').waitFor();
    const app = page.locator('#insight-app-dialog');
    await page.locator('button[data-dialog-open="insight-app-dialog"]', {hasText: 'Netflix'}).first().click();
    await app.getByRole('heading', {name: 'Netflix'}).waitFor();
    await waitForAddress('/insights/apps/netflix?range=day');
    await app.getByRole('button', {name: 'View details for george-laptop.corp.example'}).click();
    await device.getByRole('heading', {name: 'george-laptop.corp.example'}).waitFor();
    await waitForAddress(deviceAddress);
    await page.goBack();
    await device.waitFor({state: 'hidden'});
    await waitForAddress('/insights/apps/netflix?range=day');
    assert.equal(await app.isVisible(), true, 'the app drawer is still open beneath');
    await page.goBack();
    await app.waitFor({state: 'hidden'});
    await waitForAddress('/insights?range=day');

    // A hidden finding's link says so, and Show Again opens the finding.
    await page.goto(`${baseURL}/insights?range=day`);
    await page.locator('#insight-findings').waitFor();
    const hideFrom = page.locator('.insight-evidence-button').first();
    const hiddenAddress = await hideFrom.getAttribute('data-dialog-url');
    const hiding = page.locator(`#${await hideFrom.getAttribute('data-dialog-open')}`);
    await hideFrom.click();
    await hiding.locator('.insight-hide-menu > summary').click();
    // Hiding saves in the background, so the link waits until it is saved.
    const saved = page.waitForResponse(response => new URL(response.url()).pathname === '/ui/insights/feedback' && response.ok());
    await hiding.getByRole('button', {name: /For a Week/}).click();
    await saved;
    await hiding.waitFor({state: 'hidden'});
    await page.goto(baseURL + hiddenAddress);
    const standIn = page.locator('#insight-finding-missing');
    await standIn.getByText('You hid this finding').waitFor();
    await standIn.getByRole('button', {name: 'Show Again'}).click();
    await page.locator(`dialog[data-dialog-url="${hiddenAddress}"]`).waitFor();
    assert.equal(here(), hiddenAddress, 'the finding opens at its own address');

    assert.deepEqual(errors, []);
    console.log('PASS findings, devices, and apps open at their own addresses');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
