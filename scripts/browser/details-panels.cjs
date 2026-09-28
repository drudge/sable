const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Block lists open their panels at their own addresses. Back closes a panel
// and Forward opens it, a link opened fresh opens its panel, and Refresh
// updates the panel and the page beneath it.
(async () => {
  const [baseURL] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900}});
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], {origin: baseURL});
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const waitForAddress = address => page.waitForFunction(expected => location.pathname + location.search === expected, address);
    const samePage = async step => assert.equal(await page.evaluate(() => window.sableSamePage === true), true, `${step} kept the page`);

    // A list opens from its name; Back closes it and Forward opens it.
    await page.goto(`${baseURL}/blocked`);
    await page.evaluate(() => { window.sableSamePage = true; });
    const list = page.locator('#block-list-dialog');
    const listAddress = '/blocked/lists/Test%20Feed';
    await page.getByRole('button', {name: 'View details for Test Feed'}).click();
    await list.getByRole('heading', {name: 'Test Feed'}).waitFor();
    await waitForAddress(listAddress);
    await list.locator('[data-copy-url]').click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), baseURL + listAddress, 'Copy Link copies the full address');
    await page.goBack();
    await list.waitFor({state: 'hidden'});
    await waitForAddress('/blocked');
    // The drawer's close event lands a moment after Back; Forward before it
    // would race the drawer's own history handling, as in Insights.
    await page.waitForTimeout(300);
    await page.goForward();
    await list.getByRole('heading', {name: 'Test Feed'}).waitFor();
    await samePage('Back and Forward');

    // Refreshing the list updates the panel and the row beneath it, and the
    // panel stays open at its address.
    await list.getByRole('button', {name: 'Refresh This List'}).click();
    await list.getByText('Test Feed downloaded and compiled').waitFor();
    assert.equal(await list.isVisible(), true, 'the panel stays open after Refresh');
    await waitForAddress(listAddress);
    await list.locator('.dialog-close').click();
    await list.waitFor({state: 'hidden'});
    await waitForAddress('/blocked');

    // A click anywhere in the row opens it too, and so does its address.
    await page.locator('.blocking-source-row code').first().click();
    await list.getByRole('heading', {name: 'Test Feed'}).waitFor();
    await page.goto(baseURL + listAddress);
    await list.getByRole('heading', {name: 'Test Feed'}).waitFor();
    await page.goto(`${baseURL}/blocked/lists/Gone`);
    await list.getByRole('heading', {name: 'Block list not found'}).waitFor();

    assert.deepEqual(errors, []);
    console.log('PASS block lists open at their own addresses');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
