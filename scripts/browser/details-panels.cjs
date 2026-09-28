const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Block lists and cluster nodes open their panels at their own addresses.
// Back closes a panel and Forward opens it, a link opened fresh opens its
// panel, a panel stays open while the page refreshes beneath it, and a
// panel's action returns to the page.
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

    // A node's address opens its panel, which outlasts the live status
    // refreshing beneath it and keeps its own details current.
    await page.goto(`${baseURL}/cluster/nodes/ns2`);
    const node = page.locator('#cluster-node-dialog');
    await node.getByRole('heading', {name: 'ns2'}).waitFor();
    await node.getByText('Certificate renewal is failing on ns2.').waitFor();
    const refreshed = page.waitForResponse(response => new URL(response.url()).searchParams.get('part') === 'details');
    await page.waitForResponse(response => new URL(response.url()).pathname === '/ui/cluster/status');
    await refreshed;
    await page.waitForTimeout(300);
    assert.equal(await node.isVisible(), true, 'the panel stays open while the page refreshes');
    await node.getByText('Certificate renewal is failing on ns2.').waitFor();

    // Remove from the panel asks first, then returns to the Cluster page.
    await node.getByRole('button', {name: 'Remove Replica'}).click();
    const confirm = page.locator('dialog.confirmation-dialog');
    await confirm.getByRole('button', {name: 'Remove Replica'}).click();
    await page.getByText('Cluster replica removed').waitFor();
    await waitForAddress('/cluster');
    await node.waitFor({state: 'hidden'});

    // A closed panel stops polling.
    let polls = 0;
    page.on('request', request => { if (new URL(request.url()).searchParams.get('part') === 'details') polls++; });
    await page.waitForTimeout(6000);
    assert.equal(polls, 0, 'a closed panel does not poll');

    assert.deepEqual(errors, []);
    console.log('PASS block lists and cluster nodes open at their own addresses');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
