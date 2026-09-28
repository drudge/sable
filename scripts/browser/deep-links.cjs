const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// A query's details, a domain's check, and a Settings card each open at
// their own address. A row still fills the query panel at once, Back and
// Forward close and open the panels, and a link opened fresh opens its
// panel or card.
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

    // A row fills the panel without asking the server, and the address
    // becomes the query's own.
    await page.goto(`${baseURL}/logs?tab=queries`);
    await page.evaluate(() => { window.sableSamePage = true; });
    const query = page.locator('#query-detail-dialog');
    const queryAddress = '/logs/queries/1?name=example.com';
    let loads = 0;
    page.on('request', request => { if (new URL(request.url()).pathname === '/ui/logs/query') loads++; });
    await page.locator('[data-query-detail-row] .query-name-text').first().click();
    await query.getByRole('heading', {name: 'example.com'}).waitFor();
    await waitForAddress(queryAddress);
    assert.equal(loads, 0, 'a row fills the panel itself');
    assert.equal(await query.locator('[data-query-detail-why]').isHidden(), true, 'a cached query does not ask why it was blocked');
    await query.locator('[data-query-detail-copy-link]').click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), baseURL + queryAddress, 'Copy Link copies the full address');
    await page.goBack();
    await query.waitFor({state: 'hidden'});
    await waitForAddress('/logs?tab=queries');
    await page.waitForTimeout(300);
    await page.goForward();
    await query.getByRole('heading', {name: 'example.com'}).waitFor();
    await samePage('Back and Forward');
    await query.getByRole('button', {name: 'Close query details'}).click();
    await query.waitFor({state: 'hidden'});
    await waitForAddress('/logs?tab=queries');

    // A query's address loads it from the server; one that aged out offers
    // a search for its domain.
    await page.goto(baseURL + queryAddress);
    await query.getByRole('heading', {name: 'example.com'}).waitFor();
    await query.getByText('Cache hit').waitFor();
    await page.goto(`${baseURL}/logs/queries/99?name=gone.example`);
    await query.getByText('This query is no longer in the log').waitFor();
    await query.getByRole('link', {name: 'Search Query Logs'}).click();
    await waitForAddress('/logs?name=gone.example&tab=queries');
    // A row after a stand-in fills a fresh panel.
    await page.goto(`${baseURL}/logs/queries/99`);
    await query.getByText('This query is no longer in the log').waitFor();
    await query.getByRole('button', {name: 'Close query details'}).click();
    await page.locator('[data-query-detail-row] .query-name-text').first().click();
    await query.getByRole('heading', {name: 'example.com'}).waitFor();
    await query.getByText('Cache hit').waitFor();

    // The Blocking page's Check a domain box opens the panel on a domain.
    // Each check takes its address, and closing returns to the page in one
    // step.
    await page.goto(`${baseURL}/blocked`);
    await page.evaluate(() => { window.sableSamePage = true; });
    const check = page.locator('#check-domain-dialog');
    await page.getByRole('searchbox', {name: 'Check a domain'}).fill('CDN.tracker.example');
    await page.keyboard.press('Enter');
    await check.getByRole('heading', {name: 'cdn.tracker.example'}).waitFor();
    await check.getByText('Blocked because tracker.example is on Hagezi Pro.').waitFor();
    await waitForAddress('/blocked/check/CDN.tracker.example');
    await check.locator('#check-domain-input').fill('example.org');
    await check.locator('#check-domain-input').press('Enter');
    await check.getByText('Nothing blocks this domain.').waitFor();
    await waitForAddress('/blocked/check/example.org');
    await check.getByRole('button', {name: 'Close domain check'}).click();
    await check.waitFor({state: 'hidden'});
    await waitForAddress('/blocked');
    await samePage('Checking domains');

    // A check's address opens it; Allow checks again and turns the page to
    // the allow list.
    await page.goto(`${baseURL}/blocked/check/cdn.tracker.example`);
    await check.getByText('Blocked because tracker.example is on Hagezi Pro.').waitFor();
    await check.getByRole('button', {name: 'Allow'}).click();
    await check.getByText('cdn.tracker.example is now allowed.').waitFor();
    await page.locator('#blocking-tab-allowed[aria-selected="true"]').waitFor();
    assert.equal(await check.isVisible(), true, 'the panel stays open after Allow');

    // A Settings card's address opens its tab, scrolls to it, and outlines it.
    await page.goto(`${baseURL}/settings#bypass-clients`);
    const card = page.locator('#bypass-clients');
    await card.and(page.locator('.is-linked')).waitFor();
    assert.equal(await page.locator('[data-isotope-panel="blocking"]').isVisible(), true, 'the card\'s tab opens');
    // The scroll is smooth unless the viewer asks for less motion.
    await page.waitForTimeout(1000);
    const box = await card.boundingBox();
    assert.ok(box && box.y >= 0 && box.y + box.height <= 900, `the card is in view, at ${box?.y} to ${box && box.y + box.height}`);
    await page.waitForFunction(() => !document.querySelector('#bypass-clients.is-linked'), null, {timeout: 4000});

    assert.deepEqual(errors, []);
    console.log('PASS queries, domain checks, and Settings cards open at their own addresses');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
