const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Narrows the Insights Apps list by search, category, and failures, checks
// that its filters keep their own place in the URL apart from the Devices
// list's, that a row opens the app's drawer with its failed lookups, and that
// the tab fits a phone.
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

    await page.goto(`${baseURL}/insights?range=day&tab=apps`);
    const card = page.locator('section[aria-labelledby="insight-apps-title"]');
    const search = card.getByRole('searchbox', {name: 'Search apps'});
    await search.waitFor();
    const rows = card.locator('tbody tr[data-list-row]');
    const shown = () => rows.evaluateAll(list => list.filter(row => !row.hidden).map(row => row.querySelector('strong').textContent));
    const badge = card.locator('[data-list-count]');
    const choose = async (name, choice) => {
      await card.getByRole('combobox', {name}).click();
      await page.getByRole('option', {name: choice, exact: true}).click();
    };
    assert.deepEqual(await shown(), ['Netflix', 'reMarkable'], 'every app, busiest first');
    assert.equal(await badge.innerText(), '2 apps');

    // Failing keeps the app whose lookups Sable refused.
    await choose('Show apps', 'Failing');
    assert.deepEqual(await shown(), ['reMarkable']);
    assert.equal(await badge.innerText(), '1 of 2 apps');
    await page.waitForFunction(() => new URL(location.href).searchParams.get('app_show') === 'failing');
    await choose('Show apps', 'All Apps');

    // The category filter and the search narrow together.
    await choose('Category', 'Streaming');
    assert.deepEqual(await shown(), ['Netflix']);
    await search.fill('remarkable');
    await card.getByText('No apps match').waitFor();
    await card.getByRole('button', {name: 'Clear Filters'}).click();
    assert.deepEqual(await shown(), ['Netflix', 'reMarkable'], 'every app is back');

    // The search keeps its own URL parameter, so the Devices list is not
    // narrowed by it.
    await search.fill('netflix');
    await page.waitForFunction(() => new URL(location.href).searchParams.get('app_search') === 'netflix');
    assert.equal(new URL(page.url()).searchParams.get('search'), null);
    await page.reload();
    await search.waitFor();
    assert.equal(await search.inputValue(), 'netflix', 'a reload keeps the search');
    assert.deepEqual(await shown(), ['Netflix']);
    await search.fill('');

    // A row opens the app's drawer, which names the failing domain.
    await rows.filter({hasText: 'reMarkable'}).getByRole('button', {name: 'View details for reMarkable'}).click();
    const drawer = page.locator('#insight-app-dialog');
    await drawer.getByRole('heading', {name: 'Failed lookups'}).waitFor();
    await drawer.getByText('eu.tectonic.remarkable.com').first().waitFor();
    await page.keyboard.press('Escape');

    // On a phone the four tabs and the list fit without sideways scrolling.
    await page.setViewportSize({width: 390, height: 844});
    await card.locator('.admin-mobile-list').waitFor();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'the page does not scroll sideways');
    assert.deepEqual(errors, []);
    console.log('PASS the Apps list narrows by search, category, and failures, keeps its own filters in the URL, and opens the failing app');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
