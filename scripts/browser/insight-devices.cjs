const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Narrows the Insights Devices list by search, type, and whether a device has
// a name, clears it all, and checks the list stays narrowed through a range
// change and a reload, that the command palette can search it, and that the
// search fits a phone.
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

    await page.goto(`${baseURL}/insights?range=day&tab=devices`);
    const card = page.locator('[data-device-filter-root]');
    const search = card.getByRole('searchbox', {name: 'Search devices'});
    await search.waitFor();
    const rows = card.locator('tbody tr[data-device-row]');
    const shown = () => rows.evaluateAll(list => list.filter(row => !row.hidden).map(row => row.querySelector('strong').textContent));
    const badge = card.locator('[data-device-count]');
    const choose = async (name, choice) => {
      await card.getByRole('combobox', {name}).click();
      await page.getByRole('option', {name: choice, exact: true}).click();
    };
    const total = await rows.count();
    assert.ok(total >= 3, `the list has the fixture's devices: ${total}`);
    assert.equal(await badge.innerText(), `${total} devices`);

    // Search finds a device by any of its addresses, and every word counts.
    await search.fill('fd00::5');
    assert.deepEqual(await shown(), ['george-laptop.corp.example'], 'the second address finds the laptop');
    assert.equal(await badge.innerText(), `1 of ${total} devices`);
    await search.fill('george nowhere');
    assert.deepEqual(await shown(), [], 'every word must match');
    await card.getByText('No devices match').waitFor();
    assert.equal(await card.locator('.admin-desktop-table').isVisible(), false, 'an empty result hides the table');

    // Clear Filters puts everything back and returns to the search.
    await choose('Show devices', 'Named');
    await card.getByRole('button', {name: 'Clear Filters'}).click();
    assert.equal((await shown()).length, total, 'every device is back');
    assert.equal(await badge.innerText(), `${total} devices`);
    assert.equal(await search.inputValue(), '');
    assert.equal(await card.getByRole('combobox', {name: 'Show devices'}).innerText(), 'All Devices');
    assert.equal(await page.evaluate(() => document.activeElement?.matches('[data-device-search]')), true, 'focus returns to the search');

    // The type filter matches the icon each row starts with.
    await choose('Device type', 'Computer');
    assert.deepEqual(await shown(), ['george-laptop.corp.example']);
    await choose('Device type', 'All Types');
    await choose('Show devices', 'Unnamed');
    const unnamed = await shown();
    assert.ok(unnamed.length >= 2 && unnamed.every(label => /^10\.0\.0\.\d+$/.test(label)), `unnamed devices go by their addresses: ${unnamed}`);

    // The URL keeps the search and filters, so a range change and a reload
    // keep the list narrowed.
    await search.fill('10.0.0.50');
    await page.waitForFunction(() => new URL(location.href).searchParams.get('search') === '10.0.0.50');
    assert.equal(new URL(page.url()).searchParams.get('show'), 'unnamed');
    await page.locator('.range-tabs').getByRole('button', {name: 'Week'}).click();
    await page.waitForFunction(() => new URL(location.href).searchParams.get('range') === 'week');
    await card.getByText('Last 7 days').waitFor();
    assert.equal(await search.inputValue(), '10.0.0.50', 'a range change keeps the search');
    assert.equal(await card.getByRole('combobox', {name: 'Show devices'}).innerText(), 'Unnamed', 'and the filter');
    assert.deepEqual(await shown(), ['10.0.0.50']);
    await page.reload();
    await search.waitFor();
    assert.equal(await search.inputValue(), '10.0.0.50', 'a reload keeps the search');
    assert.deepEqual(await shown(), ['10.0.0.50']);

    // Search Devices in the command palette opens the list already searched,
    // with the cursor in the search.
    await page.goto(`${baseURL}/`);
    await page.locator('[data-command-open]:visible').first().click();
    const command = page.locator('#command-palette-input');
    await command.fill('search dev');
    await page.keyboard.press('Enter');
    assert.equal(await command.getAttribute('placeholder'), 'Search devices…');
    await command.fill('george');
    await page.keyboard.press('Enter');
    await page.waitForURL(url => url.pathname === '/insights' && url.searchParams.get('search') === 'george');
    await page.waitForFunction(() => document.activeElement?.matches('[data-device-search]'));
    assert.equal(await search.inputValue(), 'george');
    assert.deepEqual(await shown(), ['george-laptop.corp.example']);

    // On a phone the filters drop below the search, and nothing runs off the
    // side of the page.
    await page.setViewportSize({width: 390, height: 844});
    const field = await card.locator('.search-field').boundingBox();
    const type = await card.locator('.insight-device-type-filter').boundingBox();
    assert.ok(type.y >= field.y + field.height, `the filters sit below the search: ${JSON.stringify({field, type})}`);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'the page does not scroll sideways');
    assert.deepEqual(errors, []);
    console.log('PASS the Devices list narrows by search, type, and name, keeps its filters through a range change and a reload, and opens searched from the command palette');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
