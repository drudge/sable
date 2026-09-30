const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Each keystroke pause sends the search, and the answer replaces the panel
// around the box. The box has to keep everything typed, not the term the
// previous answer carried, and stay focused so typing can carry on.
(async () => {
  const [baseURL] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const page = await browser.newPage({viewport: {width: 1280, height: 900}});
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));

    const typeAndSettle = async (selector, path, parameter, text, expected) => {
      const answered = page.waitForResponse(response => {
        const url = new URL(response.url());
        return url.pathname === path && url.searchParams.get(parameter) === expected;
      });
      await page.locator(selector).pressSequentially(text);
      await answered;
      await page.locator(`${selector}[value="${expected}"]`).waitFor();
      // htmx lends the new box the old value for a moment; wait past that.
      await page.waitForTimeout(50);
      assert.equal(await page.locator(selector).inputValue(), expected, `the box keeps ${JSON.stringify(expected)}`);
      assert.equal(await page.evaluate(id => document.activeElement?.id, selector.slice(1)), selector.slice(1), 'the box keeps focus');
    };

    await page.goto(`${baseURL}/logs?tab=queries`);
    await page.locator('#query-log-search').click();
    await typeAndSettle('#query-log-search', '/ui/logs/queries', 'q', 'exam', 'exam');
    await typeAndSettle('#query-log-search', '/ui/logs/queries', 'q', 'ple.com', 'example.com');
    await page.waitForFunction(() => new URL(location.href).searchParams.get('q') === 'example.com');
    assert.equal(new URL(page.url()).searchParams.get('tab'), 'queries', 'the address stays on Query Logs');

    // A reload shows the same search.
    await page.reload();
    assert.equal(await page.locator('#query-log-search').inputValue(), 'example.com', 'a reload keeps the search');

    await page.goto(`${baseURL}/logs`);
    await page.locator('#runtime-log-search').click();
    await typeAndSettle('#runtime-log-search', '/ui/logs/runtime', 'search', 'zone', 'zone');
    await typeAndSettle('#runtime-log-search', '/ui/logs/runtime', 'search', ' transfer', 'zone transfer');

    assert.deepEqual(errors, [], 'log search produces no browser errors');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
