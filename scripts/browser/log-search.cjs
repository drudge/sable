const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Each keystroke pause sends the search, and the answer replaces the panel
// around the box. The box has to keep everything typed, not the term the
// previous answer carried, and stay focused so typing can carry on. That
// holds when an answer arrives in the middle of more typing, too.
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
      await page.waitForFunction(() => !document.querySelector('form.log-search-bar.htmx-request'));
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

    // A slow answer lands while the next word is still being typed. On a
    // large log a short search reads every row and takes seconds.
    await page.goto(`${baseURL}/logs?tab=queries`);
    let release;
    const held = new Promise(resolve => { release = resolve; });
    await page.route(url => url.pathname === '/ui/logs/queries' && url.searchParams.get('q') === 're', async route => {
      await held;
      await route.continue();
    });
    await page.locator('#query-log-search').click();
    const slow = page.waitForRequest(request => new URL(request.url()).searchParams.get('q') === 're');
    await page.locator('#query-log-search').pressSequentially('re');
    const slowRequest = await slow;
    await page.locator('#query-log-search').pressSequentially('mark', {delay: 50});
    release();
    // Its answer is either dropped, or never sent because the next search
    // replaced it; either way the box keeps the typing.
    await Promise.race([slowRequest.response(), page.waitForEvent('requestfailed', request => request === slowRequest)]);
    await page.waitForFunction(() => !document.querySelector('form.log-search-bar.htmx-request'));
    assert.equal(await page.locator('#query-log-search').inputValue(), 'remark', 'a slow answer keeps what was typed after it was sent');
    await typeAndSettle('#query-log-search', '/ui/logs/queries', 'q', 'able', 'remarkable');
    await page.waitForFunction(() => new URL(location.href).searchParams.get('q') === 'remarkable');
    await page.unrouteAll();

    await page.goto(`${baseURL}/logs`);
    await page.locator('#runtime-log-search').click();
    await typeAndSettle('#runtime-log-search', '/ui/logs/runtime', 'search', 'zone', 'zone');
    await typeAndSettle('#runtime-log-search', '/ui/logs/runtime', 'search', ' transfer', 'zone transfer');

    assert.deepEqual(errors, [], 'log search produces no browser errors');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
