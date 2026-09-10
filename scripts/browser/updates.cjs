const assert = require('node:assert/strict');
const {chromium} = require('playwright');
const fs = require('node:fs/promises');

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const page = await browser.newPage({viewport: {width: 390, height: 844}});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route("**/ui/updates/automatic-check", route => route.fulfill({status: 202}), {times: 1});
    await page.goto(process.argv[2]);
    const notice = page.locator('[data-update-version]');
    await notice.waitFor();
    await notice.locator('summary').click();
    assert.match(await notice.innerText(), /Rolling updates/);
    assert.equal(await notice.locator("h3").innerText(), "Improvements", "release notes render Markdown headings");
    assert.equal(await page.evaluate(() => window.releaseNotesExecuted), undefined);
    assert.equal(await page.locator('.about-version-copy a').getAttribute('href'), 'https://github.com/drudge/sable/releases/tag/v1.0.0');
    const bounds = await notice.boundingBox();
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 390, 'mobile notification fits the viewport');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'release notes do not overflow');
    if (process.env.SABLE_UPDATE_SCREENSHOTS) {
      await fs.mkdir(process.env.SABLE_UPDATE_SCREENSHOTS, {recursive: true});
      await page.screenshot({path: `${process.env.SABLE_UPDATE_SCREENSHOTS}/notification-mobile.png`, fullPage: true});
    }
    await notice.locator('[data-toast-close]').click();
    await notice.waitFor({state: 'detached'});
    await page.reload();
    assert.equal(await page.locator('[data-update-version]').count(), 0, 'dismissed notification is not repeated in the session');
    assert.equal(await (await page.request.get(`${process.argv[2]}/checks`)).json(), 1, 'same session does not recheck');
    await page.evaluate(() => sessionStorage.clear());
    await page.goto(`${process.argv[2]}/?disabled`);
    assert.equal(await (await page.request.get(`${process.argv[2]}/checks`)).json(), 1, 'opt-out prevents checks');
    await page.setViewportSize({width: 1440, height: 1000});
    await page.goto(`${process.argv[2]}/cluster?disabled`);
    assert.match(await page.locator('.cluster-update-card').innerText(), /ns3-latham/);
    assert.equal(await page.locator('[hx-post="/ui/updates/cluster/stop"]').count(), 1);
    if (process.env.SABLE_UPDATE_SCREENSHOTS) await page.screenshot({path: `${process.env.SABLE_UPDATE_SCREENSHOTS}/cluster-desktop.png`, fullPage: true});
    assert.deepEqual(errors, []);
    console.log('PASS login notice, release notes, escaping, release links, mobile layout, dismissal, opt-out, and cluster progress');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
