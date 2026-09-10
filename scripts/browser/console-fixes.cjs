const assert = require('node:assert/strict');
const {chromium} = require('playwright');

async function check(page, label, action) {
  await action();
  console.log(`PASS ${label}`);
}

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    await require('./block-lists.cjs')(browser, process.argv[2]);
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await check(page, 'About keeps the short mobile SHA in the upstream build layout', async () => {
      await page.setViewportSize({width: 375, height: 667});
      await page.goto(`${process.argv[2]}/?about`);
      const commit = page.locator('.about-build-meta .about-commit');
      assert.equal(await commit.innerText(), 'abcdef0');
      assert.equal(await commit.getAttribute('title'), 'abcdef0123456789abcdef0123456789abcdef0123');
      assert.equal(await page.locator('.about-version-row').count(), 1);
      assert.equal(await page.locator('#about-update').count(), 1);
      assert.match(await page.locator('#about-update').innerText(), /Development build/);
      const bounds = await commit.boundingBox();
      assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 375, 'mobile commit fits without overflow');
    });
    await page.setViewportSize({width: 1400, height: 1000});
    assert.equal(await page.locator('.about-commit').innerText(), 'abcdef0123456789abcdef0123456789abcdef0123');
    await check(page, 'stat card focus and tab order survive live refreshes', async () => {
      await page.clock.install();
      await page.goto(`${process.argv[2]}/?dashboard`);
      await page.emulateMedia({reducedMotion: 'reduce'});
      const cards = page.locator('#runtime-stats a.stat-card');
      const labels = await cards.evaluateAll(elements => elements.map(element => element.dataset.statLabel));
      assert.equal(labels.length, 11);
      await cards.first().focus();
      for (let index = 0; index < labels.length; index++) {
        assert.equal(await page.evaluate(() => document.activeElement?.dataset.statLabel), labels[index]);
        const value = await cards.first().locator('[data-stat-number="value"]').textContent();
        await page.clock.runFor(10000);
        await page.waitForFunction(previous => document.querySelector('#runtime-stats [data-stat-number="value"]').textContent !== previous, value);
        assert.equal(await page.evaluate(() => document.activeElement?.dataset.statLabel), labels[index], 'refresh must retain the current card');
        if (index < labels.length - 1) await page.keyboard.press('Tab');
      }
      await page.keyboard.press('Shift+Tab');
      assert.equal(await page.evaluate(() => document.activeElement?.dataset.statLabel), labels.at(-2));
    });
    await check(page, 'overview scope controls retain focus when activated and refreshed', async () => {
      const scope = page.getByRole('button', {name: 'Chart range', exact: true});
      await scope.focus();
      await page.keyboard.press('Enter');
      await page.waitForFunction(() => document.querySelector('#runtime-stats').dataset.statsScope === 'range');
      assert.equal(await scope.evaluate(element => element === document.activeElement), true);
      const value = await page.locator('#runtime-stats [data-stat-number="value"]').first().textContent();
      await page.clock.runFor(10000);
      await page.waitForFunction(previous => document.querySelector('#runtime-stats [data-stat-number="value"]').textContent !== previous, value);
      assert.equal(await scope.evaluate(element => element === document.activeElement), true);
      await page.keyboard.press('Tab');
      assert.equal(await page.evaluate(() => document.activeElement?.dataset.statLabel), 'Total Queries');
    });
    assert.deepEqual(errors, [], 'console fixes produce no browser errors');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
