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
    await check(page, 'background dashboard refresh stays visually quiet', async () => {
      await page.clock.install();
      await page.goto(`${process.argv[2]}/?dashboard`);
      const card = page.locator('#stat-card-total-queries');
      await card.focus();
      await page.locator('#stat-card-no-error').hover();
      await page.locator('#runtime-stats').evaluate(element => Promise.all(element.getAnimations({subtree: true}).map(animation => animation.finished)));
      await page.evaluate(() => {
        window.finishedRefreshes = 0;
        document.addEventListener('htmx:finally:request', () => { window.finishedRefreshes++; });
        const cardAppearance = element => ({
          transform: getComputedStyle(element).transform,
          shadow: getComputedStyle(element).boxShadow,
          arrowOpacity: getComputedStyle(element, '::before').opacity,
        });
        window.highlightedCards = [...document.querySelectorAll('.stat-card:focus-visible, .stat-card:hover')];
        window.cardAppearanceBefore = window.highlightedCards.map(cardAppearance);
        document.addEventListener('htmx:before:settle', event => {
          if (event.detail.task.target.id !== 'runtime-stats') return;
          window.cardAppearanceAfter = window.highlightedCards.map(element => cardAppearance(document.getElementById(element.id)));
        });
      });
      let receiveRequest;
      const pending = new Promise(resolve => { receiveRequest = resolve; });
      await page.route('**/ui/stats/chart**', receiveRequest, {times: 1});
      const started = page.waitForRequest('**/ui/stats/chart**');
      await page.clock.runFor(10000);
      await started;
      const request = await pending;
      assert.equal(await page.locator('#dashboard-update-indicator').isVisible(), false, 'background polling does not show the dashboard loading notice');
      assert.equal(await page.locator('.chart-plot').evaluate(element => getComputedStyle(element).opacity), '1', 'background polling does not dim the chart');
      assert.equal(await card.evaluate(element => getComputedStyle(element, '::after').animationName), 'none', 'background polling does not sweep across the cards');
      await request.continue();
      await page.waitForFunction(() => window.finishedRefreshes === 1);
      assert.deepEqual(await page.evaluate(() => window.cardAppearanceAfter), await page.evaluate(() => window.cardAppearanceBefore), 'refresh does not restart the focus or hover highlight');
      assert.equal(await page.evaluate(() => window.highlightedCards.length), 2, 'check both keyboard focus and pointer hover');
      assert.equal(await page.evaluate(() => window.highlightedCards.every(element => element === document.getElementById(element.id))), true, 'refresh updates the existing cards in place');
      await page.clock.runFor(600);
      assert.equal(await card.locator('[data-stat-number="value"]').textContent(), '101');
      assert.equal(await card.evaluate(element => element === document.activeElement), true);
      assert.equal(await page.locator('.chart-plot').evaluate(element => getComputedStyle(element).opacity), '1');
    });
    for (const control of ['desktop range', 'mobile range', 'custom range', 'overview scope']) {
      await check(page, `${control} still shows loading feedback`, async () => {
        await page.setViewportSize({width: control === 'mobile range' ? 600 : 1400, height: 1000});
        await page.emulateMedia({reducedMotion: 'reduce'});
        await page.goto(`${process.argv[2]}/?dashboard`);
        let receiveRequest;
        const pending = new Promise(resolve => { receiveRequest = resolve; });
        await page.route('**/ui/stats/chart**', receiveRequest, {times: 1});
        const started = page.waitForRequest('**/ui/stats/chart**');
        if (control === 'desktop range') await page.locator('#chart-range-day').click();
        if (control === 'mobile range') {
          await page.locator('.range-select .styled-select-trigger').click();
          await page.locator('.range-select [role="option"][data-value="day"]').click();
        }
        if (control === 'custom range') {
          await page.locator('#chart-range-custom').click();
          await page.locator('[data-range-apply]').click();
        }
        if (control === 'overview scope') await page.locator('#stats-scope-range').click();
        await started;
        const request = await pending;
        assert.equal(await page.locator('#dashboard-update-indicator').isVisible(), true);
        assert.equal(await page.locator('.chart-plot').evaluate(element => getComputedStyle(element).opacity), '0.65');
        await request.continue();
        await page.waitForFunction(() => !document.querySelector('#dashboard-update-indicator').classList.contains('htmx-request'));
        assert.equal(await page.locator('#dashboard-update-indicator').isVisible(), false);
      });
    }
    await check(page, 'stat card focus and tab order survive live refreshes', async () => {
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
      assert.equal(await scope.getAttribute('aria-pressed'), 'true');
      assert.equal(await page.locator('.stats-range-label').textContent(), 'Last hour');
      const totalCard = page.locator('#stat-card-total-queries');
      assert.equal(new URL(await totalCard.getAttribute('href'), process.argv[2]).searchParams.get('start'), '2026-09-10T10:00:00Z', 'retained cards get the updated log links');
      const value = await page.locator('#runtime-stats [data-stat-number="value"]').first().textContent();
      await page.clock.runFor(10000);
      await page.waitForFunction(previous => document.querySelector('#runtime-stats [data-stat-number="value"]').textContent !== previous, value);
      assert.equal(await scope.evaluate(element => element === document.activeElement), true);
      await page.keyboard.press('Tab');
      assert.equal(await page.evaluate(() => document.activeElement?.dataset.statLabel), 'Total Queries');
      await page.locator('#stats-scope-all').click();
      await page.waitForFunction(() => document.querySelector('#runtime-stats').dataset.statsScope === 'all');
      assert.equal(await scope.getAttribute('aria-pressed'), 'false');
      assert.equal(await page.locator('.stats-range-label').count(), 0);
      assert.equal(await totalCard.getAttribute('href'), '/logs?tab=queries');
    });
    assert.deepEqual(errors, [], 'console fixes produce no browser errors');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
