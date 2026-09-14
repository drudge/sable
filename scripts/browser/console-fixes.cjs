const assert = require('node:assert/strict');
const {chromium} = require('playwright');

async function check(page, label, action) {
  await action();
  console.log(`PASS ${label}`);
}

async function checkWidgetLifecycle(page, baseURL) {
  await check(page, 'interactive widgets survive reprocesses and dispose removed trees', async () => {
    const fragment = `
      <section id="widget-lifecycle-fixture" data-generation="GENERATION" hx-get="/ui/widget-lifecycle-fragment" hx-trigger="never">
        <label><span>Lifecycle choice</span><select data-styled-select><option value="one">One</option><option value="two">Two</option></select></label>
        <label><span>Lifecycle time</span><input type="time" value="09:30" data-styled-time></label>
        <form>
          <div data-resolver-combobox>
            <input type="hidden" data-resolver-value value="one">
            <input type="hidden" data-custom-name>
            <input type="hidden" data-custom-ip>
            <button type="button" data-resolver-trigger aria-expanded="false"><span data-resolver-label>This server</span></button>
            <div data-resolver-popover hidden>
              <input data-resolver-search aria-label="Search servers">
              <div data-resolver-group>
                <button type="button" data-resolver-option="one" data-resolver-label-value="One" data-search="one">One</button>
                <button type="button" data-resolver-option="two" data-resolver-label-value="Two" data-search="two">Two</button>
              </div>
              <div data-resolver-empty hidden>No server found.</div>
              <button type="button" data-resolver-custom-edit data-search="custom server address"><span>Custom...</span></button>
              <button type="button" data-resolver-option="custom" data-resolver-label-value="" data-resolver-custom-option hidden><span data-resolver-custom-label></span></button>
            </div>
          </div>
          <dialog data-custom-dialog>
            <label>Name <input data-custom-name-draft></label>
            <label>IP <input data-custom-ip-draft></label>
            <div data-custom-preview><span data-custom-preview-value></span></div>
            <button type="button" data-custom-apply>Apply</button>
            <button type="button" data-custom-cancel>Cancel</button>
            <label><span>Dialog choice</span><select data-dialog-choice data-styled-select><option value="a">A</option><option value="b">B</option></select></label>
          </dialog>
        </form>
      </section>`;
    let servedGeneration = 0;
    await page.route('**/ui/widget-lifecycle-fragment', route => route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: fragment.replaceAll('GENERATION', String(++servedGeneration)),
    }));
    await page.goto(`${baseURL}/?dashboard`);
    const devtools = await page.context().newCDPSession(page);
    await page.evaluate(() => {
      const host = document.createElement('div');
      host.id = 'widget-lifecycle-host';
      document.body.append(host);
      window.htmx.ajax('GET', '/ui/widget-lifecycle-fragment', {target: '#widget-lifecycle-host', swap: 'innerHTML'});
    });
    const fixture = page.locator('#widget-lifecycle-fixture');
    const waitForFixtureSwap = async (action) => {
      const expectedGeneration = servedGeneration + 1;
      await action();
      await page.locator(`#widget-lifecycle-fixture[data-generation="${expectedGeneration}"]`).waitFor({state: 'attached'});
    };
    const selectTrigger = fixture.locator('.styled-select-trigger').first();
    const timeEntry = fixture.locator('.styled-time-entry');
    const resolverTrigger = fixture.locator('[data-resolver-trigger]');
    await page.locator('#widget-lifecycle-fixture[data-generation="1"]').waitFor({state: 'attached'});
    await selectTrigger.waitFor();
    await timeEntry.waitFor();
    await resolverTrigger.waitFor();
    await page.evaluate(() => document.body.dispatchEvent(new CustomEvent('htmx:after:process', {bubbles: true})));
    assert.equal(await fixture.locator('[data-resolver-combobox]').getAttribute('data-resolver-ready'), 'true', 'resolver initializes');

    await selectTrigger.click();
    await fixture.locator('[role="option"][data-value="two"]').click();
    assert.equal(await fixture.locator('select[data-styled-select]').first().inputValue(), 'two');
    assert.equal(await selectTrigger.evaluate(element => element === document.activeElement), true, 'selection restores select focus');
    await selectTrigger.click();
    await page.keyboard.press('Escape');
    assert.equal(await selectTrigger.evaluate(element => element === document.activeElement), true, 'Escape restores select focus');

    await timeEntry.click();
    await page.keyboard.press('Escape');
    assert.equal(await timeEntry.evaluate(element => element === document.activeElement), true, 'Escape restores time focus');
    await resolverTrigger.click();
    await fixture.locator('[data-resolver-option="two"]').click();
    assert.equal(await fixture.locator('[data-resolver-value]').inputValue(), 'two');
    assert.equal(await resolverTrigger.evaluate(element => element === document.activeElement), true, 'selection restores resolver focus');
    await resolverTrigger.click();
    await page.keyboard.press('Escape');
    assert.equal(await resolverTrigger.evaluate(element => element === document.activeElement), true, 'Escape restores resolver focus');

    const listenerCount = async (expression) => {
      const result = await devtools.send('Runtime.evaluate', {
        expression,
        includeCommandLineAPI: true,
        returnByValue: true,
      });
      if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || 'listener count evaluation failed');
      assert.equal(typeof result.result.value, 'number', `listener count is numeric for ${expression}`);
      return result.result.value;
    };
    const pointerdownListeners = () => listenerCount('(getEventListeners(document).pointerdown || []).length');
    const windowResizeListeners = () => listenerCount('(getEventListeners(window).resize || []).length');
    const before = await pointerdownListeners();
    await page.evaluate(() => {
      const fixture = document.querySelector('#widget-lifecycle-fixture');
      fixture.setAttribute('hx-get', '/ui/widget-lifecycle-fragment');
      fixture.setAttribute('hx-trigger', 'never');
      window.htmx.process(fixture);
      window.htmx.process(fixture, true);
    });
    await selectTrigger.waitFor();
    await page.evaluate(() => {
      const fixture = document.querySelector('#widget-lifecycle-fixture');
      fixture.removeAttribute('hx-get');
      fixture.removeAttribute('hx-trigger');
    });
    await selectTrigger.click();
    const resizeBeforeRemoval = await windowResizeListeners();
    await waitForFixtureSwap(() => page.evaluate(() => window.htmx.ajax('GET', '/ui/widget-lifecycle-fragment', {
      target: '#widget-lifecycle-fixture', swap: 'outerHTML',
    })));
    assert.equal(await page.locator('#widget-lifecycle-fixture [data-open="true"]').count(), 0, 'removed open popovers are closed');
    assert.equal(await windowResizeListeners(), resizeBeforeRemoval - 1, 'removed open select releases window positioning listener');
    const afterReprocess = await pointerdownListeners();
    assert.equal(afterReprocess, before, 'reprocess does not add document pointerdown handlers');

    const dialog = page.locator('#widget-lifecycle-fixture [data-custom-dialog]');
    const dialogSelect = dialog.locator('.styled-select');
    await dialogSelect.waitFor({state: 'attached'});
    const dialogCloseListeners = () => listenerCount("(getEventListeners(document.querySelector('#widget-lifecycle-fixture [data-custom-dialog]')).close || []).length");
    const dialogListenersBeforeRemoval = await dialogCloseListeners();
    assert.ok(dialogListenersBeforeRemoval >= 2, 'dialog select installs close handling alongside dialog accessibility');
    await page.evaluate(() => {
      document.querySelector('#widget-lifecycle-fixture [data-custom-dialog] .styled-select').remove();
    });
    await page.waitForTimeout(0);
    const dialogListenersAfterRemoval = await dialogCloseListeners();
    assert.equal(dialogListenersAfterRemoval, dialogListenersBeforeRemoval - 1, 'removed dialog select releases close handling');

    for (let index = 0; index < 20; index++) {
      await waitForFixtureSwap(() => page.evaluate(() => window.htmx.ajax('GET', '/ui/widget-lifecycle-fragment', {
        target: '#widget-lifecycle-fixture', swap: 'outerHTML',
      })));
    }
    const afterSwaps = await pointerdownListeners();
    assert.equal(afterSwaps, before, 'repeated swaps keep document pointerdown handlers bounded');
    await page.locator('#widget-lifecycle-fixture .styled-select-trigger').first().click();
    await page.keyboard.press('Escape');
  });
}

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    await require('./block-lists.cjs')(browser, process.argv[2]);
    await require('./zone-import.cjs')(browser, process.argv[2]);
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await check(page, 'shared search clears filters, preserves focus, and never submits DNS queries', async () => {
      await page.goto(`${process.argv[2]}/?zone-import`);
      const search = page.locator('[data-zone-search]');
      const clear = search.locator('..').locator('[data-search-clear]');
      assert.equal(await clear.isVisible(), false);
      await search.fill('missing.example');
      assert.equal(await clear.isVisible(), true);
      await clear.click();
      assert.equal(await search.inputValue(), '');
      assert.equal(await clear.isVisible(), false);
      assert.equal(await search.evaluate(el => el === document.activeElement), true);
      await page.goto(`${process.argv[2]}/?dns-client`);
      await page.locator('#dns-query-form').evaluate(form => {
        window.searchSubmits = 0;
        form.addEventListener('submit', event => { window.searchSubmits++; event.preventDefault(); });
      });
      const domain = page.locator('[data-query-name]');
      const domainClear = domain.locator('..').locator('[data-search-clear]');
      assert.equal(await domainClear.isVisible(), true, 'prefilled domain has a clear button');
      await domainClear.focus();
      await page.keyboard.press('Enter');
      assert.equal(await domain.inputValue(), '');
      assert.equal(await domain.evaluate(el => el === document.activeElement), true);
      assert.equal(await page.evaluate(() => window.searchSubmits), 0);
      await page.locator('[data-resolver-trigger]').click();
      const resolver = page.locator('[data-resolver-search]');
      const resolverClear = resolver.locator('..').locator('[data-search-clear]');
      const options = page.locator('[data-resolver-option]:visible');
      const originalCount = await options.count();
      assert.ok(originalCount > 0);
      await resolver.fill('no-such-resolver');
      assert.equal(await options.count(), 0);
      await resolverClear.click();
      assert.equal(await options.count(), originalCount);
      await resolver.fill('no-such-resolver');
      await page.keyboard.press('Escape');
      await page.locator('[data-resolver-trigger]').click();
      assert.equal(await resolver.inputValue(), '');
      assert.equal(await resolverClear.isVisible(), false, 'reopening synchronizes the clear button');
    });
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
    await checkWidgetLifecycle(page, process.argv[2]);
    assert.deepEqual(errors, [], 'console fixes produce no browser errors');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
