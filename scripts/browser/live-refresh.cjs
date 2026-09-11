const assert = require('node:assert/strict');
const {chromium} = require('playwright');

const scenarios = [
  {page: 'chart', name: 'chart plot', control: '[data-chart-plot]', interval: 10000},
  {page: 'chart', name: 'mobile range picker', control: '.range-select .styled-select-trigger', interval: 10000, width: 600},
  {page: 'insights', name: 'ranking View all', control: '.ranking-view-all', interval: 60000},
  {page: 'insights', name: 'ranking link', control: '.ranking-row', interval: 60000},
  {page: 'insights', name: 'distribution legend', control: '[data-donut-legend]', interval: 60000},
  {page: 'cluster', name: 'Add Replica', control: '[data-dialog-open="enrollment-token-dialog"]', interval: 2000},
  {page: 'cluster', name: 'node portal', control: '.cluster-node-portal', interval: 2000},
  {page: 'cluster', name: 'promote replica', control: 'form[hx-post$="/promote"] button', interval: 2000},
  {page: 'cluster', name: 'remove replica', control: '.cluster-remove-node', interval: 2000},
  {page: 'unifi', name: 'UniFi actions', control: '[data-dialog-open="remove-unifi-dialog"]', interval: 10000},
  {page: 'unifi', name: 'UniFi mapping links', control: '#unifi-mapping-table a', interval: 10000},
  {page: 'dynamic', name: 'Dynamic DNS actions', control: 'a[href="/integrations?setup=dynamic-dns"]', interval: 30000},
  {page: 'update', name: 'release notes', control: '#update-release-notes-dialog-open', interval: 2000, restoresFocus: true},
];

async function refresh(page, interval) {
  const completed = await page.evaluate(() => window.finishedRefreshes);
  await page.clock.runFor(interval + 100);
  await page.waitForFunction(previous => window.finishedRefreshes > previous, completed);
}

async function rememberControl(control) {
  await control.focus();
  await control.evaluate(element => { window.originalControl = element; });
}

async function assertOriginalFocus(control) {
  assert.equal(await control.evaluate(element => element === window.originalControl && element === document.activeElement), true, 'refresh must preserve the focused control');
}

async function assertRestoredFocus(control) {
  // Stable IDs let progress refresh while htmx restores focus to the new button.
  assert.equal(await control.evaluate(element => element === document.activeElement), true, 'refresh must restore focus to the replacement control');
  assert.equal(await control.evaluate(() => window.originalControl.isConnected), false, 'progress must refresh while a control with a stable ID is focused');
}

async function holdNextRefresh(page, pattern, interval) {
  let resolveRoute;
  let timeout;
  const received = new Promise((resolve, reject) => {
    resolveRoute = resolve;
    timeout = setTimeout(() => reject(new Error(`No refresh request for ${pattern}`)), 10000);
  });
  await page.route(pattern, route => resolveRoute(route), {times: 1});
  const completed = await page.evaluate(() => window.finishedRefreshes);
  await page.clock.runFor(interval + 100);
  const route = await received;
  clearTimeout(timeout);
  return async () => {
    await route.continue();
    await page.waitForFunction(previous => window.finishedRefreshes > previous, completed);
  };
}

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  const errors = [];
  async function open(scenario, width = 1400, prepare = async () => {}) {
    const page = await browser.newPage({viewport: {width, height: 1000}, reducedMotion: 'reduce'});
    page.setDefaultTimeout(10000);
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await page.addInitScript(() => {
      window.finishedRefreshes = 0;
      document.addEventListener('htmx:finally:request', () => { window.finishedRefreshes++; });
    });
    await page.clock.install();
    await prepare(page);
    await page.goto(`${process.argv[2]}/?case=${scenario}`);
    return page;
  }
  try {
    for (const scenario of scenarios) {
      const page = await open(scenario.page, scenario.width);
      const control = page.locator(scenario.control).first();
      const assertFocus = scenario.restoresFocus ? assertRestoredFocus : assertOriginalFocus;
      await rememberControl(control);
      await refresh(page, scenario.interval);
      await assertFocus(control);
      await page.keyboard.press('Tab');
      assert.equal(await page.evaluate(() => document.activeElement !== document.body), true, 'Tab must continue from the retained control');
      await page.keyboard.press('Shift+Tab');
      await assertFocus(control);
      await rememberControl(control);
      await page.locator('#main-content').focus();
      await refresh(page, scenario.interval);
      await page.waitForFunction(() => !window.originalControl.isConnected);
      assert.equal(await page.locator('#main-content').evaluate(element => element === document.activeElement), true, 'refresh must not pull focus back into the panel');
      console.log(`PASS ${scenario.name}: focus, tab order, and polling resumes`);
      await page.close();
    }

    {
      const page = await open('update');
      const finish = await holdNextRefresh(page, '**/ui/updates', 2000);
      const opener = page.locator('#update-release-notes-dialog-open');
      await opener.click();
      const dialog = page.locator('#update-release-notes-dialog');
      const done = dialog.getByRole('button', {name: 'Done', exact: true});
      await rememberControl(done);
      await finish();
      assert.equal(await dialog.evaluate(element => element.open), true, 'release notes must stay open when a pending refresh arrives');
      await assertOriginalFocus(done);
      await done.click();
      assert.equal(await opener.evaluate(element => element === document.activeElement), true, 'closing release notes must return focus to the opener');
      await rememberControl(opener);
      await refresh(page, 2000);
      await assertRestoredFocus(opener);
      console.log('PASS release notes survive a pending refresh; closing restores focus and resumes progress');
      await page.close();
    }

    for (const scenario of [
      {page: 'logs', control: '[data-query-filters-toggle]', url: '**/ui/logs/queries**', interval: 3000},
      {page: 'unifi', control: '[data-dialog-open="remove-unifi-dialog"]', url: '**/ui/integrations/unifi/status', interval: 10000},
      {page: 'cluster', control: '.cluster-node-portal', url: '**/ui/cluster/status', interval: 2000},
    ]) {
      const page = await open(scenario.page);
      const finish = await holdNextRefresh(page, scenario.url, scenario.interval);
      const control = page.locator(scenario.control).first();
      await rememberControl(control);
      await finish();
      await assertOriginalFocus(control);
      await page.locator('#main-content').focus();
      await refresh(page, scenario.interval);
      await page.waitForFunction(() => !window.originalControl.isConnected);
      console.log(`PASS ${scenario.page}: interaction begun during an in-flight refresh`);
      await page.close();
    }

    {
      const page = await open('logs');
      const finish = await holdNextRefresh(page, '**/ui/logs/queries**', 3000);
      await page.locator('[data-log-live-toggle]').click();
      await page.locator('#main-content').focus();
      await finish();
      assert.equal(await page.locator('#query-logs-panel').getAttribute('data-live'), 'false');
      const completed = await page.evaluate(() => window.finishedRefreshes);
      await page.clock.runFor(6000);
      assert.equal(await page.evaluate(() => window.finishedRefreshes), completed);
      console.log('PASS pausing logs discards a pending refresh and remains paused');
      await page.close();
    }

    {
      let pending;
      const page = await open('loading', 1400, async page => {
        await page.route('**/ui/stats/insights**', route => { pending = route; }, {times: 1});
      });
      await page.keyboard.press('ControlOrMeta+k');
      assert.equal(await page.locator('[data-command-palette]').evaluate(element => element.open), true);
      assert.ok(pending, 'initial insights request must be in flight');
      await pending.continue();
      await page.locator('a.ranking-row').first().waitFor();
      assert.equal(await page.locator('[data-command-palette]').evaluate(element => element.open), true);
      console.log('PASS initial insights load completes behind an unrelated dialog');
      await page.close();
    }

    {
      const page = await open('chart', 600);
      const finish = await holdNextRefresh(page, '**/ui/stats/chart**', 10000);
      const picker = page.locator('.range-select .styled-select-trigger');
      await picker.click();
      const option = page.locator('.range-select [role="option"][data-value="hour"]');
      await rememberControl(option);
      await finish();
      await assertOriginalFocus(option);
      assert.equal(await picker.getAttribute('aria-expanded'), 'true');
      await page.keyboard.press('ArrowDown');
      await page.keyboard.press('Enter');
      await page.waitForFunction(() => document.querySelector('#chart-range-day').getAttribute('aria-pressed') === 'true');
      console.log('PASS mobile range picker stays open during polling and a selection still updates the chart');
      await page.close();
    }

    {
      const page = await open('insights');
      const finish = await holdNextRefresh(page, '**/ui/stats/insights**', 60000);
      await page.locator('[data-dialog-open="top-stats-domains-dialog"]').click();
      const search = page.locator('#top-stats-domains-dialog input');
      await search.fill('example');
      await finish();
      assert.equal(await page.locator('#top-stats-domains-dialog').evaluate(element => element.open), true);
      assert.equal(await search.inputValue(), 'example');
      await page.keyboard.press('Escape');
      await page.locator('#main-content').focus();
      await refresh(page, 60000);
      console.log('PASS ranking dialog survives a pending refresh and polling resumes after dismissal');
      await page.close();
    }

    {
      const page = await open('backup');
      const finish = await holdNextRefresh(page, '**/ui/backup/progress', 400);
      const directory = page.locator('input[name="directory"]');
      await rememberControl(directory);
      await directory.fill('draft-backups');
      await finish();
      await assertOriginalFocus(directory);
      await page.locator('#main-content').focus();
      await refresh(page, 400);
      assert.equal(await directory.inputValue(), 'draft-backups', 'blur must not discard unsaved edits');
      await page.getByRole('button', {name: 'Save Schedule', exact: true}).click();
      await page.waitForFunction(() => !window.originalControl.isConnected);
      assert.equal(await directory.inputValue(), 'draft-backups');
      await directory.evaluate(element => { window.originalControl = element; });
      await page.locator('#main-content').focus();
      await refresh(page, 400);
      await page.waitForFunction(() => !window.originalControl.isConnected);
      assert.equal(await directory.inputValue(), 'draft-backups');
      console.log('PASS backup drafts survive focus changes and pending refreshes; saving resumes polling');
      await page.route('**/ui/backup/progress', route => route.continue({url: `${route.request().url()}?complete=1`}), {times: 1});
      await refresh(page, 400);
      assert.equal(await page.locator('#backup-panel').getAttribute('hx-trigger'), null);
      const completed = await page.evaluate(() => window.finishedRefreshes);
      await page.clock.runFor(2000);
      assert.equal(await page.evaluate(() => window.finishedRefreshes), completed);
      console.log('PASS backup polling stops when the job completes');
      await page.close();
    }
    assert.deepEqual(errors, [], 'browser errors or CSP violations');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
