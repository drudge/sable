const assert = require('node:assert/strict');

async function check(page, label, action) {
  await action();
  console.log(`PASS ${label}`);
}

function deferredRoute() {
  let resolve;
  const intercepted = new Promise(result => { resolve = result; });
  return {intercepted, handler: route => resolve(route)};
}

async function waitForRoute(intercepted, label) {
  let timer;
  try {
    return await Promise.race([
      intercepted,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} was not intercepted`)), 10000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

module.exports = async function checkCommandPalettePosts(page, baseURL, errors) {
  await check(page, 'command palette posts use HTMX targets and status', async () => {
    const checkRoute = deferredRoute();
    let requestCount = 0;
    await page.route('**/ui/updates/command-check', route => {
      requestCount++;
      checkRoute.handler(route);
    });
    await page.goto(`${baseURL}/?dashboard`);
    const open = page.locator('[data-command-open]').first();
    const command = page.locator('#command-action-check-updates');
    await open.click();
    await command.click();
    await page.waitForFunction(() => Boolean(document.querySelector('#command-action-check-updates')?.dataset.commandPending));
    const pendingRoute = await waitForRoute(checkRoute.intercepted, 'update check request');
    await page.evaluate(() => document.querySelector('#command-action-check-updates').click());
    assert.equal(requestCount, 1, 'duplicate command clicks are ignored while pending');
    const checkRequest = pendingRoute.request();
    assert.equal(checkRequest.method(), 'POST');
    assert.equal(checkRequest.headers()['x-csrf-token'], 'fixture-csrf');
    assert.equal(checkRequest.headers()['hx-target'], '#command-feedback');
    assert.equal(checkRequest.postData(), null);
    await page.evaluate(() => {
      window.removedCommand = document.querySelector('#command-action-check-updates');
      window.removedCommand.remove();
    });
    await pendingRoute.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<div class="toast-region"><div class="toast toast-success" data-toast role="status"><p>Update check completed.</p></div></div>',
    });
    await page.locator('[data-notification-stack] .toast-region').waitFor();
    await page.waitForFunction(() => window.removedCommand && !window.removedCommand.isConnected && !window.removedCommand.dataset.commandPending && !window.removedCommand.hasAttribute('aria-busy'));
    await page.waitForFunction(() => document.querySelector('[data-a11y-announcer]')?.textContent === 'Check for Updates completed');
    assert.equal(await page.locator('[data-notification-stack] .toast-region').count(), 1, 'off-page commands use the shared notification stack');
    assert.equal(await page.locator('#command-feedback .toast-region').count(), 0, 'mounted notifications leave the command target reusable');
    await page.unroute('**/ui/updates/command-check');

    const pauseRoute = deferredRoute();
    await page.route('**/ui/blocking/pause', pauseRoute.handler);
    await page.goto(`${baseURL}/?blocking`);
    const pause = page.locator('#command-action-pause-blocking-5');
    await page.locator('[data-command-open]').first().click();
    await pause.click();
    await page.waitForFunction(() => Boolean(document.querySelector('#command-action-pause-blocking-5')?.dataset.commandPending));
    const pauseResponse = await waitForRoute(pauseRoute.intercepted, 'pause request');
    const pauseRequest = pauseResponse.request();
    assert.equal(pauseRequest.method(), 'POST');
    assert.equal(pauseRequest.headers()['x-csrf-token'], 'fixture-csrf');
    assert.equal(pauseRequest.headers()['hx-target'], '#blocking-content');
    assert.match(pauseRequest.postData(), /minutes=5/);
    await pauseResponse.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<div id="blocking-content" data-blocking-state="paused"><h1>DNS Blocking</h1><p>Paused for 5 minutes.</p></div>',
    });
    await page.waitForFunction(() => document.querySelector('#blocking-content')?.dataset.blockingState === 'paused');
    await page.waitForFunction(() => !document.querySelector('#command-action-pause-blocking-5')?.dataset.commandPending);
    await page.waitForFunction(() => document.querySelector('[data-a11y-announcer]')?.textContent === 'Pause Blocking for 5 Minutes completed');

    const markedRoute = deferredRoute();
    await page.route('**/ui/blocking/lists/update', markedRoute.handler);
    await page.locator('[data-command-open]').first().click();
    const update = page.locator('#command-action-update-block-lists');
    await update.click();
    await page.waitForFunction(() => Boolean(document.querySelector('#command-action-update-block-lists')?.dataset.commandPending));
    const markedError = await waitForRoute(markedRoute.intercepted, 'marked block-list update request');
    assert.equal(markedError.request().headers()['x-csrf-token'], 'fixture-csrf');
    await markedError.fulfill({
      status: 422,
      contentType: 'text/html',
      headers: {'X-Sable-Console-Fragment': 'true'},
      body: '<div id="blocking-content" data-blocking-state="update-error"><p>Could not update the block lists.</p></div>',
    });
    await page.waitForFunction(() => document.querySelector('#blocking-content')?.dataset.blockingState === 'update-error');
    await page.waitForFunction(() => !document.querySelector('#command-action-update-block-lists')?.dataset.commandPending);
    await page.waitForFunction(() => document.querySelector('[data-a11y-announcer]')?.textContent === 'Update Block Lists failed');
    await page.unroute('**/ui/blocking/lists/update');
    const expectedMarkedError = 'Failed to load resource: the server responded with a status of 422 (Unprocessable Entity)';
    for (let index = errors.length - 1; index >= 0; index--) {
      if (errors[index] === expectedMarkedError) errors.splice(index, 1);
    }
    await page.unroute('**/ui/blocking/pause');

    const badRoute = deferredRoute();
    await page.route('**/ui/blocking/pause', badRoute.handler);
    await page.goto(`${baseURL}/?blocking`);
    const failedPause = page.locator('#command-action-pause-blocking-5');
    await page.locator('[data-command-open]').first().click();
    await failedPause.click();
    await page.waitForFunction(() => Boolean(document.querySelector('#command-action-pause-blocking-5')?.dataset.commandPending));
    const badResponse = await waitForRoute(badRoute.intercepted, 'bare error pause request');
    assert.equal(badResponse.request().headers()['x-csrf-token'], 'fixture-csrf');
    await badResponse.fulfill({status: 503, contentType: 'text/plain', body: 'service unavailable'});
    await page.waitForFunction(() => !document.querySelector('#command-action-pause-blocking-5')?.dataset.commandPending);
    await page.waitForFunction(() => document.querySelector('[data-a11y-announcer]')?.textContent === 'Pause Blocking for 5 Minutes failed');
    assert.equal(await page.locator('#blocking-content').count(), 1, 'bare command errors do not replace the blocking panel');
    await page.unroute('**/ui/blocking/pause');
    const expectedConsoleError = 'Failed to load resource: the server responded with a status of 503 (Service Unavailable)';
    for (let index = errors.length - 1; index >= 0; index--) {
      if (errors[index] === expectedConsoleError) errors.splice(index, 1);
    }
    const abortRoute = deferredRoute();
    const networkErrorStart = errors.length;
    await page.route('**/ui/updates/command-check', abortRoute.handler);
    await page.goto(`${baseURL}/?dashboard`);
    const networkFailure = page.locator('#command-action-check-updates');
    await page.locator('[data-command-open]').first().click();
    await networkFailure.click();
    await page.waitForFunction(() => Boolean(document.querySelector('#command-action-check-updates')?.dataset.commandPending));
    const abortedRequest = await waitForRoute(abortRoute.intercepted, 'network failure request');
    await abortedRequest.abort();
    await page.waitForFunction(() => !document.querySelector('#command-action-check-updates')?.dataset.commandPending);
    await page.waitForFunction(() => document.querySelector('[data-a11y-announcer]')?.textContent === 'Check for Updates failed');
    await page.unroute('**/ui/updates/command-check');
    const networkErrors = errors.splice(networkErrorStart);
    assert.equal(networkErrors.length, 2, 'network failure only reports its expected browser and HTMX errors');
    assert.ok(networkErrors.includes('Failed to load resource: net::ERR_FAILED'));
    assert.ok(networkErrors.some(error => error.startsWith('htmx: htmx:error: Failed to fetch')));
  });
}
