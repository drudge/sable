const assert = require('node:assert/strict');

function assertSameBounds(before, after, message) {
  for (const dimension of ['x', 'y', 'width', 'height']) {
    assert.ok(Math.abs(before[dimension] - after[dimension]) < 0.5, `${message}: ${dimension}`);
  }
}

async function checkConnectionToast(page) {
  const toast = page.locator('[data-block-list-error] .toast-error');
  await toast.waitFor({state: 'visible'});
  assert.equal(await page.locator('.toast-error').count(), 1, 'one error toast is shown');
  assert.match(await toast.textContent(), /Could not confirm.*refresh the page/);
  assert.equal(await toast.getAttribute('role'), 'alert');
  assert.equal(await toast.getAttribute('data-toast-duration'), '0', 'connection errors wait to be dismissed');
  const dismiss = toast.getByRole('button', {name: 'Dismiss notification'});
  await dismiss.click({trial: true});
  const bounds = await toast.boundingBox();
  const viewport = page.viewportSize();
  assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= viewport.width, `toast fits viewport width: ${JSON.stringify({bounds, viewport})}`);
  assert.ok(bounds.y >= 0 && bounds.y + bounds.height <= viewport.height, `toast fits viewport height: ${JSON.stringify({bounds, viewport})}`);
  return dismiss;
}

module.exports = async function checkBlockListFeedback(browser, baseURL) {
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  const errors = [];
  const consoleErrors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
  let receiveRequest;
  let receiveDeleteRequest;
  let receiveListDeleteRequest;
  let requestCount = 0;
  const deleteRequests = [];
  const listDeleteRequests = [];
  await page.route('**/ui/blocking/lists/add', route => {
    requestCount++;
    receiveRequest(route);
  });
  await page.route(/\/ui\/blocking\/(allowed|domains)\/delete$/, route => {
    const request = route.request();
    deleteRequests.push(request);
    receiveDeleteRequest?.(request);
    receiveDeleteRequest = undefined;
    route.fulfill({status: 204});
  });
  await page.route('**/ui/blocking/lists/delete', route => {
    const request = route.request();
    listDeleteRequests.push(request);
    receiveListDeleteRequest?.(request);
    receiveListDeleteRequest = undefined;
    route.fulfill({status: 204});
  });
  try {
    for (const mode of ['catalog', 'catalog-mobile', 'custom', 'server-error', 'connection-error', 'http-error']) {
      const height = mode === 'catalog' ? 900 : 667;
      await page.setViewportSize({width: mode === 'catalog' ? 1400 : 375, height});
      await page.goto(`${baseURL}/?blocking`);
      await page.locator('[data-dialog-open="add-block-list-dialog"]').click();
      const dialog = page.locator('#add-block-list-dialog');
      assert.equal(
        await dialog.evaluate(element => getComputedStyle(element, '::backdrop').backdropFilter),
        'blur(4px)',
        `${mode}: modal backdrop blurs the page`,
      );
      const custom = !mode.startsWith('catalog');
      const url = mode === 'server-error' ? 'https://example.test/unavailable.txt' : 'https://example.test/large.txt';
      if (custom) {
        await dialog.getByRole('tab', {name: 'Custom', exact: true}).click();
        // Native validation must not enter a pending state.
        await dialog.locator('button[type="submit"]').click();
        assert.equal(await dialog.locator('[aria-busy="true"]').count(), 0);
        assert.equal(await dialog.locator('.block-list-add-pending:visible').count(), 0);
        await dialog.getByRole('textbox', {name: 'Block List URL'}).fill(url);
      }
      const button = custom ? dialog.locator('button[type="submit"]') : dialog.locator('#catalog-panel-popular [data-block-list-add]').first();
      const source = custom ? dialog.locator('form') : button;
      assert.equal(await button.locator('.icon-plus').isVisible(), true, `${mode}: Add icon is visible before submission`);
      await dialog.evaluate(element => Promise.all(element.getAnimations().map(animation => animation.finished)));
      const dialogBounds = await dialog.boundingBox();
      const buttonBounds = await button.boundingBox();
      requestCount = 0;
      const pending = new Promise(resolve => { receiveRequest = resolve; });
      await button.click();
      const request = await pending;
      assert.equal(await source.getAttribute('aria-busy'), 'true');
      assert.equal(await button.locator('.block-list-add-pending').isVisible(), true);
      assert.equal(await button.locator('.icon-loader-circle').isVisible(), true, `${mode}: loading spinner is visible`);
      assert.equal(await button.locator('.icon-loader-circle').evaluate(element => getComputedStyle(element).animationName), 'blocking-refresh-spin');
      assert.equal(await dialog.locator('.block-list-add-button:enabled').count(), 0);
      assert.equal(await dialog.locator('input[type="url"]').isDisabled(), true);
      assertSameBounds(dialogBounds, await dialog.boundingBox(), `${mode}: dialog stays in place while downloading`);
      assertSameBounds(buttonBounds, await button.boundingBox(), `${mode}: Add button stays in place while downloading`);
      assert.equal(await page.locator('[data-toast]').count(), 0, 'loading shows only the spinner');
      await button.evaluate(element => element.click());
      assert.equal(requestCount, 1, 'repeated clicks cannot submit duplicate additions');
      const data = new URLSearchParams(request.request().postData());
      assert.equal(data.get('format'), 'auto');
      assert.equal(data.get('url'), custom ? url : 'https://big.oisd.nl/');
      if (mode === 'connection-error' || mode === 'http-error') {
        if (mode === 'connection-error') await request.abort('failed');
        else await request.fulfill({status: 503, contentType: 'text/plain', body: 'Service unavailable'});
        const dismiss = await checkConnectionToast(page);
        await page.waitForFunction(() => !document.querySelector('#add-block-list-dialog .htmx-request'));
        assert.equal(await source.getAttribute('aria-busy'), null);
        assert.equal(await button.isEnabled(), true);
        assert.equal(await dialog.locator('input[type="url"]').inputValue(), url);
        assert.equal(await button.locator('.block-list-add-pending').isVisible(), false);
        assert.equal(await button.locator('.icon-plus').isVisible(), true, 'Add icon returns after a failed request');
        assertSameBounds(dialogBounds, await dialog.boundingBox(), `${mode}: error toast does not move the dialog`);
        if (mode === 'http-error') {
          await dismiss.click();
          await page.locator('[data-block-list-error]').waitFor({state: 'detached'});
        }
        // The form remains usable if the operator retries after checking.
        const retry = new Promise(resolve => { receiveRequest = resolve; });
        await button.click();
        const retriedRequest = await retry;
        assert.equal(await page.locator('[data-block-list-error]').count(), 0, 'retry clears the previous connection error');
        await retriedRequest.continue();
      } else {
        await request.continue();
      }
      await page.waitForFunction(() => !document.querySelector('#add-block-list-dialog')?.open);
      assert.equal(await page.locator('#blocking-content .htmx-request').count(), 0);
      assert.match(await page.locator('.toast-region').textContent(), mode === 'server-error' ? /Could not download/ : /Block list added and compiled/);
      assert.equal(await page.locator('[data-toast]').count(), 1, 'rendered responses do not produce duplicate toasts');
      await page.locator('[data-dialog-open="add-block-list-dialog"]').click();
      assert.equal(await dialog.locator('.block-list-add-button:disabled').count(), 0);
      if (mode.startsWith('catalog') || mode === 'custom') assert.deepEqual(consoleErrors, [], 'normal additions produce no browser errors');
      console.log(`PASS block list feedback: ${mode}`);
    }

    await page.route('**/ui/blocking/lists/update', route => { receiveRequest(route); });
    for (const mode of ['server-error', 'connection-error', 'http-error']) {
      await page.goto(`${baseURL}/?blocking`);
      const button = page.locator('[data-blocking-update]');
      const pending = new Promise(resolve => { receiveRequest = resolve; });
      await button.click();
      const request = await pending;
      assert.equal(await button.getAttribute('aria-busy'), 'true');
      assert.equal(await button.isDisabled(), true);
      if (mode === 'server-error') {
        await request.continue();
        await page.getByText('Could not update the block lists.', {exact: true}).waitFor();
        assert.equal(await page.locator('.toast-error').count(), 1);
        assert.equal(await page.locator('[data-block-list-error]').count(), 0);
      } else {
        if (mode === 'connection-error') await request.abort('failed');
        else await request.fulfill({status: 503, contentType: 'text/plain', body: 'Service unavailable'});
        const dismiss = await checkConnectionToast(page);
        await dismiss.click();
        await page.locator('[data-block-list-error]').waitFor({state: 'detached'});
      }
      await page.waitForFunction(() => !document.querySelector('[data-blocking-update]').disabled);
      assert.equal(await button.getAttribute('aria-busy'), null);
      assert.equal(await button.evaluate(element => element.classList.contains('htmx-request')), false);
      console.log(`PASS block list update feedback: ${mode}`);
    }

    await page.goto(`${baseURL}/?blocking`);
    const listRemove = page.getByRole('button', {name: 'Remove Fixture Block List', exact: true});
    await listRemove.click();
    const listConfirmation = page.locator('dialog.confirmation-dialog[open]');
    await listConfirmation.waitFor();
    assert.equal(await listConfirmation.getByRole('heading').innerText(), 'Remove block list?');
    assert.equal(await listConfirmation.locator('#sable-confirm-description').innerText(), 'Remove Fixture Block List from the block lists?');
    assert.equal(await listConfirmation.locator('[data-confirm-accept]').innerText(), 'Remove Block List');
    const listRequestsBeforeCancel = listDeleteRequests.length;
    await listConfirmation.getByRole('button', {name: 'Cancel', exact: true}).click();
    assert.equal(listDeleteRequests.length, listRequestsBeforeCancel, 'cancel does not remove the block list');
    assert.equal(await listRemove.isVisible(), true, 'cancelled block list remains listed');
    await listRemove.click();
    const pendingListDelete = new Promise(resolve => { receiveListDeleteRequest = resolve; });
    await listConfirmation.locator('[data-confirm-accept]').click();
    const listDeleteRequest = await pendingListDelete;
    assert.equal(new URL(listDeleteRequest.url()).pathname, '/ui/blocking/lists/delete');
    assert.equal(new URLSearchParams(listDeleteRequest.postData()).get('name'), 'Fixture Block List');
    console.log('PASS block list removal confirmation');

    for (const policy of [
      {tab: 'Allowed', domain: 'trusted.example', title: 'Remove allowed domain?', endpoint: '/ui/blocking/allowed/delete'},
      {tab: 'Blocked', domain: 'ads.example', title: 'Remove blocked domain?', endpoint: '/ui/blocking/domains/delete'},
    ]) {
      await page.getByRole('tab', {name: policy.tab, exact: true}).click();
      const remove = page.getByRole('button', {name: `Remove ${policy.domain}`, exact: true});
      await remove.click();
      const confirmation = page.locator('dialog.confirmation-dialog[open]');
      await confirmation.waitFor();
      assert.equal(await confirmation.getByRole('heading').innerText(), policy.title);
      assert.equal(await confirmation.locator('#sable-confirm-description').innerText(), `Remove ${policy.domain} from the ${policy.tab.toLowerCase()} list?`);
      assert.equal(await confirmation.locator('[data-confirm-accept]').innerText(), 'Remove Domain');
      const requestsBeforeCancel = deleteRequests.length;
      await confirmation.getByRole('button', {name: 'Cancel', exact: true}).click();
      assert.equal(deleteRequests.length, requestsBeforeCancel, `${policy.tab}: cancel does not remove the domain`);
      assert.equal(await remove.isVisible(), true, `${policy.tab}: cancelled domain remains listed`);

      await remove.click();
      const pendingDelete = new Promise(resolve => { receiveDeleteRequest = resolve; });
      await confirmation.locator('[data-confirm-accept]').click();
      const request = await pendingDelete;
      assert.equal(new URL(request.url()).pathname, policy.endpoint);
      assert.equal(new URLSearchParams(request.postData()).get('domain'), policy.domain);
      console.log(`PASS ${policy.tab.toLowerCase()} domain removal confirmation`);
    }
    assert.deepEqual(errors, [], 'block list feedback has no unhandled errors');
    assert.equal(consoleErrors.some(message => /CSP|Content Security Policy|\[hx-csp\]/.test(message)), false);
  } finally {
    await page.close();
  }
};
