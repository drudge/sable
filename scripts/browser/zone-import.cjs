const assert = require('node:assert/strict');

module.exports = async (browser, baseURL) => {
  const page = await browser.newPage();
  try {
    await page.goto(`${baseURL}/?zone-import`);
    const dialog = page.locator('#import-new-zone-dialog');
    await page.setViewportSize({width: 375, height: 900});
    const importMenu = page.locator('.zone-import-menu');
    const importTrigger = importMenu.locator('summary');
    assert.equal(await importTrigger.locator('span').isVisible(), true);
    await importTrigger.click();
    assert.equal(await importMenu.getByText('From catalog', {exact: true}).isVisible(), true);
    const menuBounds = await importMenu.locator('div').boundingBox();
    assert.ok(menuBounds.x >= 0 && menuBounds.x + menuBounds.width <= 375);
    await page.screenshot({path: '/tmp/sable-import-menu-mobile.png'});
    await page.keyboard.press('Escape');
    assert.equal(await importMenu.getAttribute('open'), null);
    await importTrigger.click();
    await importMenu.getByRole('button', {name: 'Import zone', exact: true}).click();
    assert.equal(await importMenu.getAttribute('open'), null);
    assert.equal(await dialog.isVisible(), true);
    const file = dialog.locator('[data-zone-file]');
    const text = dialog.locator('[data-zone-import-text]');
    const submit = dialog.locator('[data-zone-import-submit]');
    assert.equal(await text.isVisible(), false);
    assert.equal(await submit.isDisabled(), true);
    await file.setInputFiles({name: 'example.zone', mimeType: 'text/plain', buffer: Buffer.from('$ORIGIN example.com.\n')});
    assert.equal(await dialog.locator('[data-zone-file-name]').innerText(), 'example.zone');
    assert.equal(await submit.isEnabled(), true);
    const zoneName = dialog.locator('[data-zone-import-name]');
    const waitForName = value => page.waitForFunction(expected => document.querySelector('[data-zone-import-name]').value === expected, value);
    await waitForName('example.com');
    await file.setInputFiles({name: 'soa.zone', mimeType: 'text/plain', buffer: Buffer.from('; ignored.example. IN SOA fake\nsoa.example. 3600 IN SOA ns.example. hostmaster.example. (1 3600 600 86400 300)')});
    await waitForName('soa.example');
    await file.setInputFiles({name: 'export.zone', mimeType: 'text/plain', buffer: Buffer.from(';; Domain: example.ca.\nexample.ca\t3600\tIN\tSOA\tns.example.net. hostmaster.example.net. 1 3600 600 86400 300')});
    await waitForName('example.ca');

    await zoneName.fill('custom.example');
    await file.setInputFiles({name: 'other.zone', mimeType: 'text/plain', buffer: Buffer.from('$ORIGIN other.example.')});
    assert.equal(await zoneName.inputValue(), 'custom.example');
    await zoneName.fill('');
    await waitForName('other.example');
    await file.setInputFiles({name: 'records.zone', mimeType: 'text/plain', buffer: Buffer.from('@ IN A 192.0.2.1')});
    await page.waitForFunction(() => document.querySelector('[data-zone-name-help]').textContent.includes('No zone name detected'));
    assert.equal(await zoneName.inputValue(), '');
    for (const [size, label] of [[1, '1 byte'], [12776, '12.8 KB'], [1500000, '1.5 MB']]) {
      await file.setInputFiles({name: 'example.zone', mimeType: 'text/plain', buffer: Buffer.alloc(size, 'a')});
      assert.equal(await dialog.locator('[data-zone-file-size]').innerText(), `${label} · Ready to import`);
    }
    const remove = dialog.locator('[data-zone-file-remove]');
    const buttonBounds = await remove.boundingBox();
    const iconBounds = await remove.locator('svg').boundingBox();
    assert.ok(Math.abs((buttonBounds.x + buttonBounds.width / 2) - (iconBounds.x + iconBounds.width / 2)) < 1, 'remove icon is horizontally centered');
    assert.ok(Math.abs((buttonBounds.y + buttonBounds.height / 2) - (iconBounds.y + iconBounds.height / 2)) < 1, 'remove icon is vertically centered');
    await dialog.locator('[data-zone-import-mode="text"]').click();
    assert.equal(await submit.isDisabled(), true);
    await text.fill('$ORIGIN pasted.example.');
    await waitForName('pasted.example');
    assert.equal(await submit.isEnabled(), true);
    assert.equal(await dialog.locator('form').evaluate(form => new FormData(form).has('file')), false);
    await dialog.locator('[data-zone-import-mode="file"]').click();
    assert.equal(await dialog.locator('form').evaluate(form => new FormData(form).has('zone_text')), false);
    assert.equal(await submit.isEnabled(), true);
    await dialog.locator('[data-zone-file-remove]').click();
    assert.equal(await submit.isDisabled(), true);
    await dialog.locator('[data-zone-dropzone]').evaluate(element => {
      const transfer = new DataTransfer();
      transfer.items.add(new File(['$ORIGIN dropped.example.'], 'dropped.zone', {type: 'text/plain'}));
      element.dispatchEvent(new DragEvent('drop', {bubbles: true, cancelable: true, dataTransfer: transfer}));
    });
    assert.equal(await dialog.locator('[data-zone-file-name]').innerText(), 'dropped.zone');
    await waitForName('dropped.example');
    assert.equal(await submit.isEnabled(), true);
    await file.setInputFiles({name: 'empty.zone', mimeType: 'text/plain', buffer: Buffer.from('')});
    assert.equal(await submit.isDisabled(), true);
    await dialog.locator('[data-zone-import-mode="text"]').click();
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {readText: async () => { throw new Error('Denied'); }}}));
    await dialog.locator('[data-zone-clipboard]').click();
    assert.match(await dialog.locator('[data-zone-import-status]').innerText(), /Press .+ to paste/);
    assert.equal(await text.inputValue(), '$ORIGIN pasted.example.');
    assert.equal(await text.evaluate(element => element === document.activeElement), true);
    await text.fill('$ORIGIN keyboard.example.');
    assert.equal(await dialog.locator('[data-zone-import-status]').innerText(), '');
    await dialog.locator('[data-zone-clipboard]').evaluate(button => { delete button.dataset.keyboardPaste; });
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {readText: async () => '$ORIGIN clipboard.example.'}}));
    await dialog.locator('[data-zone-clipboard]').click();
    assert.equal(await text.inputValue(), '$ORIGIN clipboard.example.');
    await dialog.locator('[data-zone-import-mode="file"]').click();
    await dialog.locator('[data-zone-file-remove]').click();
    for (const width of [1280, 375]) {
      await page.setViewportSize({width, height: 900});
      assert.equal(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth), true);
      await page.screenshot({path: `/tmp/sable-zone-import-${width}.png`});
    }
    await page.goto(`${baseURL}/?catalog-import`);
    const catalog = page.locator('#catalog-import-dialog');
    for (const width of [375, 658, 700]) {
      await page.setViewportSize({width, height: 900});
      const cancel = await catalog.getByRole('button', {name: 'Cancel', exact: true}).boundingBox();
      const discover = await catalog.getByRole('button', {name: 'Discover zones', exact: true}).boundingBox();
      assert.ok(Math.abs(cancel.width - discover.width) < 1, `catalog actions have equal width at ${width}px`);
      assert.ok(Math.abs(cancel.x - discover.x) < 1, 'catalog actions align');
    }
    console.log('PASS zone import upload, drop, source isolation, clipboard fallback, and mobile layout');
  } finally {
    await page.close();
  }
};
