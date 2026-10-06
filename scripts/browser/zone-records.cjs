const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Delete Record in a record's dialog asks first. Cancel keeps the record and
// sends nothing; confirming removes it rather than saving the form as an
// update.
(async () => {
  const [baseURL] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900}});
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const posts = [];
    page.on('request', request => { if (request.method() === 'POST') posts.push(new URL(request.url()).pathname); });

    await page.goto(`${baseURL}/zones/example.test`);
    const row = page.locator('[data-record-row]', {hasText: '192.0.2.10'});
    const openRecord = async () => {
      await row.getByRole('button', {name: 'Edit A record'}).click();
      const dialog = page.getByRole('dialog', {name: 'Edit DNS Record'});
      await dialog.getByRole('button', {name: 'Delete Record'}).waitFor();
      return dialog;
    };

    // Cancel backs out without a request.
    let dialog = await openRecord();
    await dialog.getByRole('button', {name: 'Delete Record'}).click();
    const confirmation = page.getByRole('dialog', {name: 'Delete this record?'});
    await confirmation.waitFor();
    assert.match(await confirmation.textContent(), /Delete the A record for “www\.example\.test”\?/);
    await confirmation.getByRole('button', {name: 'Cancel'}).click();
    await confirmation.waitFor({state: 'hidden'});
    assert.deepEqual(posts, [], 'cancelling sends nothing');
    assert.equal(await dialog.isVisible(), true, 'the record dialog stays open');

    // Confirming deletes the record.
    await dialog.getByRole('button', {name: 'Delete Record'}).click();
    await confirmation.getByRole('button', {name: 'Delete Record'}).click();
    await page.getByText('Record removed and SOA serial advanced').first().waitFor();
    assert.deepEqual(posts, ['/ui/zones/records/delete'], 'the delete endpoint receives the request');
    await row.waitFor({state: 'detached'});
    assert.equal(await page.locator('[data-record-row]', {hasText: '192.0.2.20'}).count(), 1, 'other records stay');
    assert.deepEqual(errors, []);
    console.log('PASS Delete Record asks first and removes the record');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
