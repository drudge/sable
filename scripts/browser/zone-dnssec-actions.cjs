const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// The DNSSEC dialog's key actions live inside its settings form. Each one
// reaches its own endpoint with its own value rather than saving the form.
(async () => {
  const [baseURL] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900}});
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));

    for (const [button, expected] of [
      ['Roll ZSK', '/ui/zones/dnssec/rollover role=zsk'],
      ['Roll KSK', '/ui/zones/dnssec/rollover role=ksk'],
      ['Confirm Parent DS', '/ui/zones/dnssec/confirm-ds key_tag=12345'],
    ]) {
      await page.goto(baseURL);
      await page.evaluate(() => document.getElementById('dnssec-dialog').showModal());
      await page.getByRole('dialog', {name: 'DNSSEC'}).getByRole('button', {name: button}).click();
      const result = page.locator('[data-fixture-result]');
      await result.waitFor();
      assert.equal(await result.textContent(), expected, `${button} posts to its own endpoint`);
    }
    assert.deepEqual(errors, []);
    console.log('PASS DNSSEC key actions post to their own endpoints');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
