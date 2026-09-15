const assert = require('node:assert/strict');
const {chromium} = require('playwright');

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({javaScriptEnabled: false});
    await context.addCookies([{name: process.argv[3], value: 'session-token', url: process.argv[2]}]);
    const page = await context.newPage();
    await page.goto(`${process.argv[2]}/profile`);
    await page.locator('input[name="display_name"]').fill('Native Name');
    await page.locator('input[name="email"]').fill('native@example.test');
    const responsePromise = page.waitForResponse(response => response.url() === `${process.argv[2]}/ui/profile` && response.request().method() === 'POST');
    await page.getByRole('button', {name: 'Save Changes', exact: true}).click();
    const response = await responsePromise;
    assert.equal(response.status(), 303);
    await page.waitForFunction(() => document.querySelector('input[name="display_name"]')?.value === 'Native Name');
    assert.equal(await page.locator('input[name="email"]').inputValue(), 'native@example.test');
    assert.match(page.url(), /\/profile$/);
    console.log('PASS native profile form submits with JavaScript disabled');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
