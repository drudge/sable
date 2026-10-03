const assert = require('node:assert/strict');
const {chromium} = require('playwright');

const explainerOpen = page => page.locator('[data-cache-explainer]').evaluate(element => element.open);

const refresh = async (page, entries) => {
  const response = page.waitForResponse(response => response.url().endsWith('/ui/cache/status'));
  await page.getByRole('button', {name: 'Refresh cache status'}).click();
  assert.equal((await response).status(), 200);
  await page.locator('#cache-content').getByText(entries, {exact: true}).waitFor();
};

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const phone = await browser.newPage({viewport: {width: 390, height: 844}});
    await phone.goto(process.argv[2]);
    assert.equal(await explainerOpen(phone), false, 'explainer starts collapsed on phones');
    await refresh(phone, '1,001');
    assert.equal(await explainerOpen(phone), false, 'explainer stays collapsed after a refresh swap');
    console.log('PASS cache explainer stays collapsed on phones after refresh');

    const desktop = await browser.newPage({viewport: {width: 1280, height: 900}});
    await desktop.goto(process.argv[2]);
    assert.equal(await explainerOpen(desktop), true, 'explainer starts expanded on desktop');
    await refresh(desktop, '1,002');
    assert.equal(await explainerOpen(desktop), true, 'explainer stays expanded after a refresh swap');
    console.log('PASS cache explainer stays expanded on desktop after refresh');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
