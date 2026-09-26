const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Opens Hide Finding beside Why Sable surfaced this, backs out of its menu
// with Escape without losing the drawer, checks it fits a phone, and marks the
// finding normal.
(async () => {
  const [baseURL, cookieName] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900}});
    await context.addCookies([{name: cookieName, value: 'everything', url: baseURL}]);
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));

    await page.goto(`${baseURL}/insights?range=day`);
    await page.locator('#insight-findings').waitFor();
    const findings = page.locator('#insight-findings .insight-finding');
    const listed = await findings.count();
    await page.getByRole('button', {name: 'View details for telemetry.example.com'}).click();
    const drawer = page.getByRole('dialog', {name: 'telemetry.example.com'});
    await drawer.waitFor();

    // The choices start folded away behind Hide Finding.
    const hide = drawer.locator('.insight-hide-menu > summary', {hasText: 'Hide Finding'});
    const normal = drawer.getByRole('button', {name: /That's Normal/});
    assert.equal(await normal.isVisible(), false, 'the choices start folded away');
    await hide.click();
    await normal.waitFor();
    for (const choice of [/For a Day/, /For a Week/]) {
      assert.equal(await drawer.getByRole('button', {name: choice}).isVisible(), true, `${choice} is offered`);
    }

    // Escape closes the menu and keeps the drawer.
    await page.keyboard.press('Escape');
    await normal.waitFor({state: 'hidden'});
    assert.equal(await drawer.isVisible(), true, 'Escape keeps the drawer open');
    assert.equal(await page.evaluate(() => document.activeElement?.textContent), 'Hide Finding', 'focus goes back to Hide Finding');

    // On a phone the first reason starts clear of the button, which sits on
    // the heading's line, and the menu stays inside the drawer's body.
    await page.setViewportSize({width: 390, height: 844});
    // Crossing into the phone layout replays the drawer's slide-up, so let it
    // settle before measuring anything in it.
    await drawer.evaluate(dialog => Promise.all(dialog.getAnimations({subtree: true}).map(animation => animation.finished)));
    const button = await hide.boundingBox();
    const reason = await drawer.locator('.insight-why li').first().boundingBox();
    assert.ok(reason.y >= button.y + button.height + 4, `the first reason clears the button: ${JSON.stringify({button, reason})}`);
    await hide.click();
    await normal.waitFor();
    const menu = await drawer.locator('.insight-hide-menu > form').boundingBox();
    const body = await drawer.locator('.query-detail-body').boundingBox();
    assert.ok(
      menu.x >= body.x && menu.x + menu.width <= body.x + body.width + 0.5 &&
        menu.y >= body.y && menu.y + menu.height <= body.y + body.height + 0.5,
      `the menu fits the drawer: ${JSON.stringify({menu, body})}`,
    );

    // Choosing hides the finding for everyone and closes the drawer.
    await normal.click();
    await drawer.waitFor({state: 'hidden'});
    await page.getByText('1 hidden finding').waitFor();
    assert.equal(await findings.count(), listed - 1, 'the finding leaves the list');
    assert.deepEqual(errors, []);
    console.log('PASS a finding hides from the menu beside its reasons, and Escape keeps the drawer');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
