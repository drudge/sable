const assert = require('node:assert/strict');
const {chromium} = require('playwright');
const fs = require('node:fs/promises');

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const page = await browser.newPage({viewport: {width: 390, height: 844}});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route("**/ui/updates/automatic-check", route => route.fulfill({status: 202}), {times: 1});
    await page.goto(process.argv[2]);
    const notice = page.locator('[data-update-version]');
    await notice.waitFor();
    assert.equal(await notice.locator('details').count(), 0, 'notification has no release notes disclosure');
    await notice.getByRole('button', {name: 'Release notes', exact: true}).click();
    const notesDialog = page.locator('#notification-release-notes-dialog');
    await notesDialog.waitFor({state: 'visible'});
    assert.match(await notesDialog.innerText(), /Rolling updates/);
    assert.equal(await notesDialog.locator("h3").innerText(), "Improvements", "release notes render Markdown headings");
    const releaseLink = await notesDialog.getByRole('link', {name: 'View release'}).boundingBox();
    const done = await notesDialog.getByRole('button', {name: 'Done', exact: true}).boundingBox();
    assert.ok(done.y >= releaseLink.y + releaseLink.height, 'Done follows View release on mobile');
    assert.equal(await page.evaluate(() => window.releaseNotesExecuted), undefined);
    assert.equal(await page.locator('.about-version-copy a').getAttribute('href'), 'https://github.com/drudge/sable/releases/tag/v1.0.0');
    const bounds = await notice.boundingBox();
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 390, 'mobile notification fits the viewport');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'release notes do not overflow');
    await notesDialog.getByRole('button', {name: 'Done', exact: true}).click();
    assert.equal(await notice.getByRole('button', {name: 'Release notes', exact: true}).evaluate(element => element === document.activeElement), true, 'closing notes restores focus');
    await page.locator('#about-update').getByRole('button', {name: 'Release notes', exact: true}).click();
    assert.equal(await page.locator('#update-release-notes-dialog .release-notes-content').innerHTML(), await notesDialog.locator('.release-notes-content').innerHTML(), 'About and notification use the same notes dialog content');
    await page.locator('#update-release-notes-dialog').getByRole('button', {name: 'Done', exact: true}).click();
    if (process.env.SABLE_UPDATE_SCREENSHOTS) {
      await fs.mkdir(process.env.SABLE_UPDATE_SCREENSHOTS, {recursive: true});
      await page.screenshot({path: `${process.env.SABLE_UPDATE_SCREENSHOTS}/notification-mobile.png`, fullPage: true});
    }
    await notice.locator('[data-toast-close]').click();
    await notice.waitFor({state: 'detached'});
    assert.equal(await notesDialog.count(), 0, 'dismissing the notification removes its dialog');
    await page.reload();
    assert.equal(await page.locator('[data-update-version]').count(), 0, 'dismissed notification is not repeated in the session');
    assert.equal(await (await page.request.get(`${process.argv[2]}/checks`)).json(), 1, 'same session does not recheck');
    await page.evaluate(() => sessionStorage.clear());
    await page.goto(`${process.argv[2]}/?disabled`);
    assert.equal(await (await page.request.get(`${process.argv[2]}/checks`)).json(), 1, 'opt-out prevents checks');
    await page.setViewportSize({width: 1440, height: 1000});
    await page.goto(`${process.argv[2]}/cluster?disabled`);
    assert.match(await page.locator('.cluster-update-card').innerText(), /ns3-latham/);
    assert.equal(await page.locator('[hx-post="/ui/updates/cluster/stop"]').count(), 1);
    if (process.env.SABLE_UPDATE_SCREENSHOTS) await page.screenshot({path: `${process.env.SABLE_UPDATE_SCREENSHOTS}/cluster-desktop.png`, fullPage: true});
    const installPage = await browser.newPage();
    await installPage.goto(`${process.argv[2]}/cluster`);
    await installPage.locator('[data-update-version]').getByRole('button', {name: 'Install v1.1.0', exact: true}).click();
    const confirmation = installPage.locator('dialog.confirmation-dialog[open]');
    await confirmation.waitFor({state: 'visible'});
    assert.equal(await (await page.request.get(`${process.argv[2]}/installs`)).json(), 0, 'install waits for confirmation');
    await confirmation.getByRole('button', {name: 'Download & Install', exact: true}).click();
    await installPage.waitForURL('**/about#about-update');
    assert.equal(await (await page.request.get(`${process.argv[2]}/installs`)).json(), 1, 'notification installs from a page without an About panel');
    await installPage.close();
    assert.deepEqual(errors, []);
    console.log('PASS login notice, release notes, escaping, release links, mobile layout, dismissal, opt-out, and cluster progress');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
