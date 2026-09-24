const assert = require('node:assert/strict');
const {chromium} = require('playwright');
const fs = require('node:fs/promises');

async function assertDismissAlignment(regions, viewport) {
  const alignment = await regions.evaluateAll(elements => elements.map(element => {
    const button = element.querySelector('[data-toast-close]').getBoundingClientRect();
    const icon = element.querySelector('[data-toast-close] svg').getBoundingClientRect();
    return {
      x: (icon.x + icon.width / 2) - (button.x + button.width / 2),
      y: (icon.y + icon.height / 2) - (button.y + button.height / 2),
    };
  }));
  alignment.forEach(({x, y}) => {
    assert.ok(Math.abs(x) < 0.1, `${viewport} dismiss icon is horizontally centered: ${x}`);
    assert.ok(Math.abs(y) < 0.1, `${viewport} dismiss icon is vertically centered: ${y}`);
  });
}

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const page = await browser.newPage({viewport: {width: 390, height: 844}, colorScheme: 'dark'});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route("**/ui/updates/automatic-check", route => route.fulfill({status: 202}), {times: 1});
    await page.goto(process.argv[2]);
    const notice = page.locator('[data-update-version]');
    await notice.waitFor();
    assert.equal(await page.locator('.toast-success').count(), 0, 'ordinary login does not report a completed update');
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

    // Every notification source mounts into one stack. Desktop keeps the
    // newest card in front until pointer or keyboard interaction expands it;
    // touch-sized layouts remain expanded.
    await page.setViewportSize({width: 1440, height: 900});
    const addNotification = path => page.evaluate(async path => {
      await window.htmx.ajax('GET', path, {target: document.body, swap: 'beforeend'});
    }, path);
    await addNotification('/test/notification/success');
    await addNotification('/test/notification/error');
    const stack = page.locator('[data-notification-stack]');
    const regions = stack.locator(':scope > .toast-region');
    await regions.nth(2).waitFor();
    await page.mouse.move(0, 0);
    await stack.evaluate(element => Promise.all(
      element.getAnimations({subtree: true}).map(animation => animation.finished.catch(() => {})),
    ));
    assert.equal(await regions.count(), 3, 'update and ordinary notifications share one stack');
    assert.equal(await page.locator('body > .toast-region').count(), 0, 'global notifications do not create competing fixed regions');
    await page.waitForFunction(() => {
      const cards = [...document.querySelectorAll('[data-notification-stack] > .toast-region')].map(region => region.getBoundingClientRect());
      return cards.length === 3 && cards[0].width < cards[2].width - 1 && cards.slice(1).every((card, index) => cards[index].bottom > card.top);
    });
    const collapsedBounds = await regions.evaluateAll(elements => elements.map(element => element.getBoundingClientRect().toJSON()));
    const collapsedHeights = await regions.evaluateAll(elements => elements.map(element => element.offsetHeight));
    assert.ok(collapsedBounds[0].width < collapsedBounds[2].width, 'older cards scale into the collapsed deck');
    assert.ok(Math.max(...collapsedHeights) - Math.min(...collapsedHeights) < 1, 'collapsed cards use one uniform layout height');
    assert.equal(await regions.nth(0).evaluate(element => getComputedStyle(element).opacity), '1', 'collapsed layers are the real notification cards');
    assert.equal(await regions.nth(0).locator('.notification-summary').evaluate(element => getComputedStyle(element).opacity), '0', 'collapsed backing cards hide their content');
    if (process.env.SABLE_UPDATE_SCREENSHOTS) await page.screenshot({path: `${process.env.SABLE_UPDATE_SCREENSHOTS}/stack-collapsed-desktop.png`, fullPage: false});

    await stack.hover();
    assert.ok(await stack.evaluate(element => element.getAnimations({subtree: true}).some(animation => animation.playState === 'running')), 'real cards animate out of the collapsed deck');
    await page.waitForFunction(() => {
      const cards = [...document.querySelectorAll('[data-notification-stack] > .toast-region')].map(region => region.getBoundingClientRect());
      return cards.slice(1).every((card, index) => cards[index].bottom <= card.top + 1);
    });
    await stack.evaluate(element => Promise.all(
      element.getAnimations({subtree: true}).map(animation => animation.finished.catch(() => {})),
    ));
    const expandedBounds = await regions.evaluateAll(elements => elements.map(element => element.getBoundingClientRect().toJSON()));
    for (let index = 1; index < expandedBounds.length; index++) {
      assert.ok(expandedBounds[index - 1].y + expandedBounds[index - 1].height <= expandedBounds[index].y + 1, 'expanded notifications do not overlap');
    }
    const expandedGaps = expandedBounds.slice(1).map((card, index) => card.y - (expandedBounds[index].y + expandedBounds[index].height));
    assert.ok(Math.max(...expandedGaps) - Math.min(...expandedGaps) < 1, 'expanded notification gaps are equal');
    assert.ok(expandedBounds[0].height > expandedBounds[1].height, 'the update card grows to its natural action-card height');
    const dismissInsets = await regions.evaluateAll(elements => elements.map(element => {
      const style = getComputedStyle(element.querySelector('[data-toast-close]'));
      return {top: style.top, right: style.right};
    }));
    dismissInsets.forEach(({top, right}) => {
      assert.equal(top, '8px', 'dismiss controls share the update card top inset');
      assert.equal(right, '8px', 'dismiss controls share the update card right inset');
    });
    await assertDismissAlignment(regions, 'desktop');
    if (process.env.SABLE_UPDATE_SCREENSHOTS) await page.screenshot({path: `${process.env.SABLE_UPDATE_SCREENSHOTS}/stack-expanded-desktop.png`, fullPage: false});

    await page.mouse.move(0, 0);
    await regions.nth(0).getByRole('button', {name: 'Dismiss notification'}).focus();
    await page.waitForFunction(() => {
      const cards = [...document.querySelectorAll('[data-notification-stack] > .toast-region')].map(region => region.getBoundingClientRect());
      return cards.slice(1).every((card, index) => cards[index].bottom <= card.top + 1);
    });
    assert.equal(await regions.nth(0).getByRole('button', {name: 'Dismiss notification'}).evaluate(element => element === document.activeElement), true, 'keyboard focus expands the stack');

    await page.setViewportSize({width: 390, height: 844});
    const sidebarScrim = page.locator('.sidebar-scrim');
    if (await sidebarScrim.isVisible()) await sidebarScrim.click();
    await page.locator('#app-sidebar').evaluate(element => Promise.all(
      element.getAnimations({subtree: true}).map(animation => animation.finished.catch(() => {})),
    ));
    const mobileBounds = await regions.evaluateAll(elements => elements.map(element => element.getBoundingClientRect().toJSON()));
    for (let index = 1; index < mobileBounds.length; index++) {
      assert.ok(mobileBounds[index - 1].y + mobileBounds[index - 1].height <= mobileBounds[index].y, 'mobile notifications remain expanded');
    }
    await assertDismissAlignment(regions, 'mobile');
    if (process.env.SABLE_UPDATE_SCREENSHOTS) await page.screenshot({path: `${process.env.SABLE_UPDATE_SCREENSHOTS}/stack-mobile.png`, fullPage: false});
    await page.locator('.toast-success').getByRole('button', {name: 'Dismiss notification'}).click();
    await page.locator('.toast-error').getByRole('button', {name: 'Dismiss notification'}).click();
    await page.waitForFunction(() => document.querySelectorAll('[data-notification-stack] > .toast-region').length === 1);

    await page.setViewportSize({width: 1440, height: 900});
    await page.mouse.move(0, 0);
    await addNotification('/test/notification/transient?label=one');
    await addNotification('/test/notification/transient?label=two');
    await addNotification('/test/notification/transient?label=three');
    const transients = stack.locator('.toast-success').filter({hasText: 'Test transient notification'});
    await page.waitForFunction(() => document.querySelectorAll('[data-notification-stack] .toast-success').length === 3);
    await page.waitForTimeout(4000);
    await stack.hover();
    await page.waitForFunction(() => {
      const cards = [...document.querySelectorAll('[data-notification-stack] > .toast-region')].map(region => region.getBoundingClientRect());
      return cards.slice(1).every((card, index) => cards[index].bottom <= card.top + 1);
    });
    for (let index = 0; index < await transients.count(); index++) {
      const bounds = await transients.nth(index).boundingBox();
      assert.ok(bounds, 'transient notification has rendered bounds');
      await page.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
    }
    await page.waitForTimeout(700);
    assert.equal(await transients.count(), 3, 'moving between cards keeps every transient notification timer paused while the stack remains open');
    while (await transients.count()) {
      await transients.first().getByRole('button', {name: 'Dismiss notification'}).click();
      await page.waitForTimeout(180);
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
    const clusterCard = page.locator('.cluster-aside .cluster-update-card');
    assert.match(await clusterCard.innerText(), /ns3-latham/);
    const clusterBounds = await clusterCard.boundingBox();
    const localNodeBounds = await page.locator('.cluster-details').boundingBox();
    assert.ok(clusterBounds.y + clusterBounds.height <= localNodeBounds.y, 'rolling updates appear above Local Node');
    await clusterCard.getByRole('button', {name: 'Release notes', exact: true}).click();
    const clusterNotes = page.locator('#cluster-release-notes-dialog');
    await clusterNotes.waitFor({state: 'visible'});
    assert.match(await clusterNotes.locator('.release-notes-content').innerText(), /Rolling updates/);
    await page.waitForResponse(response => response.url().endsWith('/ui/cluster/status'));
    assert.equal(await clusterNotes.isVisible(), true, 'live refresh preserves the open release notes dialog');
    await clusterNotes.getByRole('button', {name: 'Done', exact: true}).click();
    await page.waitForResponse(response => response.url().endsWith('/ui/cluster/status'));
    assert.equal(await page.locator('#cluster-updates').count(), 1, 'live refresh replaces the sidebar without duplicating it');
    assert.equal(await clusterCard.isVisible(), true, 'rollout remains visible while a restarting node renegotiates support');
    assert.equal(await clusterCard.locator('.cluster-update-step .icon-loader-circle').count(), 1);
    assert.equal(await clusterCard.locator('.cluster-update-step .icon-check').count(), 1);
    assert.match(await clusterCard.locator('.cluster-update-version').innerText(), /v1\.1\.0/);
    assert.equal(await clusterCard.locator('.cluster-update-status').innerText(), 'Updating cluster');
    assert.equal(await page.locator('[hx-post="/ui/updates/cluster/stop"]').count(), 1);
    if (process.env.SABLE_UPDATE_SCREENSHOTS) await page.screenshot({path: `${process.env.SABLE_UPDATE_SCREENSHOTS}/cluster-desktop.png`, fullPage: true});
    const scopePage = await browser.newPage({viewport: {width: 320, height: 844}});
    scopePage.on('pageerror', error => errors.push(error.message));
    await scopePage.goto(`${process.argv[2]}/about?scope`);
    const scopeTrigger = scopePage.getByRole('button', {name: 'Choose update scope', exact: true});
    await scopeTrigger.waitFor();
    await scopePage.getByRole('button', {name: 'Install update', exact: true}).click();
    const scopeConfirmation = scopePage.locator('dialog.confirmation-dialog[open]');
    await scopeConfirmation.waitFor();
    assert.match(await scopeConfirmation.innerText(), /Install this release/);
    await scopeConfirmation.getByRole('button', {name: 'Cancel', exact: true}).click();
    await scopeTrigger.click();
    await scopeTrigger.click();
    assert.equal(await scopePage.locator('.update-scope-menu:popover-open').count(), 0, 'second click closes the scope menu');
    await scopeTrigger.focus();
    await scopeTrigger.press('ArrowUp');
    const scopeMenu = scopePage.getByRole('menu', {name: 'Update scope', exact: true});
    await scopeMenu.waitFor({state: 'visible'});
    const scopeBounds = await scopeMenu.boundingBox();
    assert.ok(scopeBounds.x >= 0 && scopeBounds.x + scopeBounds.width <= 320, 'scope menu fits narrow screens');
    assert.ok(scopeBounds.y >= 0 && scopeBounds.y + scopeBounds.height <= 844, 'scope menu opens above the notification');
    assert.match(await scopePage.locator(':focus').innerText(), /Entire cluster/);
    await scopePage.keyboard.press('Escape');
    await scopeMenu.waitFor({state: 'hidden'});
    // Popover toggle events update accessibility state asynchronously.
    await scopePage.waitForFunction(() =>
      document.querySelector('[data-update-scope-trigger]')?.getAttribute('aria-expanded') === 'false');
    assert.equal(await scopeTrigger.getAttribute('aria-expanded'), 'false');
    assert.equal(await scopeTrigger.evaluate(element => element === document.activeElement), true);
    await scopeTrigger.click();
    await scopeMenu.getByRole('menuitemradio', {name: /Entire cluster/}).click();
    await scopeConfirmation.waitFor();
    assert.equal(await scopeMenu.isVisible(), false, 'scope menu closes before confirmation');
    assert.match(await scopeConfirmation.innerText(), /Each replica restarts and synchronizes/);
    await scopeConfirmation.getByRole('button', {name: 'Cancel', exact: true}).click();
    assert.equal(await scopeTrigger.evaluate(element => element === document.activeElement), true, 'cancel returns focus to the scope picker');
    assert.equal(await (await page.request.get(`${process.argv[2]}/rollouts`)).json(), 0);
    assert.equal(await scopePage.getByRole('button', {name: 'Update cluster', exact: true}).isVisible(), true, 'selection becomes the primary action immediately');
    // A fresh session creates another notification while preserving browser preferences.
    const reopenNotice = async path => {
      await scopePage.evaluate(() => sessionStorage.clear());
      await scopePage.goto(`${process.argv[2]}${path}`);
      await scopePage.locator('[data-update-version]').waitFor();
    };
    await reopenNotice('/about?scope');
    assert.equal(await scopePage.getByRole('button', {name: 'Update cluster', exact: true}).isVisible(), true, 'cluster choice survives the next session');
    await scopeTrigger.click();
    assert.equal(await scopeMenu.getByRole('menuitemradio', {name: /Entire cluster/}).getAttribute('aria-checked'), 'true');
    await scopePage.keyboard.press('Escape');
    await reopenNotice('/about?standalone');
    assert.equal(await scopeTrigger.count(), 0, 'unsupported clusters have no cluster action');
    assert.equal(await scopePage.getByRole('button', {name: 'Install update', exact: true}).isVisible(), true);
    await reopenNotice('/about?scope&user=other');
    assert.equal(await scopePage.getByRole('button', {name: 'Install update', exact: true}).isVisible(), true, 'another user has an independent default');
    await reopenNotice('/about?scope');
    assert.equal(await scopePage.getByRole('button', {name: 'Update cluster', exact: true}).isVisible(), true, 'temporary fallback preserves the cluster preference');
    await scopeTrigger.click();
    await scopeMenu.getByRole('menuitemradio', {name: /This node/}).click();
    await scopeConfirmation.getByRole('button', {name: 'Cancel', exact: true}).click();
    await reopenNotice('/about?scope');
    assert.equal(await scopePage.getByRole('button', {name: 'Install update', exact: true}).isVisible(), true, 'changing back to this node persists too');
    await scopeTrigger.click();
    await scopeMenu.getByRole('menuitemradio', {name: /Entire cluster/}).click();
    await scopeConfirmation.getByRole('button', {name: 'Cancel', exact: true}).click();
    await scopePage.getByRole('button', {name: 'Update cluster', exact: true}).click();
    assert.match(await scopeConfirmation.innerText(), /Each replica restarts and synchronizes/, 'remembered action uses the cluster confirmation');
    await scopeConfirmation.getByRole('button', {name: 'Start rolling update', exact: true}).click();
    await scopePage.waitForURL('**/cluster');
    assert.equal(await (await page.request.get(`${process.argv[2]}/rollouts`)).json(), 1);
    assert.equal(await (await page.request.get(`${process.argv[2]}/installs`)).json(), 0, 'cluster choice never calls the node installer');
    await scopePage.close();
    const installPage = await browser.newPage();
    installPage.on('pageerror', error => errors.push(error.message));
    await installPage.goto(`${process.argv[2]}/cluster`);
    await installPage.locator('[data-update-version]').getByRole('button', {name: 'Install update', exact: true}).click();
    const confirmation = installPage.locator('dialog.confirmation-dialog[open]');
    await confirmation.waitFor({state: 'visible'});
    assert.equal(await (await page.request.get(`${process.argv[2]}/installs`)).json(), 0, 'install waits for confirmation');
    await confirmation.getByRole('button', {name: 'Download & Install', exact: true}).click();
    const installNotice = installPage.locator('[data-update-version]');
    const installing = installNotice.getByRole('button', {name: 'Installing…', exact: true});
    await installing.waitFor({state: 'visible'});
    assert.equal(await installing.isEnabled(), false, 'download cannot be started twice');
    assert.match(await installNotice.innerText(), /Downloading sable/);
    assert.equal(await installing.locator('.icon-refresh').evaluate(element => getComputedStyle(element).animationName), 'about-update-spin', 'download has a spinner');
    assert.equal(new URL(installPage.url()).pathname, '/cluster', 'install stays on the current page');
    await installNotice.getByRole('button', {name: 'Release notes', exact: true}).click();
    await installPage.locator('#notification-release-notes-dialog').getByRole('button', {name: 'Done', exact: true}).click();
    const restartButton = installNotice.getByRole('button', {name: 'Restart Sable', exact: true});
    await restartButton.waitFor({state: 'visible'});
    assert.match(await installNotice.innerText(), /Sable v1.1.0 is installed/);
    assert.equal(await (await page.request.get(`${process.argv[2]}/installs`)).json(), 1, 'notification installs from a page without an About panel');
    await restartButton.click();
    const restartConfirmation = installPage.locator('dialog.confirmation-dialog[open]');
    await restartConfirmation.waitFor({state: 'visible'});
    assert.equal(await (await page.request.get(`${process.argv[2]}/restarts`)).json(), 0, 'restart waits for confirmation');
    await Promise.all([
      installPage.waitForEvent('load'),
      restartConfirmation.getByRole('button', {name: 'Restart Sable', exact: true}).click(),
    ]);
    assert.equal(new URL(installPage.url()).pathname, '/cluster', 'restart returns to the same page');
    assert.equal(await (await page.request.get(`${process.argv[2]}/restarts`)).json(), 1, 'notification restarts once');
    const completedToast = installPage.locator('.toast-success');
    await completedToast.waitFor({state: 'visible'});
    assert.match(await completedToast.innerText(), /Sable was updated to v1\.1\.0\./);
    assert.equal(await completedToast.getAttribute('data-toast-duration'), '4500', 'completion toast dismisses automatically');
    await installPage.reload();
    assert.equal(await installPage.locator('.toast-success').count(), 0, 'completion toast is shown only once');
    await installPage.close();

    // A rolling update the page watched reloads it once the rollout is over,
    // so the new release's console takes over, and says what it updated to.
    const rolloutPage = await browser.newPage({viewport: {width: 1280, height: 900}});
    rolloutPage.on('pageerror', error => errors.push(error.message));
    await rolloutPage.goto(`${process.argv[2]}/cluster?disabled&finishing`);
    assert.equal(await rolloutPage.locator('#cluster-updates').getAttribute('data-rollout-active'), 'true');
    const rolloutToast = rolloutPage.locator('.toast-success');
    await rolloutToast.waitFor({state: 'visible', timeout: 20000});
    assert.match(await rolloutToast.innerText(), /Sable was updated to v1\.1\.0\./);
    assert.equal(await rolloutPage.evaluate(() => performance.getEntriesByType('navigation')[0].type), 'reload', 'the page reloads itself at the end of the rollout');
    assert.equal(await rolloutPage.locator('#cluster-updates').getAttribute('data-rollout-phase'), 'complete');
    await rolloutPage.waitForResponse(response => response.url().endsWith('/ui/cluster/status'));
    assert.equal(await rolloutPage.evaluate(() => performance.getEntriesByType('navigation')[0].type), 'reload', 'a completed rollout reloads the page only once');
    await rolloutPage.close();

    // An installed update finished by restarting Sable another way, such as
    // with its service manager, reloads the page too.
    const externalPage = await browser.newPage();
    externalPage.on('pageerror', error => errors.push(error.message));
    await Promise.all([
      externalPage.waitForResponse(response => response.url().endsWith('/api/v1/health')),
      externalPage.goto(`${process.argv[2]}/about?disabled&installed`),
    ]);
    await Promise.all([
      externalPage.waitForEvent('load', {timeout: 20000}),
      page.request.post(`${process.argv[2]}/test/restart`),
    ]);
    const externalToast = externalPage.locator('.toast-success');
    await externalToast.waitFor({state: 'visible'});
    assert.match(await externalToast.innerText(), /Sable was updated to v1\.1\.0\./);
    await externalPage.close();

    assert.deepEqual(errors, []);
    console.log('PASS login notice, release notes, escaping, release links, mobile layout, dismissal, opt-out, cluster progress, and reloads after updates');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
