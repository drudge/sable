const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const {chromium} = require('playwright');

// Settings > Alerts against the console with alerts wired: add an ntfy
// destination, preview it, see it listed, send it a test, and save the groups.
(async () => {
  const [base, cookie, ntfy] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900}});
    await context.addCookies([{name: cookie, value: 'everything', url: base}]);
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const focusedID = () => page.evaluate(() => document.activeElement?.id || '');
    // SABLE_ALERTS_SCREENSHOTS names a directory to photograph each step into.
    const shoot = async (name, fullPage = false) => {
      if (!process.env.SABLE_ALERTS_SCREENSHOTS) return;
      await fs.mkdir(process.env.SABLE_ALERTS_SCREENSHOTS, {recursive: true});
      await page.screenshot({path: `${process.env.SABLE_ALERTS_SCREENSHOTS}/${name}.png`, fullPage, animations: 'disabled'});
    };

    await page.goto(`${base}/settings?tab=alerts`);
    const panel = page.locator('#alerts-panel');
    await panel.waitFor();
    assert.equal(await page.getByRole('tab', {name: 'Alerts'}).getAttribute('aria-selected'), 'true');
    assert.match(await panel.innerText(), /No destinations yet/);
    assert.equal(await panel.locator('.alerts-status .status-badge').innerText(), 'Off');
    await shoot('empty', true);

    // Add Destination loads a fresh form, then opens it on its first field.
    await page.getByRole('button', {name: 'Add Destination'}).click();
    const dialog = page.locator('#alert-destination-dialog');
    await dialog.waitFor({state: 'visible'});
    await page.waitForFunction(() => document.activeElement?.getAttribute('name') === 'name');
    await dialog.locator('input[name="name"]').fill('Phone');
    await dialog.locator('label.alert-format', {hasText: 'ntfy'}).click();
    assert.equal(await dialog.getByText('Topic URL', {exact: true}).isVisible(), true, 'ntfy asks for a topic URL');
    assert.equal(await dialog.locator('input[name="pushover_token"]').isVisible(), false, 'ntfy asks for no Pushover keys');
    await dialog.locator('input[name="url"]').fill(`${ntfy}/sable-alerts`);
    await dialog.locator('summary', {hasText: 'Advanced'}).click();
    await dialog.getByRole('switch', {name: /ntfy Receipt/}).check();
    await shoot('dialog-ntfy');

    // Picking only some groups shows them; Everything hides them again.
    const groups = dialog.locator('.alert-sends-groups');
    assert.equal(await groups.isVisible(), false, 'Everything lists no groups');
    await dialog.getByText('Only These Groups', {exact: true}).click();
    assert.equal(await groups.isVisible(), true, 'picking groups lists them');
    await shoot('dialog-groups');
    await dialog.getByText('Everything', {exact: true}).click();
    assert.equal(await groups.isVisible(), false, 'Everything hides the groups again');

    // The preview drops from its button with the topic cut short.
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    const preview = page.locator('#alert-destination-preview');
    await preview.waitFor({state: 'visible'});
    const request = await preview.locator('code').innerText();
    assert.match(request, /^POST http:\/\/127\.0\.0\.1:\d+\/••••erts\n/);
    assert.match(request, /Title: Test alert: Sable/);
    assert.ok(!request.includes('sable-alerts'), 'the preview cuts the topic short');
    await shoot('dialog-preview');
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    await preview.waitFor({state: 'hidden'});

    await dialog.getByRole('button', {name: 'Save', exact: true}).click();
    await dialog.waitFor({state: 'hidden'});
    const row = panel.locator('.alert-destination-row');
    await row.waitFor();
    const listed = await row.innerText();
    assert.match(listed, /Phone/);
    assert.match(listed, /ntfy/);
    assert.match(listed, /••••erts/);
    assert.match(listed, /Everything/);
    assert.ok(!listed.includes('sable-alerts'), 'the list cuts the topic short');
    assert.equal(await panel.locator('.alerts-status .status-badge').innerText(), 'On');
    await page.getByText('Added Phone. Send a test to make sure it arrives.').waitFor();
    assert.equal(await focusedID(), 'alert-destination-add', 'focus returns to Add Destination');

    // A test says what ntfy answered, and focus stays on the button.
    await row.getByRole('button', {name: 'Send Test to Phone'}).click();
    await page.getByText('Test sent. ntfy published it as message browserTest01.').waitFor();
    assert.match(await panel.locator('.alert-destination-row').innerText(), /Last sent .*: Test alert: Sable/);
    assert.match(await focusedID(), /^alert-destination-test-[0-9a-f]{16}$/, 'focus stays on Send Test');
    await shoot('tested', true);

    // Editing shows the saved topic cut short and never the topic itself.
    await panel.getByRole('button', {name: 'Edit Phone'}).click();
    await dialog.waitFor({state: 'visible'});
    const address = dialog.locator('input[name="url"]');
    await page.waitForFunction(() => document.querySelector('#alert-destination-dialog input[name="id"]'));
    assert.equal(await address.inputValue(), '');
    assert.match(await address.getAttribute('placeholder'), /^Saved: http:\/\/127\.0\.0\.1:\d+\/••••erts$/);
    assert.equal(await dialog.locator('input[name="name"]').inputValue(), 'Phone');
    await dialog.getByRole('button', {name: 'Cancel'}).click();
    await dialog.waitFor({state: 'hidden'});
    assert.match(await focusedID(), /^alert-destination-edit-[0-9a-f]{16}$/, 'closing the dialog returns focus to Edit');

    // With Insights Findings off, its kinds fold away, and they come back with it.
    const insights = panel.getByRole('switch', {name: /Insights Findings/});
    const kinds = panel.locator('.alert-insight-kinds');
    assert.equal(await kinds.isVisible(), true, 'Insights Findings lists its kinds');
    await insights.uncheck();
    assert.equal(await kinds.isVisible(), false, 'turning Insights Findings off folds its kinds away');
    await shoot('insights-off');
    await insights.check();
    assert.equal(await kinds.isVisible(), true, 'turning Insights Findings back on shows its kinds');

    // The groups save on their own.
    await panel.getByRole('switch', {name: /Failed Sign-Ins/}).check();
    await panel.getByRole('spinbutton', {name: 'Failed sign-ins before an alert'}).fill('3');
    await panel.getByRole('spinbutton', {name: 'Minutes to count failed sign-ins in'}).fill('15');
    await panel.getByRole('button', {name: 'Save Groups'}).click();
    await page.getByText('Saved which alerts Sable sends.').waitFor();
    assert.equal(await panel.getByRole('switch', {name: /Failed Sign-Ins/}).isChecked(), true);
    assert.equal(await focusedID(), 'alerts-groups-save', 'focus stays on Save Groups');

    // A problem shows in the open dialog and leaves what was typed alone.
    await panel.getByRole('button', {name: 'Add Destination'}).click();
    await dialog.waitFor({state: 'visible'});
    await page.waitForFunction(() => document.activeElement?.getAttribute('name') === 'name');
    await dialog.locator('input[name="name"]').fill('Team');
    await dialog.locator('label.alert-format', {hasText: 'Slack'}).click();
    await dialog.getByRole('button', {name: 'Save', exact: true}).click();
    await dialog.getByText('Team needs a URL.').waitFor();
    assert.equal(await dialog.isVisible(), true, 'a problem keeps the dialog open');
    assert.equal(await dialog.locator('input[name="name"]').inputValue(), 'Team', 'a problem keeps what was typed');
    await shoot('dialog-problem');
    await dialog.locator('input[name="url"]').fill(`${ntfy}/services/T0/B0/token`);
    await dialog.getByRole('button', {name: 'Save', exact: true}).click();
    await dialog.waitFor({state: 'hidden'});
    assert.equal(await panel.locator('.alert-destination-row').count(), 2);

    // Removing asks first, then focus moves to Add Destination.
    await panel.getByRole('button', {name: 'Remove Team'}).click();
    const confirmation = page.locator('dialog.confirmation-dialog[open]');
    await confirmation.waitFor();
    assert.match(await confirmation.innerText(), /Remove Team\? Sable stops sending it alerts/);
    await confirmation.getByRole('button', {name: 'Remove', exact: true}).click();
    await page.getByText('Removed Team.').waitFor();
    assert.equal(await panel.locator('.alert-destination-row').count(), 1);
    assert.equal(await focusedID(), 'alert-destination-add', 'focus moves to Add Destination after a removal');

    // The tab fits a phone.
    await page.setViewportSize({width: 390, height: 844});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'the Alerts tab does not overflow a phone');
    await shoot('phone', true);
    await page.emulateMedia({colorScheme: 'dark'});
    await page.setViewportSize({width: 1280, height: 900});
    await page.reload();
    await panel.waitFor();
    await shoot('dark', true);

    // The Insights bell says alerts are on and leads back to the tab.
    await page.emulateMedia({colorScheme: 'light'});
    await page.goto(`${base}/insights?range=day`);
    const bell = page.getByRole('link', {name: 'Insights alerts on'});
    await bell.waitFor();
    await shoot('insights-bell');
    await bell.click();
    await page.waitForURL(/\/settings\?tab=alerts$/);
    assert.equal(await page.getByRole('tab', {name: 'Alerts'}).getAttribute('aria-selected'), 'true');

    assert.deepEqual(errors, [], 'the page threw no errors');
    console.log('PASS Settings > Alerts adds, previews, lists, and tests an ntfy destination');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
