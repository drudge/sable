const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Settings > General > Software Updates: the schedule asks for a day only for
// weekly checks and a time only for daily and weekly ones, folds away while
// checks are off, and saves with Save Settings.
(async () => {
  const [base, cookie] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900}});
    await context.addCookies([{name: cookie, value: 'everything', url: base}]);
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));

    await page.goto(`${base}/settings?tab=general`);
    const schedule = page.getByRole('group', {name: 'When to check for updates'});
    await schedule.waitFor();
    const often = schedule.getByRole('combobox', {name: 'How often to check for updates'});
    const day = schedule.locator('span.update-check-day');
    const time = schedule.locator('span.update-check-at');
    const choose = async (combobox, option) => {
      await combobox.click();
      await page.getByRole('option', {name: option, exact: true}).click();
    };

    // Checks start hourly, which needs no day or time. A daily check has a
    // time and no day.
    assert.match(await often.innerText(), /Hourly/);
    assert.equal(await time.isVisible(), false, 'an hourly check has no time');
    assert.equal(await day.isVisible(), false, 'an hourly check has no day');
    await choose(often, 'Daily');
    assert.equal(await time.isVisible(), true, 'a daily check has a time');
    assert.equal(await day.isVisible(), false, 'a daily check has no day');

    await choose(often, 'Weekly');
    assert.equal(await day.isVisible(), true, 'a weekly check has a day');
    assert.equal(await time.isVisible(), true, 'a weekly check has a time');
    await choose(schedule.getByRole('combobox', {name: 'Day to check for updates'}), 'Friday');
    await schedule.getByRole('button', {name: 'Open time to check for updates picker'}).click();
    const picker = page.getByRole('dialog', {name: 'Choose time to check for updates'});
    await picker.getByRole('listbox', {name: 'Hour'}).getByRole('option', {name: '06', exact: true}).click();
    await picker.getByRole('listbox', {name: 'Minute'}).getByRole('option', {name: '30', exact: true}).click();
    await picker.getByRole('listbox', {name: 'Period'}).getByRole('option', {name: 'PM', exact: true}).click();
    await picker.getByRole('button', {name: 'Done', exact: true}).click();
    assert.equal(await page.locator('input[name="check_at"]').inputValue(), '18:30');

    await choose(often, 'Hourly');
    assert.equal(await time.isVisible(), false, 'an hourly check has no time');
    assert.equal(await day.isVisible(), false, 'an hourly check has no day');
    await choose(often, 'Weekly');

    // Turning checks off folds the schedule away, and it comes back as it was.
    const checks = page.getByRole('switch', {name: /Check for updates/});
    await checks.uncheck();
    assert.equal(await schedule.isVisible(), false, 'turning checks off folds the schedule away');
    await checks.check();
    assert.equal(await day.isVisible(), true, 'turning checks back on shows the schedule as it was');

    await page.getByRole('button', {name: 'Save Settings'}).click();
    await page.getByText('Settings saved and applied').waitFor();
    await page.reload();
    await schedule.waitFor();
    assert.match(await often.innerText(), /Weekly/);
    assert.match(await schedule.getByRole('combobox', {name: 'Day to check for updates'}).innerText(), /Friday/);
    assert.equal(await schedule.getByRole('textbox', {name: 'Time to check for updates'}).inputValue(), '06:30 PM');

    // The schedule fits a phone.
    await page.setViewportSize({width: 390, height: 844});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'the schedule does not overflow a phone');

    assert.deepEqual(errors, [], 'the page threw no errors');
    console.log('PASS Settings > General schedules update checks hourly, daily, or weekly');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
