const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// The MCP setup wizard warns before Connect when its group lacks a checked
// tool's grant: Go Back stays on Access, Continue Anyway goes on, and a tool
// list the group covers goes straight through.
(async () => {
  const [baseURL] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const page = await browser.newPage({viewport: {width: 1218, height: 787}});
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const wizard = page.locator('#mcp-setup-dialog');
    const panel = name => wizard.locator(`[data-dialog-panel="${name}"]`);
    const next = () => wizard.locator('.wizard-footer-advance button:visible', {hasText: 'Next'}).click();
    const warning = page.getByRole('dialog', {name: /won't work/});

    await page.goto(baseURL + '/');
    await panel('tools').waitFor();
    await next();
    await panel('access').waitFor();

    // Next warns, naming the tool and the grant, and Go Back stays on Access.
    await next();
    await warning.waitFor();
    assert.equal(await warning.getByRole('heading').textContent(), "A tool won't work");
    assert.equal(await warning.locator('.confirmation-icon.warning svg').count(), 1, 'the warning leads with a warning icon');
    const text = await warning.textContent();
    for (const expected of ['MCP Server lacks metrics.read, so an assistant that calls get_stats gets a permission error.', 'Use Update Group on this step to add it, or fix it later in Edit Setup.']) {
      assert.ok(text.includes(expected), `the warning says ${expected}: ${text}`);
    }
    await warning.getByRole('button', {name: 'Go Back'}).click();
    await warning.waitFor({state: 'hidden'});
    assert.equal(await panel('access').isVisible(), true, 'Go Back stays on Access');
    assert.equal(await panel('connect').isVisible(), false);

    // The step tab warns too, and Continue Anyway goes on.
    await wizard.locator('[data-dialog-tab="connect"]').first().click();
    await warning.getByRole('button', {name: 'Continue Anyway'}).click();
    await panel('connect').waitFor();

    // Without the tool that lacks its grant, Connect needs no warning.
    await wizard.locator('[data-dialog-tab="tools"]').first().click();
    await wizard.locator('input[value="get_stats"]').uncheck();
    await wizard.locator('[data-dialog-tab="connect"]').first().click();
    await panel('connect').waitFor();
    assert.equal(await warning.count(), 0, 'no warning when the group covers the tools');

    // Two tools, and someone who can't update the group, are told to ask.
    await page.goto(baseURL + '/?two&reader');
    await panel('tools').waitFor();
    await wizard.locator('[data-dialog-tab="connect"]').first().click();
    await warning.waitFor();
    const two = await warning.textContent();
    assert.equal(await warning.getByRole('heading').textContent(), "Some tools won't work");
    for (const expected of ['MCP Server lacks metrics.read and cluster.read, so an assistant that calls get_stats or get_cluster_status gets a permission error.', 'Ask an administrator to add them to MCP Server.']) {
      assert.ok(two.includes(expected), `the warning says ${expected}: ${two}`);
    }
    await page.keyboard.press('Escape');
    await warning.waitFor({state: 'hidden'});
    assert.equal(await panel('connect').isVisible(), false, 'Escape stays put');

    assert.deepEqual(errors, []);
    console.log('PASS the MCP wizard warns before Connect when its group lacks a tool\'s grant');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
