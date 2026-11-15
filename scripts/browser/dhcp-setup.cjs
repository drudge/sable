const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// DHCP setup: the empty page lists the host's networks; Set Up opens Add
// Scope filled in from one; Turn On probes first and, when another server
// answers, says which and offers Turn On Anyway behind a confirmation.
(async () => {
  const [baseURL] = process.argv.slice(2);
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900}});
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });

    await page.goto(`${baseURL}/dhcp`);
    const networks = page.getByRole('region', {name: 'Networks this server is on'});
    assert.match(await networks.textContent(), /eth0 · this server is 192\.0\.2\.10 · router 192\.0\.2\.1/);
    await networks.getByRole('button', {name: 'Set up 192.0.2.0/24'}).click();

    const dialog = page.getByRole('dialog', {name: 'Add Scope'}).filter({visible: true});
    await dialog.waitFor();
    assert.equal(await dialog.getByLabel('ID').inputValue(), 'lan');
    assert.equal(await dialog.getByLabel('Subnet').inputValue(), '192.0.2.0/24');
    assert.equal(await dialog.getByLabel('Range Start').inputValue(), '192.0.2.100');
    assert.equal(await dialog.getByLabel('Range End').inputValue(), '192.0.2.199');
    assert.equal(await dialog.getByLabel('Router').inputValue(), '192.0.2.1');
    const id = dialog.getByLabel('ID');
    await id.fill('Bad ID');
    assert.equal(await id.evaluate(input => input.validity.patternMismatch), true, 'the ID pattern refuses capitals and spaces');
    await id.fill('lan');
    await dialog.getByRole('button', {name: 'Add Scope'}).click();
    await page.getByText('Saved scope LAN').first().waitFor();
    console.log('PASS Set Up adds the scope suggested for the network');

    // The probe listens for seconds: Turn On says so and takes no second
    // click meanwhile.
    const turnOn = await page.getByRole('button', {name: 'Turn On', exact: true}).elementHandle();
    await turnOn.click();
    await page.waitForFunction(button => button.disabled && /Checking Network/.test(button.innerText), turnOn);
    const box = await turnOn.boundingBox();
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    console.log('PASS Turn On is busy and disabled while the probe listens');
    await page.getByText(/Another DHCP server answers: 192\.0\.2\.1 on eth0 \(offered 192\.0\.2\.57\)/).waitFor();
    const anyway = page.getByRole('button', {name: 'Turn On Anyway'});
    await anyway.click();
    const confirmation = page.getByRole('dialog', {name: 'Turn DHCP on anyway?'});
    await confirmation.waitFor();
    await confirmation.getByRole('button', {name: 'Turn On Anyway'}).click();
    await page.getByText('Turned DHCP on').first().waitFor();
    await page.getByRole('button', {name: 'Turn Off'}).waitFor();
    console.log('PASS Turn On names the other server and Turn On Anyway turns it on');
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
