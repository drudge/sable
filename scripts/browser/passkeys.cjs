const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Run against a fresh, isolated Sable instance; this creates its administrator.
(async () => {
  const base = process.argv[2];
  assert.ok(base, 'usage: node passkeys.cjs http://localhost:PORT');
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('dialog', dialog => dialog.accept());
    await page.goto(base);
    assert.equal(new URL(page.url()).pathname, '/setup', 'requires a fresh instance with no administrator');
    await page.locator('[name=username]').fill('passkey-admin');
    await page.locator('[name=password]').fill('test-passkey-bootstrap-12345');
    await page.locator('[name=confirm_password]').fill('test-passkey-bootstrap-12345');
    await page.getByRole('button', {name: 'Create administrator', exact: true}).click();
    await page.waitForURL(`${base}/`);
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    }});
    await page.goto(`${base}/profile`);
    assert.deepEqual(await page.locator('.profile-account-stack > section h2').allTextContents(), ['Account details', 'Passkeys', 'Password']);
    await page.locator('[data-passkey-name]').fill('Browser test passkey');
    const registered = page.waitForResponse(response => response.url().endsWith('/ui/profile/passkeys/finish'));
    await page.getByRole('button', {name: 'Add passkey', exact: true}).click();
    assert.equal((await registered).status(), 200);
    await page.getByText('Browser test passkey', {exact: true}).waitFor();
    console.log('PASS enroll a resident passkey through the browser');
    await page.getByRole('button', {name: 'Disable password sign-in', exact: true}).click();
    await page.locator('dialog.confirmation-dialog [data-confirm-accept]').click();
    await page.getByText('Password sign-in is disabled. Your existing password is saved.', {exact: true}).waitFor();
    await page.screenshot({path: '/tmp/sable-passkey-profile.png', fullPage: true});
    await context.clearCookies();
    await page.goto(`${base}/login?return_to=/profile`);
    await page.getByRole('button', {name: 'Sign in with a passkey', exact: true}).click();
    await page.waitForURL(`${base}/profile`);
    console.log('PASS sign in without a username or password and preserve the return URL');
    await page.locator('[data-passkey-action=remove]').click();
    await page.locator('dialog.confirmation-dialog [data-confirm-accept]').click();
    await page.getByText('keep at least one passkey while password sign-in is disabled', {exact: true}).waitFor();
    console.log('PASS prevent removal of the last passwordless passkey');
    await page.locator('[name=new_password]').fill('test-restored-password-12345');
    await page.locator('[name=confirm_password]').fill('test-restored-password-12345');
    await page.getByRole('button', {name: 'Set new password and enable sign-in', exact: true}).click();
    await page.waitForURL(`${base}/login`);
    await page.locator('[name=username]').fill('passkey-admin');
    await page.locator('[name=password]').fill('test-restored-password-12345');
    await page.getByRole('button', {name: 'Sign in', exact: true}).click();
    await page.waitForURL(`${base}/`);
    console.log('PASS restore password sign-in and revoke the previous session');
    assert.deepEqual(errors, [], 'browser runtime errors');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
