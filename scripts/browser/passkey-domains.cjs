const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// All page requests are fulfilled locally: this never contacts these hosts.
(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext();
    await context.route('**/*', route => route.fulfill({contentType: 'text/html', body: '<!doctype html><title>Passkey domain test</title>'}));
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    }});
    await page.goto('https://ns1.penree.net');
    const createdID = await page.evaluate(async () => {
      const credential = await navigator.credentials.create({publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: {id: 'penree.net', name: 'Sable'},
        user: {id: crypto.getRandomValues(new Uint8Array(32)), name: 'admin', displayName: 'Administrator'},
        pubKeyCredParams: [{type: 'public-key', alg: -7}],
        authenticatorSelection: {residentKey: 'required', userVerification: 'required'},
      }});
      return credential.id;
    });
    await page.goto('https://ns2.penree.net');
    const login = await page.evaluate(async () => {
      const credential = await navigator.credentials.get({publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: 'penree.net', userVerification: 'required',
      }});
      return {id: credential.id, origin: JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON)).origin};
    });
    assert.equal(login.id, createdID);
    assert.equal(login.origin, 'https://ns2.penree.net');
    console.log('PASS browser uses one passkey across ns1.penree.net and ns2.penree.net');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
