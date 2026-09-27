const {execFileSync, spawn} = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const {parseArgs} = require('node:util');
const {chromium} = require('playwright');

// Photographs console pages at Nick's laptop size and a phone, in dark and
// light, and reports sideways scrolling, script errors, and failed requests.
// With --demo it builds the checked-out code, starts the Vandelay demo, and
// always stops it again; without it, --base points at a console that is
// already running. The build doesn't regenerate templ files, so it can run
// beside `mage verify`; run `go tool mage generate` first after editing them.
//
//   node scripts/browser/pages.cjs --demo --pages '/insights?tab=devices,/settings?tab=alerts' --out _work/look
//   node scripts/browser/pages.cjs --base http://127.0.0.1:5391 --pages / --out _work/look
const root = path.resolve(__dirname, '../..');
const {values} = parseArgs({options: {demo: {type: 'boolean'}, base: {type: 'string'}, pages: {type: 'string'}, out: {type: 'string'}}});
const pages = (values.pages || '').split(',').map(page => page.trim()).filter(Boolean);
if (!pages.length || !values.out || (!values.demo && !values.base)) {
  console.error('Usage: node scripts/browser/pages.cjs (--demo | --base <url>) --pages /a,/b --out <dir>');
  process.exit(2);
}
const out = path.resolve(values.out);
const base = values.base || 'http://127.0.0.1:5391';
const viewports = [
  {name: 'desktop', width: 1218, height: 787},
  {name: 'phone', width: 390, height: 844, isMobile: true, hasTouch: true},
];
// Console, HTTPS, and DNS ports of the demo's three nodes. The DNS ports are
// fixed, so a second demo can never run beside one that is already up.
const demoPorts = [5391, 5392, 5393, 5491, 5492, 5493, 8555, 8556, 8557];

const listening = port => new Promise(resolve => {
  const socket = net.connect({host: '127.0.0.1', port});
  socket.once('connect', () => { socket.destroy(); resolve(true); });
  socket.once('error', () => resolve(false));
});

async function startDemo() {
  const busy = [];
  for (const port of demoPorts) if (await listening(port)) busy.push(port);
  if (busy.length) throw new Error(`Something is already listening on ${busy.join(', ')}. Stop the running Vandelay demo first; this script never stops one it didn't start.`);
  const build = {cwd: root, stdio: ['ignore', process.stderr, process.stderr], env: {...process.env, GOEXPERIMENT: 'jsonv2', CGO_ENABLED: '0'}};
  execFileSync('go', ['build', '-trimpath', '-o', 'bin/sable', './cmd/sable'], build);
  execFileSync('go', ['build', '-o', 'bin/sable-demo', './scripts/demo'], build);
  fs.mkdirSync(out, {recursive: true});
  const logFile = path.join(out, 'demo.log');
  const log = fs.openSync(logFile, 'w');
  const demo = spawn(path.join(root, 'bin/sable-demo'), ['-binary', 'bin/sable', '-keep'], {cwd: root, detached: true, stdio: ['ignore', log, log], env: {...process.env, GOEXPERIMENT: 'jsonv2'}});
  let exited = null;
  demo.once('exit', code => { exited = code ?? 'a signal'; });
  // Interrupting the demo's process group stops the demo and its three nodes.
  const stop = async () => {
    if (exited !== null) return;
    try { process.kill(-demo.pid, 'SIGINT'); } catch { return; }
    for (let waited = 0; exited === null && waited < 30000; waited += 500) await new Promise(resolve => setTimeout(resolve, 500));
    if (exited === null) try { process.kill(-demo.pid, 'SIGKILL'); } catch {}
  };
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => stop().finally(() => process.exit(130)));
  for (const deadline = Date.now() + 8 * 60000; Date.now() < deadline;) {
    if (fs.readFileSync(logFile, 'utf8').includes('Vandelay Industries is up.')) return stop;
    if (exited !== null) throw new Error(`The demo exited with ${exited}; see ${logFile}`);
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  await stop();
  throw new Error(`The demo did not come up within 8 minutes; see ${logFile}`);
}

async function settle(page) {
  await page.waitForLoadState('networkidle', {timeout: 8000}).catch(() => {});
  await page.evaluate(() => document.fonts.ready);
  await page.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))));
  await page.waitForTimeout(800);
}

// Elements that stick out past the viewport while their parent fits are the
// ones pushing the page sideways; anything inside a clipped box can't.
function sideways() {
  const width = document.documentElement.clientWidth;
  if (document.documentElement.scrollWidth <= width + 1) return null;
  const clipped = element => {
    for (let node = element.parentElement; node && node !== document.body; node = node.parentElement) {
      if (!/visible/.test(getComputedStyle(node).overflowX)) return true;
    }
    return false;
  };
  const describe = element => element.tagName.toLowerCase() + (element.id ? '#' + element.id : '') + [...element.classList].slice(0, 3).map(name => '.' + name).join('');
  const culprits = [...document.body.querySelectorAll('*')].filter(element => {
    const box = element.getBoundingClientRect();
    return box.width > 0 && box.right > width + 1 && element.parentElement.getBoundingClientRect().right <= width + 1 && !clipped(element);
  });
  return {scrollWidth: document.documentElement.scrollWidth, width, culprits: culprits.slice(0, 3).map(describe)};
}

async function photograph() {
  const fixture = fs.readFileSync(path.join(root, 'scripts/demo/fixture.go'), 'utf8');
  const constant = name => fixture.match(new RegExp(`${name}\\s*=\\s*"([^"]+)"`))[1];
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  const shots = [];
  try {
    const session = await browser.newContext({viewport: {width: 1218, height: 787}});
    const signIn = await session.newPage();
    await signIn.goto(base + '/');
    if (signIn.url().includes('/login')) {
      await signIn.locator('input[name="username"]').fill(constant('operatorUsername'));
      await signIn.locator('input[type="password"]').first().fill(constant('operatorPassword'));
      await Promise.all([signIn.waitForURL(url => !url.pathname.startsWith('/login')), signIn.locator('form button[type="submit"]').first().click()]);
    }
    const storageState = await session.storageState();
    fs.mkdirSync(out, {recursive: true});
    for (const address of pages) {
      const slug = address.replace(/^\//, '').replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') || 'dashboard';
      for (const {name, ...viewport} of viewports) {
        for (const theme of ['dark', 'light']) {
          const context = await browser.newContext({storageState, colorScheme: theme, reducedMotion: 'reduce', deviceScaleFactor: 2, viewport: {width: viewport.width, height: viewport.height}, isMobile: Boolean(viewport.isMobile), hasTouch: Boolean(viewport.hasTouch)});
          const page = await context.newPage();
          const shot = {page: address, viewport: `${name} ${viewport.width}x${viewport.height}`, theme, file: path.join(out, `${slug}-${name}-${theme}.png`), sideways: null, errors: [], failedRequests: []};
          page.on('pageerror', error => shot.errors.push(error.message));
          page.on('console', message => { if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) shot.errors.push(message.text()); });
          page.on('response', response => { if (response.url().startsWith(base) && response.status() >= 400) shot.failedRequests.push(`${response.status()} ${response.url().slice(base.length)}`); });
          await page.goto(base + address);
          await settle(page);
          if (new URL(page.url()).pathname.startsWith('/login')) shot.errors.push('Landed on the sign-in page instead');
          shot.sideways = await page.evaluate(sideways);
          await page.screenshot({path: shot.file, fullPage: true});
          shots.push(shot);
          await context.close();
        }
      }
    }
  } finally {
    await browser.close();
  }
  return shots;
}

(async () => {
  const stop = values.demo ? await startDemo() : null;
  try {
    const shots = await photograph();
    const problems = shots.filter(shot => shot.sideways || shot.errors.length || shot.failedRequests.length).length;
    console.log(JSON.stringify({ok: problems === 0, problems, shots}, null, 2));
    if (problems) process.exitCode = 1;
  } finally {
    if (stop) await stop();
  }
})().catch(error => {
  console.error(error.message);
  process.exit(1);
});
