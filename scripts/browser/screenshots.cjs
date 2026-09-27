const {execFileSync, spawn} = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const {parseArgs} = require('node:util');

// The console's one screenshot engine. It builds Sable, runs the Vandelay
// demo, photographs pages in dark and light, and reports sideways scrolling,
// script errors, and failed requests. The feature-build workflow uses the
// command line below; sabledns.io's release screenshots load it as a module
// with their own list of shots.
//
//   node scripts/browser/screenshots.cjs --demo --pages '/insights?tab=devices,/settings?tab=alerts' --out _work/look
//   node scripts/browser/screenshots.cjs --base http://127.0.0.1:5391 --pages / --out _work/look
//
// Builds skip templ generation so they can run beside `mage verify`; run
// `go tool mage generate` first after editing .templ files.
const repository = path.resolve(__dirname, '../..');
const versionPackage = 'github.com/drudge/sable/internal/version';
const demoBase = 'http://127.0.0.1:5391';
// Console, HTTPS, and DNS ports of the demo's three nodes. The DNS ports are
// fixed, so a second demo can never run beside one that is already up.
const demoPorts = [5391, 5392, 5393, 5491, 5492, 5493, 8555, 8556, 8557];
// Nick's laptop window and a phone, for looking at the pages a change touches.
const viewports = [
  {name: 'desktop', width: 1218, height: 787},
  {name: 'phone', width: 390, height: 844, isMobile: true},
];

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const listening = port => new Promise(resolve => {
  const socket = net.connect({host: '127.0.0.1', port});
  socket.once('connect', () => { socket.destroy(); resolve(true); });
  socket.once('error', () => resolve(false));
});

// buildDemo builds bin/sable, stamped with version when one is given so the
// console shows it, and bin/sable-demo.
function buildDemo({root = repository, version} = {}) {
  const options = {cwd: root, stdio: ['ignore', process.stderr, process.stderr], env: {...process.env, GOEXPERIMENT: 'jsonv2', CGO_ENABLED: '0'}};
  const flags = ['-s', '-w', ...(version ? ['-X', `${versionPackage}.Release=${version}`] : [])].join(' ');
  execFileSync('go', ['build', '-trimpath', '-ldflags', flags, '-o', 'bin/sable', './cmd/sable'], options);
  execFileSync('go', ['build', '-o', 'bin/sable-demo', './scripts/demo'], options);
  if (!version) return;
  const reported = execFileSync(path.join(root, 'bin/sable'), ['version'], {encoding: 'utf8'});
  if (!reported.includes(version)) throw new Error(`bin/sable reports "${reported.trim()}", not ${version}`);
}

// startDemo starts the demo in the background and returns once it is up. Its
// log and process ID go in dir, so another process can stop it later. With
// docsOut, the demo also photographs Sable's own docs screenshots on the way up.
async function startDemo({root = repository, dir, docsOut} = {}) {
  const busy = [];
  for (const port of demoPorts) if (await listening(port)) busy.push(port);
  if (busy.length) throw new Error(`Something is already listening on ${busy.join(', ')}. Stop the running Vandelay demo first; this never stops one it didn't start.`);
  if (!fs.existsSync(path.join(root, 'bin/sable-demo'))) throw new Error('bin/sable-demo is missing; build it first.');
  fs.mkdirSync(dir, {recursive: true});
  const logFile = path.join(dir, 'demo.log');
  const log = fs.openSync(logFile, 'w');
  const demo = spawn(path.join(root, 'bin/sable-demo'), ['-binary', 'bin/sable', '-keep', ...(docsOut ? ['-out', docsOut] : [])], {cwd: root, detached: true, stdio: ['ignore', log, log], env: {...process.env, GOEXPERIMENT: 'jsonv2'}});
  let exited = null;
  demo.once('exit', code => { exited = code ?? 'a signal'; });
  demo.unref();
  fs.writeFileSync(path.join(dir, 'demo.pid'), String(demo.pid));
  for (const deadline = Date.now() + 8 * 60000; Date.now() < deadline; await sleep(2000)) {
    if (fs.readFileSync(logFile, 'utf8').includes('Vandelay Industries is up.')) return;
    if (exited !== null) throw new Error(`The demo exited with ${exited}; see ${logFile}`);
  }
  await stopDemo({dir});
  throw new Error(`The demo did not come up within 8 minutes; see ${logFile}`);
}

// stopDemo interrupts the demo's process group, which stops the demo and its
// three nodes. It only signals a process that is still the demo.
async function stopDemo({dir} = {}) {
  const pidFile = path.join(dir, 'demo.pid');
  if (!fs.existsSync(pidFile)) return;
  const pid = Number(fs.readFileSync(pidFile, 'utf8'));
  const alive = () => {
    try {
      return execFileSync('ps', ['-o', 'command=', '-p', String(pid)], {encoding: 'utf8'}).includes('sable-demo');
    } catch {
      return false;
    }
  };
  if (alive()) {
    try { process.kill(-pid, 'SIGINT'); } catch {}
    for (let waited = 0; alive() && waited < 30000; waited += 500) await sleep(500);
    if (alive()) try { process.kill(-pid, 'SIGKILL'); } catch {}
  }
  fs.rmSync(pidFile, {force: true});
}

async function settle(page) {
  await page.waitForLoadState('networkidle', {timeout: 8000}).catch(() => {});
  await page.waitForFunction(() => !document.querySelector('.htmx-request, [class*="skeleton"]'), null, {timeout: 10000}).catch(() => {});
  await page.evaluate(() => document.fonts.ready);
  await page.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))));
  await page.waitForTimeout(1200);
}

// post sends a console form the way htmx does, with the CSRF headers <body> carries.
async function post(page, url, fields) {
  return page.evaluate(async ([url, fields]) => {
    const headers = JSON.parse(document.body.getAttribute('hx-headers:inherited') || document.body.getAttribute('hx-headers') || '{}');
    const response = await fetch(url, {method: 'POST', headers: {...headers, 'HX-Request': 'true', 'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams(fields)});
    return {status: response.status, text: (await response.text()).slice(0, 300)};
  }, [url, fields]);
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

// capture photographs each shot in each of its themes into dir/<theme>/<name>.png
// and measures it. A shot is {name, path, width, height}, optionally with
// isMobile, themes (dark and light unless given), fullPage, prepare(page, base,
// helpers) run once on the signed-in page, and open(page, helpers) run before
// each photograph. Pass playwright when this checkout has no node_modules.
async function capture({root = repository, base = demoBase, shots, dir, playwright}) {
  const {chromium} = playwright || require('playwright');
  const fixture = fs.readFileSync(path.join(root, 'scripts/demo/fixture.go'), 'utf8');
  const constant = name => fixture.match(new RegExp(`${name}\\s*=\\s*"([^"]+)"`))[1];
  const browser = await chromium.launch({headless: true, args: ['--hide-scrollbars'], ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  const helpers = {settle, post};
  const results = [];
  try {
    const session = await browser.newContext({viewport: {width: 1600, height: 1000}});
    const page = await session.newPage();
    await page.goto(base + '/');
    if (page.url().includes('/login')) {
      await page.locator('input[name="username"]').fill(constant('operatorUsername'));
      await page.locator('input[type="password"]').first().fill(constant('operatorPassword'));
      await Promise.all([page.waitForURL(url => !url.pathname.startsWith('/login')), page.locator('form button[type="submit"]').first().click()]);
    }
    if (page.url().includes('/login')) throw new Error('Could not sign in to the console');
    const storageState = await session.storageState();
    for (const shot of shots) {
      if (shot.prepare) await shot.prepare(page, base, helpers);
      for (const theme of shot.themes || ['dark', 'light']) {
        const context = await browser.newContext({storageState, colorScheme: theme, reducedMotion: 'reduce', locale: 'en-US', deviceScaleFactor: 2, viewport: {width: shot.width, height: shot.height}, isMobile: Boolean(shot.isMobile), hasTouch: Boolean(shot.isMobile)});
        const shotPage = await context.newPage();
        const result = {name: shot.name, page: shot.path, viewport: `${shot.width}x${shot.height}`, theme, file: path.join(dir, theme, `${shot.name}.png`), sideways: null, errors: [], failedRequests: []};
        shotPage.on('pageerror', error => result.errors.push(error.message));
        shotPage.on('console', message => { if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) result.errors.push(message.text()); });
        shotPage.on('response', response => { if (response.url().startsWith(base) && response.status() >= 400) result.failedRequests.push(`${response.status()} ${response.url().slice(base.length)}`); });
        await shotPage.goto(base + shot.path);
        await settle(shotPage);
        if (shot.open) await shot.open(shotPage, helpers);
        await shotPage.mouse.move(Math.floor(shot.width / 2), 4);
        await settle(shotPage);
        if (new URL(shotPage.url()).pathname.startsWith('/login')) result.errors.push('Landed on the sign-in page instead');
        result.sideways = await shotPage.evaluate(sideways);
        fs.mkdirSync(path.dirname(result.file), {recursive: true});
        await shotPage.screenshot({path: result.file, fullPage: Boolean(shot.fullPage)});
        results.push(result);
        await context.close();
      }
    }
  } finally {
    await browser.close();
  }
  return results;
}

async function main() {
  const {values} = parseArgs({options: {demo: {type: 'boolean'}, base: {type: 'string'}, pages: {type: 'string'}, out: {type: 'string'}}});
  const pages = (values.pages || '').split(',').map(page => page.trim()).filter(Boolean);
  if (!pages.length || !values.out || (!values.demo && !values.base)) {
    console.error('Usage: node scripts/browser/screenshots.cjs (--demo | --base <url>) --pages /a,/b --out <dir>');
    process.exit(2);
  }
  const dir = path.resolve(values.out);
  const slug = address => address.replace(/^\//, '').replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') || 'dashboard';
  const shots = pages.flatMap(address => viewports.map(({name, ...size}) => ({name: `${slug(address)}-${name}`, path: address, fullPage: true, ...size})));
  if (values.demo) {
    buildDemo();
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => stopDemo({dir}).finally(() => process.exit(130)));
    await startDemo({dir});
  }
  try {
    const results = await capture({base: values.base || demoBase, shots, dir});
    const problems = results.filter(result => result.sideways || result.errors.length || result.failedRequests.length).length;
    console.log(JSON.stringify({ok: problems === 0, problems, shots: results}, null, 2));
    if (problems) process.exitCode = 1;
  } finally {
    if (values.demo) await stopDemo({dir});
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = {buildDemo, startDemo, stopDemo, capture, settle, post, viewports, demoBase};
