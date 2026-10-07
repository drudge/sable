const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Real touch input through the DevTools protocol, so the browser decides on
// scrolling and cancelability the way a phone does. Each event carries its
// own timestamp, since headless Chromium delivers them on its own schedule.
const touch = async (cdp, points, {stepMs = 16, release = true} = {}) => {
  const at = ([x, y]) => [{x, y, id: 1, radiusX: 4, radiusY: 4, force: 1}];
  let timestamp = Date.now() / 1000;
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: at(points[0]), timestamp});
  for (const point of points.slice(1)) {
    timestamp += stepMs / 1000;
    await cdp.send('Input.dispatchTouchEvent', {type: 'touchMove', touchPoints: at(point), timestamp});
  }
  if (release) await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: [], timestamp: timestamp + 0.008});
};
const path = (from, to, steps) => Array.from({length: steps + 1}, (_, i) => [
  from[0] + (to[0] - from[0]) * i / steps, from[1] + (to[1] - from[1]) * i / steps,
]);
const isOpen = page => page.evaluate(() => document.documentElement.classList.contains('sidebar-mobile-open'));
const drawerX = page => page.evaluate(() => document.getElementById('app-sidebar').getBoundingClientRect().left);
const settle = page => page.waitForTimeout(350);
const close = async page => {
  await page.evaluate(() => document.querySelector('.sidebar-scrim').click());
  await settle(page);
  assert.equal(await isOpen(page), false);
};

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 390, height: 844}, hasTouch: true, isMobile: true});
    const page = await context.newPage();
    await page.goto(process.argv[2]);
    // A tall page to scroll and a wide table to scroll sideways.
    await page.evaluate(() => {
      const main = document.getElementById('main-content');
      const wide = document.createElement('div');
      wide.className = 'table-scroll';
      wide.id = 'wide';
      // The CSP drops style attributes, so size the cell from script.
      wide.innerHTML = '<table><tr><td>wide</td></tr></table>';
      Object.assign(wide.querySelector('td').style, {minWidth: '1200px', height: '120px'});
      main.prepend(wide);
      const tall = document.createElement('div');
      tall.style.height = '3000px';
      main.append(tall);
    });
    const cdp = await context.newCDPSession(page);
    const width = await page.evaluate(() => document.getElementById('app-sidebar').offsetWidth);

    // The drawer follows the finger mid-drag, with its transition off.
    await touch(cdp, path([60, 500], [60 + 14 + width / 2, 500], 12), {stepMs: 30, release: false});
    assert.ok(await page.evaluate(() => document.documentElement.classList.contains('sidebar-dragging')));
    const mid = await drawerX(page);
    assert.ok(Math.abs(mid + width / 2) < 4, `drawer tracks the finger: left ${mid}, expected ${-width / 2}`);
    assert.ok(Number(await page.evaluate(() => document.querySelector('.sidebar-scrim').style.opacity)) > 0.4);
    await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
    await settle(page);
    assert.equal(await isOpen(page), true, 'a half-way drag opens the drawer');
    assert.equal(await drawerX(page), 0);
    assert.equal(await page.evaluate(() => document.getElementById('app-sidebar').style.transform), '');
    assert.equal(await page.evaluate(() => document.documentElement.classList.contains('sidebar-dragging')), false);
    console.log('PASS drag right opens the drawer, following the finger');
    await close(page);

    // A short, slow drag snaps back.
    await touch(cdp, path([60, 500], [60 + 14 + width / 5, 500], 20), {stepMs: 40});
    await settle(page);
    assert.equal(await isOpen(page), false, 'a short drag snaps back closed');
    assert.ok(await drawerX(page) <= -width + 1);
    console.log('PASS a short drag snaps back');

    // A short, fast flick opens.
    await touch(cdp, path([60, 500], [60 + 14 + width / 5, 500], 4), {stepMs: 8});
    await settle(page);
    assert.equal(await isOpen(page), true, 'a flick opens the drawer');
    console.log('PASS a flick opens the drawer');
    await close(page);

    // A vertical swipe scrolls the page and leaves the drawer alone.
    await touch(cdp, path([200, 700], [215, 300], 12));
    await settle(page);
    assert.ok(await page.evaluate(() => window.scrollY) > 100, 'vertical swipe scrolls the page');
    assert.equal(await isOpen(page), false);
    console.log('PASS vertical scrolling still works');
    await page.evaluate(() => window.scrollTo(0, 0));
    await settle(page);

    // A sideways scroller keeps its drag. Scroll it a little first so a
    // right drag has somewhere to go.
    await page.evaluate(() => { document.getElementById('wide').scrollLeft = 400; });
    const box = await page.locator('#wide').boundingBox();
    const y = box.y + box.height / 2;
    await touch(cdp, path([100, y], [300, y], 12));
    await settle(page);
    assert.equal(await isOpen(page), false, 'wide table drag leaves the drawer closed');
    assert.ok(await page.evaluate(() => document.getElementById('wide').scrollLeft) < 400, 'wide table scrolled sideways');
    console.log('PASS wide tables scroll sideways without opening the drawer');

    // The menu button still works.
    await page.locator('[data-mobile-header] [data-sidebar-toggle]').click();
    await settle(page);
    assert.equal(await isOpen(page), true);
    await close(page);
    console.log('PASS the menu button still opens the drawer');

    const desktop = await browser.newContext({viewport: {width: 1280, height: 900}, hasTouch: true});
    const desk = await desktop.newPage();
    await desk.goto(process.argv[2]);
    const deskCDP = await desktop.newCDPSession(desk);
    // Desktop Chromium turns a sideways touch drag into history navigation.
    await desk.evaluate(() => { document.documentElement.style.overscrollBehaviorX = 'none'; });
    const before = await desk.evaluate(() => document.getElementById('app-sidebar').getBoundingClientRect().toJSON());
    await touch(deskCDP, path([700, 500], [1000, 500], 12));
    await settle(desk);
    assert.deepEqual(await desk.evaluate(() => document.getElementById('app-sidebar').getBoundingClientRect().toJSON()), before);
    assert.equal(await desk.evaluate(() => document.documentElement.className.includes('sidebar-mobile-open') || document.documentElement.className.includes('sidebar-dragging')), false);
    console.log('PASS desktop width is unaffected');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
