const assert = require('node:assert/strict');
const {chromium} = require('playwright');

// Same real-touch helper as nav-swipe.cjs: the browser decides on scrolling
// the way a phone does.
const drag = async (cdp, from, to, steps = 12) => {
  const at = ([x, y]) => [{x, y, id: 1, radiusX: 4, radiusY: 4, force: 1}];
  let timestamp = Date.now() / 1000;
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: at(from), timestamp});
  for (let i = 1; i <= steps; i++) {
    timestamp += 0.016;
    await cdp.send('Input.dispatchTouchEvent', {type: 'touchMove', touchPoints: at([from[0] + (to[0] - from[0]) * i / steps, from[1] + (to[1] - from[1]) * i / steps]), timestamp});
  }
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: [], timestamp: timestamp + 0.008});
  // Let any fling finish: Chromium will not let a page cancel touches mid-fling.
  await new Promise(resolve => setTimeout(resolve, 1200));
};
// Whether the page refused the last touch move: a window listener runs after
// the document-level guard has had its say.
const refused = page => page.evaluate(() => window.lastTouchRefused);

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    const context = await browser.newContext({viewport: {width: 390, height: 844}, hasTouch: true, isMobile: true});
    const page = await context.newPage();
    await page.goto(process.argv[2]);
    await page.evaluate(() => {
      document.documentElement.style.scrollBehavior = 'auto';
      const filler = document.createElement('div');
      filler.style.height = '4000px';
      document.getElementById('main-content').append(filler);
      window.addEventListener('touchmove', event => { window.lastTouchRefused = event.defaultPrevented; }, {passive: true});
    });
    const cdp = await context.newCDPSession(page);

    // With no modal open the page scrolls freely.
    await drag(cdp, [195, 700], [195, 300]);
    assert.equal(await refused(page), false, 'touch scrolls reach the page without a modal');

    // A finger on the backdrop or on a part of the modal that cannot scroll
    // moves nothing.
    await page.evaluate(() => document.getElementById('cache-flush-dialog').showModal());
    await drag(cdp, [195, 830], [195, 300]);
    assert.equal(await refused(page), true, 'the backdrop does not scroll the page');
    const title = await page.evaluate(() => { const r = document.querySelector('#cache-flush-dialog h2, #cache-flush-dialog [id$=title]').getBoundingClientRect(); return [r.x + r.width / 2, r.y + r.height / 2]; });
    await drag(cdp, title, [title[0], title[1] - 200]);
    assert.equal(await refused(page), true, 'a modal that cannot scroll does not hand the touch to the page');
    await page.evaluate(() => document.getElementById('cache-flush-dialog').close());

    // A scroller inside the modal keeps its own touch scroll, and contains it.
    await page.evaluate(() => {
      const dialog = document.getElementById('cache-browser-dialog');
      const body = dialog.querySelector('.cache-browser-body');
      const tall = document.createElement('div');
      tall.style.height = '3000px';
      body.append(tall);
      dialog.showModal();
    });
    const inner = await page.evaluate(() => { const r = document.querySelector('#cache-browser-dialog .cache-browser-body').getBoundingClientRect(); return [r.x + r.width / 2, r.y + r.height / 2]; });
    await drag(cdp, inner, [inner[0], inner[1] - 150]);
    assert.equal(await refused(page), false, 'the modal scroller takes the touch');
    await page.waitForTimeout(200);
    assert.ok(await page.evaluate(() => document.querySelector('#cache-browser-dialog .cache-browser-body').scrollTop) > 0, 'the modal scroller moves');
    assert.equal(await page.evaluate(() => getComputedStyle(document.querySelector('#cache-browser-dialog .cache-browser-body')).overscrollBehaviorY), 'contain');
    console.log('modal scroll lock: ok');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exit(1); });
