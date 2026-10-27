const assert = require('node:assert/strict');
const {chromium} = require('playwright');

const layout = page => page.evaluate(() => {
  const box = selector => document.querySelector(selector).getBoundingClientRect();
  return {
    book: document.documentElement.classList.contains('book-pages'),
    collapsed: document.documentElement.classList.contains('sidebar-collapsed'),
    sidebarRight: box('.sidebar').right,
    mainLeft: box('.main').left,
    mainWidth: box('.main').width,
    // 24px in the laptop layout, 16px in the phone one.
    cardPadding: getComputedStyle(document.querySelector('.cache-card-body')).paddingLeft,
  };
});
// The view transition that turns the pages runs on its own clock.
const settle = page => page.waitForTimeout(500);

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.SABLE_TEST_BROWSER ? {executablePath: process.env.SABLE_TEST_BROWSER} : {})});
  try {
    // An iPhone Duo, unfolded and held wide, in Safari.
    const duo = await browser.newContext({viewport: {width: 951, height: 543}, hasTouch: true, isMobile: true});
    const page = await duo.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(process.argv[2]);
    let open = await layout(page);
    assert.equal(open.book, true, 'the unfolded Duo opens as a book');
    assert.ok(Math.abs(open.sidebarRight - 475.5) < 1, `the sidebar fills the left page: ${open.sidebarRight}`);
    assert.ok(Math.abs(open.mainLeft - 475.5) < 1 && Math.abs(open.mainWidth - 475.5) < 1, `the page fills the right page: ${open.mainLeft} + ${open.mainWidth}`);
    assert.equal(open.cardPadding, '16px', 'the right page uses the phone layout');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'the book does not scroll sideways');

    // The keyboard shortens the window without the phone changing shape.
    await page.setViewportSize({width: 951, height: 300});
    await settle(page);
    assert.equal((await layout(page)).book, true, 'the keyboard does not close the book');

    // Folded, it's a phone; unfolded again, a book.
    await page.setViewportSize({width: 466, height: 678});
    await settle(page);
    assert.equal((await layout(page)).book, false, 'the folded phone is not a book');
    await page.setViewportSize({width: 951, height: 543});
    await settle(page);
    assert.equal((await layout(page)).book, true, 'unfolding opens the book again');

    // Held tall, the unfolded Duo is not a book either.
    await page.setViewportSize({width: 669, height: 869});
    await settle(page);
    assert.equal((await layout(page)).book, false, 'held tall it is not a book');
    await page.setViewportSize({width: 951, height: 543});
    await settle(page);

    // The sidebar button closes the book into one page across the screen.
    await page.click('.sidebar-collapse');
    await settle(page);
    const closed = await layout(page);
    assert.equal(closed.collapsed, true);
    assert.ok(closed.mainLeft < 100 && closed.mainWidth > 800, `the page takes the whole screen: ${closed.mainLeft} + ${closed.mainWidth}`);
    assert.equal(closed.cardPadding, '24px', 'one page across the screen uses the wider layout');
    await page.click('.sidebar-rail');
    await settle(page);
    assert.equal((await layout(page)).mainLeft > 470, true, 'the sidebar button opens the book again');

    // A dialog opens over the right page.
    await page.evaluate(() => {
      const dialog = document.createElement('dialog');
      dialog.className = 'custom-server-dialog';
      dialog.textContent = 'Fixture';
      document.querySelector('.main').append(dialog);
      dialog.showModal();
    });
    const dialog = await page.evaluate(() => document.querySelector('.main > dialog').getBoundingClientRect().toJSON());
    assert.ok(dialog.left >= 475.5 && dialog.right <= 951, `the dialog stays on the right page: ${dialog.left}-${dialog.right}`);
    assert.deepEqual(errors, []);
    await duo.close();

    // A laptop window the same size, with a mouse, keeps the usual layout.
    const laptop = await browser.newContext({viewport: {width: 951, height: 543}});
    const desk = await laptop.newPage();
    await desk.goto(process.argv[2]);
    const usual = await layout(desk);
    assert.equal(usual.book, false, 'a mouse-driven window is never a book');
    assert.ok(usual.sidebarRight < 300, `the laptop sidebar keeps its width: ${usual.sidebarRight}`);
    await laptop.close();
    console.log('book mode ok');
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exit(1);
});
