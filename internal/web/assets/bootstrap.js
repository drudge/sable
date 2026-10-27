(() => {
  const themeKey = "sable-theme";
  const sidebarKey = "sable-sidebar-collapsed";
  const systemDark = () => window.matchMedia("(prefers-color-scheme: dark)").matches;
  let theme = "system";
  let sidebarCollapsed = false;
  try {
    const storedTheme = localStorage.getItem(themeKey);
    if (["light", "dark"].includes(storedTheme)) theme = storedTheme;
    sidebarCollapsed = localStorage.getItem(sidebarKey) === "true";
  } catch {}
  document.documentElement.classList.toggle("dark", theme === "dark" || (theme === "system" && systemDark()));
  document.documentElement.classList.toggle("sidebar-collapsed", sidebarCollapsed);

  // Book mode: an unfolded foldable such as the iPhone Duo, held wide, reads
  // like a book, with the sidebar on the left page and the page itself, at
  // phone size, on the right. Safari can't see the fold, so the window's
  // shape says so: a touch screen 768 to 1100 points wide and 1.2 to 1.9
  // times as wide as it is tall. The keyboard shortens a Home Screen app's
  // window without the phone changing shape, so at one width the tallest
  // height seen counts. This runs before the first paint so the console
  // never opens in one layout and jumps to the other.
  const root = document.documentElement;
  let bookWidth = 0;
  let bookHeight = 0;
  const bookShape = () => {
    const width = window.innerWidth;
    if (width !== bookWidth) { bookWidth = width; bookHeight = 0; }
    bookHeight = Math.max(bookHeight, window.innerHeight);
    const ratio = width / bookHeight;
    return window.matchMedia("(pointer: coarse)").matches && width >= 768 && width <= 1100 && bookHeight >= 500 && ratio >= 1.2 && ratio <= 1.9;
  };
  // Opening or closing the book, by unfolding the phone or with the sidebar
  // button, morphs the sidebar and the page into their new places.
  // A turn that starts before the last one ends skips it, so only the
  // latest one takes the class away.
  let turning = null;
  const turnPages = (change) => {
    if (!document.startViewTransition || !document.body || window.matchMedia("(prefers-reduced-motion: reduce)").matches) { change(); return; }
    root.classList.add("book-turning");
    const transition = document.startViewTransition(change);
    turning = transition;
    transition.ready.catch(() => {});
    transition.finished.catch(() => {}).then(() => {
      if (turning === transition) root.classList.remove("book-turning");
    });
  };
  window.sableTurnPages = (change) => root.classList.contains("book-pages") ? turnPages(change) : change();
  const syncBook = (animate = true) => {
    const book = bookShape();
    if (book === root.classList.contains("book-pages")) return;
    const change = () => root.classList.toggle("book-pages", book);
    if (animate) turnPages(change);
    else change();
  };
  syncBook(false);
  // iOS can hand a Home Screen app its window at the folded screen's size
  // and settle it later without a resize, so look again whenever the page's
  // box changes, when it comes back into view, and a few times after.
  let bookTimers = [];
  const syncBookSoon = () => {
    syncBook();
    bookTimers.forEach(clearTimeout);
    bookTimers = [150, 500, 1200, 2500].map((delay) => setTimeout(syncBook, delay));
  };
  window.addEventListener("resize", () => syncBook());
  window.addEventListener("orientationchange", syncBookSoon);
  window.addEventListener("pageshow", syncBookSoon);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) syncBookSoon(); });
  new ResizeObserver(() => syncBook()).observe(root);

  // Timestamps render on the server, so tell it which zone this browser is in.
  const timeZoneCookie = "sable_time_zone";
  const readCookie = (name) => document.cookie.split("; ").find((entry) => entry.startsWith(`${name}=`))?.slice(name.length + 1) ?? "";
  let browserTimeZone = "";
  try { browserTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch {}
  if (/^[A-Za-z0-9_+\-/]{1,64}$/.test(browserTimeZone) && readCookie(timeZoneCookie) !== browserTimeZone) {
    document.cookie = `${timeZoneCookie}=${browserTimeZone}; Path=/; Max-Age=31536000; SameSite=Lax`;
    // Only reload once the cookie actually stuck, otherwise this would loop.
    if (readCookie(timeZoneCookie) === browserTimeZone) window.location.reload();
  }
})();
