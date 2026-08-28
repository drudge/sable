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
