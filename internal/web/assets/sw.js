// Sable's service worker shows the Insights alerts Sable pushes to this
// browser, even when no Sable page is open. It does nothing else: it caches
// nothing and never stands between the console and the server.
self.addEventListener("push", (event) => {
  let alert = {};
  try {
    alert = event.data?.json() || {};
  } catch {
    alert = {body: event.data?.text() || ""};
  }
  event.waitUntil(self.registration.showNotification(alert.title || "Sable", {
    body: alert.body || "",
    icon: alert.icon,
    // A finding that alerts again replaces its notification instead of piling up.
    tag: alert.tag,
    data: {url: alert.url || "/insights"},
  }));
});

// Opening an alert goes to Insights, in a Sable window already open there
// when there is one.
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = new URL(event.notification.data?.url || "/insights", self.location.origin);
  event.waitUntil(self.clients.matchAll({type: "window", includeUncontrolled: true}).then((windows) => {
    const open = windows.find((client) => new URL(client.url).pathname === target.pathname);
    return open ? open.focus() : self.clients.openWindow(target.href);
  }));
});
