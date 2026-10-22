/* Service worker: shows "something arrived" notifications. They never
 * contain message text; tapping one opens the inbox or the conversation. */
self.addEventListener("push", (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (_) { /* show the generic one */ }
  event.waitUntil(self.registration.showNotification(data.title || "Complaints", {
    body: data.body || "You have a new message.",
    icon: "icon-192.png",
    badge: "favicon-32.png",
    tag: data.tag || "secret-message",
    renotify: true,
    data: { url: new URL(data.url || "./", self.registration.scope).href },
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = event.notification.data && event.notification.data.url;
  event.waitUntil((async () => {
    const open = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    // Reuse a tab already on that page; otherwise open a new one.
    const same = open.find((c) => c.url.split("#")[0] === url.split("#")[0]);
    if (same) return same.focus();
    return self.clients.openWindow(url);
  })());
});
