// Keeps a copy of the app on the phone so it opens instantly and works offline.
const C = "oc-shell-v1";
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(C).then((c) => c.addAll(["/", "/manifest.webmanifest", "/icon-180.png"])).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const u = new URL(req.url);
  const own = u.origin === self.location.origin;
  const font = /(^|\.)fonts\.(googleapis|gstatic)\.com$/.test(u.hostname);
  if (!own && !font) return;
  if (own && (u.pathname.startsWith("/api") || u.pathname === "/version.json" || u.pathname === "/sw.js")) return;
  const key = own && (req.mode === "navigate" || u.pathname === "/") ? "/" : req;
  e.respondWith(
    caches.open(C).then(async (c) => {
      const fresh = () =>
        fetch(req).then((r) => {
          if (r.ok || r.type === "opaque") c.put(key, r.clone());
          return r;
        });
      if (req.cache === "reload" || req.cache === "no-store") return fresh();
      const hit = await c.match(key);
      if (hit) {
        if (!font) e.waitUntil(fresh().catch(() => {}));
        return hit;
      }
      return fresh();
    }),
  );
});

// A partner added a shared event: show it, and open the app when tapped.
self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data.json(); } catch (x) {}
  e.waitUntil(self.registration.showNotification(d.title || "Our Countdowns", { body: d.body || "", icon: "/icon-180.png", badge: "/icon-180.png" }));
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((cs) => (cs.length ? cs[0].focus() : self.clients.openWindow("/"))));
});
