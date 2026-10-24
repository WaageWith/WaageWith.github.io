// Offline-Unterstützung: App-Dateien aus dem Cache, Messdaten immer frisch aus dem Netz.
const CACHE = 'withings-dashboard-v2';
const SHELL = ['./', 'index.html', 'd3.min.js', 'manifest.webmanifest', 'icons/icon-192.png',
  'fonts/figtree-latin-400-normal.woff2', 'fonts/figtree-latin-500-normal.woff2', 'fonts/figtree-latin-600-normal.woff2',
  'fonts/figtree-latin-700-normal.woff2', 'fonts/figtree-latin-800-normal.woff2'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.endsWith('data.enc.json') || url.pathname.endsWith('callback.html')) return; // immer Netz
  // Netz zuerst, damit Updates sofort ankommen; Cache nur als Rückfall ohne Verbindung
  e.respondWith(
    fetch(e.request).then((res) => {
      const copy = res.clone();
      caches.open(CACHE).then((c) => c.put(e.request, copy));
      return res;
    }).catch(() => caches.match(e.request).then((r) => r || caches.match('index.html')))
  );
});
