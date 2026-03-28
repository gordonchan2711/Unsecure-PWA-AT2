// ─────────────────────────────────────────────────────────────────────────────
//  serviceWorker.js  —  Version 1
//  PWA fix: service worker now works correctly on Codespaces forwarded ports.
//
//  STILL VULNERABLE (intentional):
//    1. Cache Poisoning    — caches all GET responses including user pages
//    2. skipWaiting        — compromised SW update takes effect immediately
//    3. clients.claim()    — instantly hijacks all open tabs
//    4. No SRI checks      — cached resources have no integrity verification
//    5. Push Phishing      — notification URL opened with no validation
//    6. Hardcoded VAPID    — public key visible in source
// ─────────────────────────────────────────────────────────────────────────────

const CACHE_NAME = 'social-pwa-cache-v1';

const PRECACHE_URLS = [
  '/',
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

// ── INSTALL ───────────────────────────────────────────────────────────────────
self.addEventListener('install', function (event) {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      console.log('[SW] Pre-caching app shell');
      return cache.addAll(PRECACHE_URLS);
    })
  );
});

// ── ACTIVATE ─────────────────────────────────────────────────────────────────
self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (cacheNames) {
      return Promise.all(
        cacheNames
          .filter(name => name !== CACHE_NAME)
          .map(name => caches.delete(name))
      );
    }).then(function () {
      return clients.claim();
    })
  );
});

// ── FETCH ─────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', function (event) {
  // Only handle GET requests from same origin
  if (event.request.method !== 'GET') return;

  // PWA FIX: skip chrome-extension and non-http requests
  if (!event.request.url.startsWith('http')) return;

  event.respondWith(
    caches.match(event.request).then(function (cachedResponse) {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request).then(function (networkResponse) {
        if (event.request.method === 'GET') {
          let responseClone = networkResponse.clone();
          caches.open(CACHE_NAME).then(function (cache) {
            cache.put(event.request, responseClone);
          });
        }
        return networkResponse;
      }).catch(function () {
        return caches.match('/');
      });
    })
  );
});

// ── PUSH NOTIFICATIONS ────────────────────────────────────────────────────────
self.addEventListener('push', function (event) {
  let data = { title: 'SocialPWA', body: 'You have a new notification!', url: '/' };
  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      console.warn('[SW] Push data parse error:', e);
    }
  }
  const options = {
    body: data.body,
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    tag: 'social-pwa-notification',
    data: { url: data.url || '/' }
  };
  event.waitUntil(
    self.registration.showNotification(data.title || 'SocialPWA', options)
  );
});

// ── NOTIFICATION CLICK ────────────────────────────────────────────────────────
self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  const targetUrl = event.notification.data.url || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (clientList) {
      for (let client of clientList) {
        if (client.url === targetUrl && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(targetUrl);
    })
  );
});
