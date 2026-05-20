// Hermes Agent — Service Worker
// Caches the app shell for fast loads and offline support.
// Version: 1

const CACHE_NAME = 'hermes-dashboard-v1';

// App shell files to cache on install.
const APP_SHELL = [
  '/',
  '/index.html',
  '/manifest.json',
  '/favicon.ico',
  '/icons/icon-192x192.png',
  '/icons/icon-512x512.png',
];

// Install — cache the app shell.
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      // Silently cache what we can; non-critical failures shouldn't block install.
      return Promise.allSettled(
        APP_SHELL.map((url) =>
          cache.add(url).catch(() => {
            // Some assets (like / with injected token) may vary — that's fine.
          })
        )
      );
    })
  );
  // Activate immediately without waiting for existing clients to close.
  self.skipWaiting();
});

// Activate — clean up old caches.
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      )
    )
  );
  // Take control of all clients immediately.
  self.clients.claim();
});

// Fetch — network-first for API/WebSocket requests, cache-first for static assets.
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Never cache API calls or WebSocket upgrades.
  if (url.pathname.startsWith('/api/') || event.request.url.includes('/api/')) {
    return;
  }

  // Never cache WebSocket upgrades.
  if (
    event.request.headers.get('upgrade') === 'websocket' ||
    url.protocol === 'wss:' ||
    url.protocol === 'ws:'
  ) {
    return;
  }

  // For navigation requests (HTML pages), try network first, fall back to cached index.html.
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          // Cache a copy for offline.
          const cloned = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, cloned);
          });
          return response;
        })
        .catch(() => caches.match('/index.html') || caches.match(event.request))
    );
    return;
  }

  // For static assets (JS, CSS, images, fonts), cache-first.
  if (
    url.pathname.startsWith('/assets/') ||
    url.pathname.startsWith('/icons/') ||
    url.pathname.startsWith('/fonts/') ||
    url.pathname.startsWith('/ds-assets/') ||
    url.pathname.endsWith('.png') ||
    url.pathname.endsWith('.svg') ||
    url.pathname.endsWith('.ico') ||
    url.pathname.endsWith('.woff2') ||
    url.pathname.endsWith('.woff') ||
    url.pathname.endsWith('.css') ||
    url.pathname.endsWith('.js')
  ) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        if (cached) {
          // Return cached, but update cache in background.
          fetch(event.request).then((fresh) => {
            if (fresh && fresh.ok) {
              caches.open(CACHE_NAME).then((cache) => cache.put(event.request, fresh));
            }
          }).catch(() => {});
          return cached;
        }
        // Not cached yet — fetch and cache.
        return fetch(event.request).then((response) => {
          if (response.ok) {
            const cloned = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, cloned));
          }
          return response;
        });
      })
    );
    return;
  }

  // Default: network first, cache fallback.
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok) {
          const cloned = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, cloned));
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});