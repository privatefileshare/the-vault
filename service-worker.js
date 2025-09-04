// This is a basic service worker for Progressive Web App (PWA) functionality.
// It handles caching and provides a simple offline experience.

const CACHE_NAME = 'the-vault-cache-v1';
const urlsToCache = [
  '/',
  '/favicon.png'
  // You can add other static assets here like CSS files or logos if you have them
];

// Install event: fires when the browser installs the service worker.
self.addEventListener('install', (event) => {
  // Perform install steps
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
});

// Fetch event: fires for every network request the page makes.
self.addEventListener('fetch', (event) => {
  event.respondWith(
    // Try to find a matching request in the cache first.
    caches.match(event.request)
      .then((response) => {
        // If a cached version is found, return it.
        if (response) {
          return response;
        }

        // If not found in cache, try to fetch it from the network.
        return fetch(event.request).catch(() => {
          // If the network fetch also fails (i.e., the user is offline),
          // return a basic offline fallback page.
          return new Response(
            '<h1>You are offline</h1><p>This app requires an internet connection to function.</p>', 
            { headers: { 'Content-Type': 'text/html' } }
          );
        });
      })
  );
});