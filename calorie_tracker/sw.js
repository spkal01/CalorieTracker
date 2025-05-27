const CACHE_NAME = 'calorie-tracker-v1'; // Increment cache version
const OFFLINE_URL = '/offline';

const ASSETS_TO_CACHE = [
  '/',
  '/static/css/output.css',
  '/static/images/favicon.png',
  '/landing',
  OFFLINE_URL // Add the offline page to assets to cache
];

// Install event: cache files
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Opened cache and caching assets');
        return cache.addAll(ASSETS_TO_CACHE);
      })
      .catch(error => {
        console.error('Failed to cache assets during install:', error);
      })
  );
  self.skipWaiting();
});

// Activate event: cleanup old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(key => {
          if (key !== CACHE_NAME) {
            console.log('Deleting old cache:', key);
            return caches.delete(key);
          }
        })
      )
    )
  );
  self.clients.claim();
});

// Fetch event: serve from cache, fallback to network, then to offline page
self.addEventListener('fetch', event => {
  // We only want to handle GET requests for navigation
  if (event.request.mode === 'navigate' || 
      (event.request.method === 'GET' && 
       event.request.headers.get('accept').includes('text/html'))) {
    event.respondWith(
      fetch(event.request)
        .catch(error => {
          // The network failed, try to serve the offline page from cache
          console.log('Fetch failed; returning offline page instead.', error);
          return caches.match(OFFLINE_URL);
        })
    );
  } else {
    // For non-navigation requests (like CSS, JS, images), try cache then network
    event.respondWith(
      caches.match(event.request)
        .then(response => {
          return response || fetch(event.request);
        })
        .catch(error => {
          console.log('Asset fetch failed:', event.request.url, error);
        })
    );
  }
});