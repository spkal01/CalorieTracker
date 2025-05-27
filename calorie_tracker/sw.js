const CACHE_NAME = 'calorie-tracker-v2';
const OFFLINE_URL = '/offline';

const ASSETS_TO_CACHE = [
  '/',
  '/landing',
  '/static/css/output.css',
  '/static/images/favicon.png',
  '/static/manifest.json', 
  '/sw.js',
  OFFLINE_URL,
  '/dashboard',
  '/diet',
  '/saved'
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
  const url = new URL(event.request.url);
  
  // Handle navigation requests (HTML pages)
  if (event.request.mode === 'navigate' || 
      (event.request.method === 'GET' && 
       event.request.headers.get('accept').includes('text/html'))) {
    event.respondWith(
      fetch(event.request)
        .catch(error => {
          console.log('Navigation fetch failed; returning offline page instead.', error);
          return caches.match(OFFLINE_URL);
        })
    );
  } 
  // Handle static assets (CSS, JS, images) - cache first
  else if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(event.request)
        .then(response => {
          if (response) {
            return response; // Return cached version
          }
          // If not in cache, fetch and cache
          return fetch(event.request).then(response => {
            if (response.status === 200) {
              const responseClone = response.clone();
              caches.open(CACHE_NAME).then(cache => {
                cache.put(event.request, responseClone);
              });
            }
            return response;
          });
        })
        .catch(error => {
          console.log('Static asset fetch failed:', event.request.url, error);
        })
    );
  }
  // Handle API calls and other requests - network first
  else {
    event.respondWith(
      fetch(event.request)
        .catch(error => {
          console.log('API/other fetch failed:', event.request.url, error);
          // Could return a cached API response or error page here
        })
    );
  }
});