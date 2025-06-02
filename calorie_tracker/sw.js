const CACHE_NAME = 'calorie-tracker-v1.2';
const OFFLINE_URL = '/offline';

// Install: cache the offline page and essential assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll([
        OFFLINE_URL,
        '/static/css/output.css',
        '/static/images/favicon.png'
      ]);
    })
  );
  self.skipWaiting();
});

// Activate: clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(key => key !== CACHE_NAME ? caches.delete(key) : null)
      )
    )
  );
  self.clients.claim();
});

// Fetch: show offline page for failed navigation
self.addEventListener('fetch', event => {
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => caches.match(OFFLINE_URL))
    );
  }
});

/**
 * Push event handler
 * Triggered when a push message is received from the server
 */
self.addEventListener('push', event => {
  if (!event.data) {
    console.log('Push event received but no data');
    return;
  }

  try {
    // Parse the push data
    const data = event.data.json();
    
    // Default notification options
    const options = {
      body: data.body || 'New notification from Calorie Tracker',
      icon: data.icon || '/static/images/favicon.png',
      badge: '/static/images/favicon.png',
      data: {
        url: data.url || '/',
        actionData: data.actionData || {}
      },
      vibrate: [100, 50, 100],
      timestamp: data.timestamp || Date.now()
    };

    // Add actions if provided
    if (data.actions && Array.isArray(data.actions)) {
      options.actions = data.actions;
    }

    // Add tag if provided (for notification grouping)
    if (data.tag) {
      options.tag = data.tag;
    }

    // Show the notification
    event.waitUntil(
      self.registration.showNotification(data.title || 'Calorie Tracker', options)
    );
  } catch (error) {
    console.error('Error handling push event:', error);
  }
});

/**
 * Notification click event handler
 * Triggered when a user clicks on a notification
 */
self.addEventListener('notificationclick', event => {
  // Close the notification
  event.notification.close();

  // Get the notification data
  const data = event.notification.data || {};
  const url = data.url || '/';
  
  // Handle notification action buttons if clicked
  let actionUrl = url;
  if (event.action && data.actionData && data.actionData[event.action]) {
    actionUrl = data.actionData[event.action];
  }

  // Focus on existing window or open a new one
  event.waitUntil(
    clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    }).then(windowClients => {
      // Check if there is already a window/tab open with the target URL
      for (let i = 0; i < windowClients.length; i++) {
        const client = windowClients[i];
        // If so, focus it
        if (client.url === actionUrl && 'focus' in client) {
          return client.focus();
        }
      }
      
      // If not, open a new window/tab
      if (clients.openWindow) {
        return clients.openWindow(actionUrl);
      }
    })
  );
});

/**
 * Push subscription change event handler
 * Triggered when the push subscription changes
 */
self.addEventListener('pushsubscriptionchange', event => {
  event.waitUntil(
    // Get the server's public key
    fetch('/api/vapid-public-key')
      .then(response => response.json())
      .then(data => {
        // Convert the public key to the format needed for subscription
        function urlB64ToUint8Array(base64String) {
          const padding = '='.repeat((4 - base64String.length % 4) % 4);
          const base64 = (base64String + padding)
            .replace(/\-/g, '+')
            .replace(/_/g, '/');

          const rawData = window.atob(base64);
          const outputArray = new Uint8Array(rawData.length);

          for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
          }
          return outputArray;
        }

        // Create subscription options
        const options = {
          userVisibleOnly: true,
          applicationServerKey: urlB64ToUint8Array(data.publicKey)
        };

        // Subscribe with the new options
        return self.registration.pushManager.subscribe(options);
      })
      .then(subscription => {
        // Send the new subscription to the server
        return fetch('/api/push-subscription', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            subscription: subscription.toJSON(),
            oldEndpoint: event.oldSubscription ? event.oldSubscription.endpoint : null
          })
        });
      })
  );
});

/**
 * Sync event handler for background sync
 * Used for offline subscription management
 */
self.addEventListener('sync', event => {
  if (event.tag === 'sync-subscriptions') {
    event.waitUntil(
      // Get stored subscriptions from IndexedDB and sync with server
      // Implementation depends on how offline storage is handled
      syncSubscriptionsWithServer()
    );
  }
});

/**
 * Helper function to sync subscriptions with server
 * Used by the sync event handler
 */
async function syncSubscriptionsWithServer() {
  // This is a placeholder for the actual implementation
  // The actual implementation would retrieve pending subscription changes
  // from IndexedDB and send them to the server
  console.log('Syncing subscriptions with server');
  
  // Example implementation:
  // 1. Open IndexedDB
  // 2. Get pending subscription changes
  // 3. Send each change to the server
  // 4. Mark changes as processed
  
  return Promise.resolve();
}
