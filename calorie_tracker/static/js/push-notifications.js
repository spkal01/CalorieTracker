/**
 * Push Notification Utility for CalorieTracker PWA
 * 
 * This module handles push notification subscription, permission management,
 * and user preferences for the CalorieTracker Progressive Web App.
 */

class PushNotificationManager {
  constructor() {
    this.swRegistration = null;
    this.isSubscribed = false;
    this.applicationServerPublicKey = null;
  }

  /**
   * Initialize the push notification manager
   * @param {string} vapidPublicKey - The VAPID public key for push subscription
   * @returns {Promise} - Resolves when initialization is complete
   */
  async initialize(vapidPublicKey) {
    try {
      // Store the application server public key
      this.applicationServerPublicKey = vapidPublicKey;

      // Check if service worker and push manager are supported
      if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        console.log('Push notifications are not supported in this browser');
        return false;
      }

      // Get the service worker registration
      this.swRegistration = await navigator.serviceWorker.ready;
      
      // Check if already subscribed
      const subscription = await this.swRegistration.pushManager.getSubscription();
      this.isSubscribed = subscription !== null;
      
      return true;
    } catch (error) {
      console.error('Error initializing push notifications:', error);
      return false;
    }
  }

  /**
   * Convert a base64 string to Uint8Array for the push subscription
   * @param {string} base64String - The base64 encoded string
   * @returns {Uint8Array} - The converted array
   */
  _urlB64ToUint8Array(base64String) {
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

  /**
   * Subscribe to push notifications
   * @returns {Promise<PushSubscription|null>} - The push subscription object or null if failed
   */
  async subscribe() {
    try {
      if (!this.swRegistration) {
        console.error('Service worker registration not found');
        return null;
      }

      // Create subscription options with the application server key
      const options = {
        userVisibleOnly: true,
        applicationServerKey: this._urlB64ToUint8Array(this.applicationServerPublicKey)
      };

      // Subscribe to push notifications
      const subscription = await this.swRegistration.pushManager.subscribe(options);
      this.isSubscribed = true;
      
      // Send the subscription to the server
      await this._sendSubscriptionToServer(subscription);
      
      return subscription;
    } catch (error) {
      console.error('Failed to subscribe to push notifications:', error);
      return null;
    }
  }

  /**
   * Unsubscribe from push notifications
   * @returns {Promise<boolean>} - True if unsubscribed successfully
   */
  async unsubscribe() {
    try {
      const subscription = await this.swRegistration.pushManager.getSubscription();
      
      if (subscription) {
        // Unsubscribe from push manager
        await subscription.unsubscribe();
        
        // Remove subscription from server
        await this._removeSubscriptionFromServer(subscription);
        
        this.isSubscribed = false;
        return true;
      }
      
      return false;
    } catch (error) {
      console.error('Error unsubscribing from push notifications:', error);
      return false;
    }
  }

  /**
   * Check if the user has granted notification permission
   * @returns {string} - The permission status: 'granted', 'denied', or 'default'
   */
  getNotificationPermission() {
    return Notification.permission;
  }

  /**
   * Request notification permission from the user
   * @returns {Promise<string>} - The permission status after request
   */
  async requestNotificationPermission() {
    try {
      const permission = await Notification.requestPermission();
      return permission;
    } catch (error) {
      console.error('Error requesting notification permission:', error);
      return 'denied';
    }
  }

  /**
   * Send the subscription to the server
   * @param {PushSubscription} subscription - The push subscription object
   * @returns {Promise<boolean>} - True if sent successfully
   */
  async _sendSubscriptionToServer(subscription) {
    try {
      // Get CSRF token from meta tag
      const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
      
      // Send subscription to server
      const response = await fetch('/api/push-subscription', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
          subscription: subscription.toJSON(),
          userAgent: navigator.userAgent
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to send subscription to server');
      }
      
      return true;
    } catch (error) {
      console.error('Error sending subscription to server:', error);
      return false;
    }
  }

  /**
   * Remove the subscription from the server
   * @param {PushSubscription} subscription - The push subscription object
   * @returns {Promise<boolean>} - True if removed successfully
   */
  async _removeSubscriptionFromServer(subscription) {
    try {
      // Get CSRF token from meta tag
      const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
      
      // Remove subscription from server
      const response = await fetch('/api/push-subscription', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
          subscription: subscription.toJSON()
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to remove subscription from server');
      }
      
      return true;
    } catch (error) {
      console.error('Error removing subscription from server:', error);
      return false;
    }
  }

  /**
   * Update notification preferences
   * @param {Object} preferences - The notification preferences
   * @returns {Promise<boolean>} - True if updated successfully
   */
  async updateNotificationPreferences(preferences) {
    try {
      // Get CSRF token from meta tag
      const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
      
      // Update preferences on server
      const response = await fetch('/api/notification-preferences', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
        },
        body: JSON.stringify(preferences)
      });
      
      if (!response.ok) {
        throw new Error('Failed to update notification preferences');
      }
      
      return true;
    } catch (error) {
      console.error('Error updating notification preferences:', error);
      return false;
    }
  }

  /**
   * Display a soft permission prompt before requesting browser permission
   * @param {string} containerId - The ID of the container to show the prompt in
   * @returns {Promise<boolean>} - True if user agrees to proceed
   */
  showSoftPermissionPrompt(containerId) {
    return new Promise((resolve) => {
      const container = document.getElementById(containerId);
      if (!container) {
        resolve(false);
        return;
      }
      
      // Create soft permission prompt
      const promptDiv = document.createElement('div');
      promptDiv.className = 'bg-zinc-800 border border-zinc-700 rounded-lg p-4 mb-4';
      promptDiv.innerHTML = `
        <h3 class="text-lg font-semibold mb-2">Enable Notifications</h3>
        <p class="text-zinc-300 mb-3">Get reminders for meal logging and updates on your calorie goals.</p>
        <div class="flex space-x-3">
          <button id="notification-allow" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">
            Enable
          </button>
          <button id="notification-deny" class="bg-zinc-700 hover:bg-zinc-600 text-white px-4 py-2 rounded">
            Not Now
          </button>
        </div>
      `;
      
      container.prepend(promptDiv);
      
      // Add event listeners
      document.getElementById('notification-allow').addEventListener('click', () => {
        container.removeChild(promptDiv);
        resolve(true);
      });
      
      document.getElementById('notification-deny').addEventListener('click', () => {
        container.removeChild(promptDiv);
        resolve(false);
      });
    });
  }
}

// Create and export a singleton instance
const pushNotificationManager = new PushNotificationManager();

// Make it available globally
window.pushNotificationManager = pushNotificationManager;
