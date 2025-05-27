// Mobile UI Enhancement JavaScript
// This file contains JavaScript functions for the enhanced mobile experience

document.addEventListener('DOMContentLoaded', function() {
  // Check if on mobile device
  function isMobileDevice() {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) || window.innerWidth <= 768;
  }

  // Only run mobile enhancements if on a mobile device
  if (isMobileDevice()) {
    // Set active state for bottom navigation based on current path
    setActiveBottomNavItem();
    
    // Add ripple effect to mobile buttons and cards
    addRippleEffect();
    
    // Add enhanced haptic feedback
    enhanceHapticFeedback();
    
    // Add smooth page transitions
    addPageTransitions();
  }

  // Set active state for bottom navigation
  function setActiveBottomNavItem() {
    const currentPath = window.location.pathname;
    const bottomNavItems = document.querySelectorAll('.bottom-nav-item');
    
    bottomNavItems.forEach(item => {
      const itemPath = item.getAttribute('href');
      if (itemPath === currentPath) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });
  }

  // Add ripple effect to buttons and interactive elements
  function addRippleEffect() {
    const interactiveElements = document.querySelectorAll(
      '.mobile-button, .mobile-card-interactive, .bottom-nav-item, .mobile-list-item, .header-action-button'
    );
    
    interactiveElements.forEach(element => {
      element.addEventListener('touchstart', createRipple);
    });
    
    function createRipple(event) {
      const button = event.currentTarget;
      
      // Remove any existing ripple
      const existingRipple = button.querySelector('.ripple');
      if (existingRipple) {
        existingRipple.remove();
      }
      
      // Create new ripple
      const ripple = document.createElement('span');
      ripple.classList.add('ripple');
      button.appendChild(ripple);
      
      // Position the ripple
      const rect = button.getBoundingClientRect();
      const size = Math.max(rect.width, rect.height);
      
      ripple.style.width = ripple.style.height = `${size}px`;
      ripple.style.left = `${event.touches[0].clientX - rect.left - size / 2}px`;
      ripple.style.top = `${event.touches[0].clientY - rect.top - size / 2}px`;
      
      // Remove ripple after animation completes
      setTimeout(() => {
        ripple.remove();
      }, 600);
    }
  }

  // Enhanced haptic feedback for different interactions
  function enhanceHapticFeedback() {
    if ('vibrate' in navigator) {
      // Primary buttons - stronger vibration
      document.addEventListener('click', function(e) {
        const primaryButton = e.target.closest('.mobile-button-primary');
        if (primaryButton) {
          navigator.vibrate(12);
        }
      });
      
      // Secondary buttons - lighter vibration
      document.addEventListener('click', function(e) {
        const secondaryButton = e.target.closest('.mobile-button-secondary, .header-action-button');
        if (secondaryButton) {
          navigator.vibrate(8);
        }
      });
      
      // Bottom navigation - medium vibration
      document.addEventListener('click', function(e) {
        const navItem = e.target.closest('.bottom-nav-item');
        if (navItem) {
          navigator.vibrate(10);
        }
      });
    }
  }

  // Add smooth page transitions
  function addPageTransitions() {
    // Store the current page in session storage when navigating
    document.addEventListener('click', function(e) {
      const link = e.target.closest('a[href]');
      if (link && !link.target && link.hostname === window.location.hostname) {
        sessionStorage.setItem('lastPage', window.location.pathname);
      }
    });
    
    // Add transition class on page load if coming from another page
    const lastPage = sessionStorage.getItem('lastPage');
    if (lastPage && lastPage !== window.location.pathname) {
      const contentContainer = document.getElementById('content-container');
      if (contentContainer) {
        contentContainer.classList.add('page-transition-in');
        setTimeout(() => {
          contentContainer.classList.remove('page-transition-in');
        }, 300);
      }
    }
  }
});

// Add CSS for ripple effect and page transitions
document.addEventListener('DOMContentLoaded', function() {
  if (window.innerWidth <= 768) {
    const style = document.createElement('style');
    style.textContent = `
      .ripple {
        position: absolute;
        background-color: rgba(255, 255, 255, 0.3);
        border-radius: 50%;
        transform: scale(0);
        animation: ripple 0.6s linear;
        pointer-events: none;
      }
      
      @keyframes ripple {
        to {
          transform: scale(4);
          opacity: 0;
        }
      }
      
      .page-transition-in {
        animation: fadeInUp 0.3s ease forwards;
      }
      
      @keyframes fadeInUp {
        from {
          opacity: 0;
          transform: translateY(20px);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }
      
      .mobile-button, .mobile-card-interactive, .bottom-nav-item, .mobile-list-item, .header-action-button {
        position: relative;
        overflow: hidden;
      }
    `;
    document.head.appendChild(style);
  }
});
