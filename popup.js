/**
 * PopStop Popup Script
 * Handles the extension popup interface interactions
 */

document.addEventListener('DOMContentLoaded', function() {
  // DOM elements
  const blockingToggle = document.getElementById('blockingToggle');
  const blockedCount = document.getElementById('blockedCount');
  const statusText = document.getElementById('statusText');
  const statusIndicator = document.getElementById('statusIndicator');
  const resetButton = document.getElementById('resetButton');
  const loadingIndicator = document.getElementById('loadingIndicator');
  const mainContent = document.getElementById('mainContent');
  const errorMessage = document.getElementById('errorMessage');
  
  let isLoading = false;
  
  /**
   * Show loading state
   */
  function showLoading() {
    isLoading = true;
    loadingIndicator.style.display = 'block';
    mainContent.style.display = 'none';
    errorMessage.style.display = 'none';
  }
  
  /**
   * Hide loading state
   */
  function hideLoading() {
    isLoading = false;
    loadingIndicator.style.display = 'none';
    mainContent.style.display = 'block';
  }
  
  /**
   * Show error message
   */
  function showError(message) {
    errorMessage.textContent = message;
    errorMessage.style.display = 'block';
    setTimeout(() => {
      errorMessage.style.display = 'none';
    }, 5000);
  }
  
  /**
   * Update the UI with current settings and stats
   */
  async function updateUI() {
    try {
      showLoading();
      
      // Get data from storage
      const result = await chrome.storage.sync.get(['blockingEnabled', 'blockedCount']);
      const isEnabled = result.blockingEnabled !== false; // Default to true
      const count = result.blockedCount || 0;
      
      // Update toggle
      blockingToggle.checked = isEnabled;
      
      // Update blocked count with animation
      const currentCount = parseInt(blockedCount.textContent) || 0;
      if (count !== currentCount) {
        blockedCount.classList.add('updated');
        setTimeout(() => {
          blockedCount.classList.remove('updated');
        }, 500);
      }
      blockedCount.textContent = count;
      
      // Update status
      if (isEnabled) {
        statusText.textContent = 'Active';
        statusIndicator.className = 'status-indicator status-enabled';
      } else {
        statusText.textContent = 'Disabled';
        statusIndicator.className = 'status-indicator status-disabled';
      }
      
      hideLoading();
      
    } catch (error) {
      console.error('Error updating UI:', error);
      showError('Failed to load settings');
      hideLoading();
    }
  }
  
  /**
   * Toggle blocking on/off
   */
  async function toggleBlocking(enabled) {
    try {
      console.log('PopStop: Attempting to toggle blocking to:', enabled);
      
      // Update storage FIRST
      await chrome.storage.sync.set({ blockingEnabled: enabled });
      console.log('PopStop: Storage updated successfully');
      
      // Send message to background script with timeout
      const response = await Promise.race([
        chrome.runtime.sendMessage({
          action: 'toggleBlocking',
          enabled: enabled
        }),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Background script timeout')), 5000)
        )
      ]);
      
      console.log('PopStop: Background response:', response);
      
      if (response && response.success) {
        // Send message to all content scripts
        const tabs = await chrome.tabs.query({});
        console.log(`PopStop: Updating ${tabs.length} tabs`);
        
        for (const tab of tabs) {
          try {
            await chrome.tabs.sendMessage(tab.id, {
              action: 'updateBlockingStatus',
              enabled: enabled
            });
            console.log('PopStop: Updated tab:', tab.id);
          } catch (err) {
            // Some tabs might not have the content script loaded
            console.log('PopStop: Could not update tab:', tab.id, err.message);
          }
        }
        
        // Update UI
        await updateUI();
        
        // Show success feedback
        const successMessage = enabled ? 'Pop-up blocking enabled' : 'Pop-up blocking disabled';
        console.log('PopStop: Success -', successMessage);
        
      } else {
        throw new Error('Background script returned error: ' + JSON.stringify(response));
      }
      
    } catch (error) {
      console.error('PopStop: Error toggling blocking:', error);
      showError(`Failed to update settings: ${error.message}`);
      
      // Revert toggle state
      blockingToggle.checked = !enabled;
      
      // Try to update UI anyway
      setTimeout(() => updateUI(), 1000);
    }
  }
  
  /**
   * Reset the blocked count
   */
  async function resetBlockedCount() {
    try {
      console.log('PopStop: Attempting to reset counter...');
      
      // Disable button temporarily
      resetButton.disabled = true;
      resetButton.textContent = '🔄 Resetting...';
      
      // Reset in storage FIRST
      await chrome.storage.sync.set({ blockedCount: 0 });
      console.log('PopStop: Storage reset successfully');
      
      // Send message to background script with timeout
      const response = await Promise.race([
        chrome.runtime.sendMessage({
          action: 'resetCount'
        }),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Reset timeout')), 5000)
        )
      ]);
      
      console.log('PopStop: Reset response:', response);
      
      if (response && response.success) {
        // Update UI immediately
        blockedCount.textContent = '0';
        blockedCount.classList.add('updated');
        setTimeout(() => {
          blockedCount.classList.remove('updated');
        }, 500);
        
        console.log('PopStop: Counter reset successful');
      } else {
        // Even if background fails, we already reset storage
        console.log('PopStop: Background reset failed, but storage was reset');
        blockedCount.textContent = '0';
      }
      
    } catch (error) {
      console.error('PopStop: Error resetting count:', error);
      
      // Try to reset storage again and update UI anyway
      try {
        await chrome.storage.sync.set({ blockedCount: 0 });
        blockedCount.textContent = '0';
        console.log('PopStop: Fallback reset successful');
      } catch (fallbackError) {
        console.error('PopStop: Fallback reset failed:', fallbackError);
        showError(`Failed to reset counter: ${error.message}`);
      }
    } finally {
      // Re-enable button
      resetButton.disabled = false;
      resetButton.textContent = '🔄 Reset Counter';
    }
  }
  
  /**
   * Get additional stats from background script
   */
  async function getAdditionalStats() {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'getStats'
      });
      
      if (response) {
        console.log('Extension stats:', response);
        // Could be used to show additional information in future versions
      }
    } catch (error) {
      console.log('Could not get additional stats:', error);
    }
  }
  
  /**
   * Event Listeners
   */
  
  // Toggle switch event
  blockingToggle.addEventListener('change', function() {
    if (!isLoading) {
      toggleBlocking(this.checked);
    }
  });
  
  // Reset button event
  resetButton.addEventListener('click', function() {
    if (!isLoading && !this.disabled) {
      resetBlockedCount();
    }
  });
  
  // Listen for storage changes (if changed from another popup instance)
  chrome.storage.onChanged.addListener(function(changes, namespace) {
    if (namespace === 'sync') {
      if (changes.blockedCount || changes.blockingEnabled) {
        updateUI();
      }
    }
  });
  
  // Listen for messages from background script
  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (message.action === 'updatePopup') {
      updateUI();
    }
    return true;
  });
  
  /**
   * Keyboard shortcuts
   */
  document.addEventListener('keydown', function(event) {
    // Space bar to toggle
    if (event.code === 'Space' && !isLoading) {
      event.preventDefault();
      blockingToggle.checked = !blockingToggle.checked;
      toggleBlocking(blockingToggle.checked);
    }
    
    // 'R' key to reset
    if (event.code === 'KeyR' && !isLoading && !resetButton.disabled) {
      event.preventDefault();
      resetBlockedCount();
    }
  });
  
  /**
   * Initialize the popup
   */
  async function initialize() {
    try {
      // Check if extension context is available
      if (!chrome.runtime || !chrome.storage) {
        throw new Error('Extension context not available');
      }
      
      // Load initial data
      await updateUI();
      
      // Get additional stats
      await getAdditionalStats();
      
      console.log('PopStop popup initialized');
      
    } catch (error) {
      console.error('Error initializing popup:', error);
      showError('Extension initialization failed');
      hideLoading();
    }
  }
  
  /**
   * Cleanup when popup is closed
   */
  window.addEventListener('beforeunload', function() {
    // Cleanup any ongoing operations
    console.log('PopStop popup closing');
  });
  
  // Start initialization
  initialize();
});

/**
 * Utility functions
 */

/**
 * Format number with commas for large counts
 */
function formatNumber(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Animate number change
 */
function animateNumberChange(element, startValue, endValue, duration = 500) {
  const startTime = performance.now();
  const difference = endValue - startValue;
  
  function updateNumber(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    
    // Easing function for smooth animation
    const easeInOutCubic = progress < 0.5 
      ? 4 * progress * progress * progress 
      : 1 - Math.pow(-2 * progress + 2, 3) / 2;
    
    const currentValue = Math.round(startValue + (difference * easeInOutCubic));
    element.textContent = formatNumber(currentValue);
    
    if (progress < 1) {
      requestAnimationFrame(updateNumber);
    }
  }
  
  requestAnimationFrame(updateNumber);
}

// Export for testing (if needed)
if (typeof module !== 'undefined') {
  module.exports = {
    formatNumber,
    animateNumberChange
  };
} 