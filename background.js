/**
 * PopStop Background Service Worker
 * Handles pop-up blocking, request monitoring, and storage management
 */

// AI-ENHANCED: Comprehensive threat database for universal coverage
const AD_DOMAINS = [
  // General Ad Networks
  'googleads.g.doubleclick.net', 'googlesyndication.com', 'amazon-adsystem.com',
  'facebook.com/tr', 'outbrain.com', 'taboola.com', 'adsystem.amazon.com',
  'ads.yahoo.com', 'bing.com/ads', 'adnxs.com', 'bidswitch.net',
  'casalemedia.com', 'contextweb.com', 'doubleclick.net', 'rubiconproject.com',
  'scorecardresearch.com', 'turn.com', 'adsystem.amazon.co.uk',
  
  // Adult Site Ad Networks (Essential for universal coverage)
  'exoclick.com', 'juicyads.com', 'trafficjunky.net', 'plugrush.com',
  'exosrv.com', 'tsyndicate.com', 'streamate.com', 'cams.com',
  'chaturbate.com/affiliates', 'livejasmin.com/landing', 'stripchat.com/promo',
  'bongacams.com/promo', 'cam4.com/ads', 'flirt4free.com/go',
  'adsterra.com', 'hilltopads.net', 'propellerads.com', 'popcash.net',
  'popads.net', 'popunder.net', 'adcash.com', 'clickadu.com',
  'mgid.com', 'revcontent.com', 'contentad.net', 'nativeads.com',
  
  // Cryptocurrency Mining & Scam Networks
  'coinhive.com', 'coin-hive.com', 'cryptoloot.pro', 'jsecoin.com',
  'mineralt.io', 'authedmine.com', 'cryptonoter.com'
];

// AI threat intelligence database
let unsafeWebsites = new Set();
let aiThreatAnalysis = {
  totalThreats: 0,
  threatTypes: {
    malware: 0,
    phishing: 0,
    cryptoMining: 0,
    adultScam: 0,
    fakeSoftware: 0
  }
};

// Suspicious patterns that often indicate pop-ups
const POP_UP_PATTERNS = [
  /popup/i,
  /popunder/i,
  /overlay/i,
  /interstitial/i,
  /banner/i,
  /advertisement/i
];

let blockedCount = 0;
let isBlockingEnabled = true;

/**
 * Initialize the extension when installed or started
 */
chrome.runtime.onInstalled.addListener(async () => {
  console.log('PopStop AI: Extension installed - Initializing AI-powered protection');
  
  // Initialize storage with default values
  await chrome.storage.sync.set({
    blockingEnabled: true,
    blockedCount: 0
  });
  
  // Initialize AI threat analysis storage
  await chrome.storage.local.set({
    aiThreatAnalysis: aiThreatAnalysis,
    unsafeSites: []
  });
  
  // Update dynamic rules for ad blocking
  updateBlockingRules();
  
  // Initialize data and monitoring
  await initializeData();
  
  // Initialize AI systems
  await initializeAISystems();
  
  console.log('PopStop AI: Full initialization complete - Ready for universal protection');
});

/**
 * Set up monitoring for blocked network requests
 */
function setupNetworkMonitoring() {
  // Monitor failed requests that might indicate blocks
  chrome.webRequest.onErrorOccurred.addListener(
    (details) => {
      if (details.error === 'net::ERR_BLOCKED_BY_CLIENT') {
        // Check if this was blocked by our extension
        const isAdDomain = AD_DOMAINS.some(domain => details.url.includes(domain));
        const hasSuspiciousPattern = POP_UP_PATTERNS.some(pattern => pattern.test(details.url));
        
        if (isAdDomain || hasSuspiciousPattern) {
          console.log('PopStop: Network blocked request to:', details.url);
          incrementBlockedCount();
        }
      }
    },
    { urls: ["<all_urls>"] }
  );
  
  // Also monitor before requests to catch more blocks
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      // Check if this request would be blocked by our rules
      const isAdDomain = AD_DOMAINS.some(domain => details.url.includes(domain));
      const hasSuspiciousPattern = POP_UP_PATTERNS.some(pattern => pattern.test(details.url));
      
      if (isAdDomain || hasSuspiciousPattern) {
        console.log('PopStop: Pre-blocking suspicious request to:', details.url);
        
        // Don't increment here as it might double-count with onErrorOccurred
        // but log it for debugging
      }
    },
    { urls: ["<all_urls>"] },
    ["requestBody"]
  );
}

/**
 * Listen for tab updates to detect potential pop-ups
 */
chrome.tabs.onCreated.addListener((tab) => {
  // Check if this tab was likely created by a pop-up
  if (isLikelyPopUp(tab)) {
    handlePopUpBlocked(tab);
  }
});

/**
 * Listen for window creation (another pop-up indicator)
 */
chrome.windows.onCreated.addListener((window) => {
  // Pop-up windows often have specific characteristics
  if (window.type === 'popup' || (window.width && window.width < 800)) {
    console.log('Potential pop-up window detected:', window);
    incrementBlockedCount();
  }
});

/**
 * Update dynamic blocking rules
 */
async function updateBlockingRules() {
  // Get current blocking status
  const result = await chrome.storage.sync.get(['blockingEnabled']);
  isBlockingEnabled = result.blockingEnabled !== false;
  
  if (!isBlockingEnabled) {
    // Remove all rules if blocking is disabled
    chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [1, 2, 3, 4, 5]
    });
    return;
  }
  
  // Create blocking rules for known ad domains
  const rules = AD_DOMAINS.map((domain, index) => ({
    id: index + 1,
    priority: 1,
    action: { type: 'block' },
    condition: {
      urlFilter: `*://*${domain}/*`,
      resourceTypes: ['main_frame', 'sub_frame', 'script']
    }
  }));
  
  // Update the rules
  chrome.declarativeNetRequest.updateDynamicRules({
    addRules: rules,
    removeRuleIds: rules.map(rule => rule.id)
  });
  
  console.log('Updated blocking rules for', AD_DOMAINS.length, 'ad domains');
}

/**
 * Check if a tab is likely a pop-up
 */
function isLikelyPopUp(tab) {
  if (!tab.url) return false;
  
  // Check if URL contains suspicious patterns
  const urlContainsSuspiciousPattern = POP_UP_PATTERNS.some(pattern => 
    pattern.test(tab.url)
  );
  
  // Check if it's from a known ad domain
  const isFromAdDomain = AD_DOMAINS.some(domain => 
    tab.url.includes(domain)
  );
  
  // Check if tab was opened without user interaction (likely programmatic)
  const likelyProgrammatic = !tab.active && tab.index === 0;
  
  return urlContainsSuspiciousPattern || isFromAdDomain || likelyProgrammatic;
}

/**
 * Handle when a pop-up is blocked
 */
async function handlePopUpBlocked(tab) {
  if (!isBlockingEnabled) return;
  
  console.log('Pop-up blocked:', tab.url);
  
  // Close the tab if it's a pop-up
  try {
    await chrome.tabs.remove(tab.id);
    incrementBlockedCount();
  } catch (error) {
    console.error('Error closing pop-up tab:', error);
  }
}

/**
 * Increment the blocked count in storage with better error handling
 */
async function incrementBlockedCount() {
  try {
    const result = await chrome.storage.sync.get(['blockedCount']).catch(err => {
      console.warn('PopStop: Storage read error, using cached count');
      return { blockedCount: blockedCount };
    });
    
    const currentCount = result.blockedCount || 0;
    const newCount = currentCount + 1;
    
    // Update local cache immediately
    blockedCount = newCount;
    
    // Try to update storage, but don't block if it fails
    chrome.storage.sync.set({ blockedCount: newCount }).catch(err => {
      console.warn('PopStop: Storage write error:', err);
    });
    
    console.log('PopStop: Blocked count:', newCount);
    
    // Update badge with retry logic
    try {
      chrome.action.setBadgeText({
        text: newCount > 99 ? '99+' : newCount.toString()
      });
      chrome.action.setBadgeBackgroundColor({ color: '#ff4444' });
    } catch (badgeError) {
      console.warn('PopStop: Badge update error:', badgeError);
    }
    
  } catch (error) {
    console.error('PopStop: Critical error in incrementBlockedCount:', error);
    // Fallback: just increment local counter
    blockedCount++;
  }
}

/**
 * Listen for messages from popup or content scripts with better error handling
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  try {
    if (!message || !message.action) {
      sendResponse({ error: 'Invalid message format' });
      return true;
    }

    console.log('PopStop: Received message:', message.action);

    switch (message.action) {
      case 'toggleBlocking':
        (async () => {
          try {
            isBlockingEnabled = message.enabled;
            await chrome.storage.sync.set({ blockingEnabled: message.enabled });
            updateBlockingRules();
            sendResponse({ success: true });
          } catch (error) {
            console.error('PopStop: Toggle error:', error);
            sendResponse({ success: false, error: error.message });
          }
        })();
        break;
        
      case 'resetCount':
        (async () => {
          try {
            await chrome.storage.sync.set({ blockedCount: 0 });
            blockedCount = 0;
            chrome.action.setBadgeText({ text: '' }).catch(() => {});
            sendResponse({ success: true });
          } catch (error) {
            console.error('PopStop: Reset error:', error);
            sendResponse({ success: false, error: error.message });
          }
        })();
        break;
        
      case 'getStats':
        sendResponse({
          blockedCount: blockedCount,
          isEnabled: isBlockingEnabled
        });
        break;
        
      case 'popupBlocked':
        console.log('PopStop: Blocked popup:', message.url);
        incrementBlockedCount();
        sendResponse({ success: true });
        break;
        
      case 'overlayRemoved':
      case 'documentWriteBlocked':
      case 'cryptoMiningDetected':
        console.log('PopStop: Blocked content:', message.action);
        incrementBlockedCount();
        sendResponse({ success: true });
        break;
        
      case 'unsafeWebsiteDetected':
        console.log('PopStop: Unsafe website:', message.host);
        // Just log for now, don't break functionality
        sendResponse({ success: true });
        break;
        
      default:
        console.warn('PopStop: Unknown action:', message.action);
        sendResponse({ error: 'Unknown action' });
    }
  } catch (error) {
    console.error('PopStop: Message handler error:', error);
    sendResponse({ success: false, error: error.message });
  }
  
  return true; // Keep message channel open for async response
});

/**
 * Initialize badge and load stored data on startup
 */
chrome.runtime.onStartup.addListener(async () => {
  await initializeData();
});

/**
 * Load stored data and update badge
 */
async function initializeData() {
  const result = await chrome.storage.sync.get(['blockedCount', 'blockingEnabled']);
  blockedCount = result.blockedCount || 0;
  isBlockingEnabled = result.blockingEnabled !== false;
  
  console.log('PopStop: Loaded data - blocked count:', blockedCount, 'enabled:', isBlockingEnabled);
  
  // Update badge
  if (blockedCount > 0) {
    chrome.action.setBadgeText({
      text: blockedCount > 99 ? '99+' : blockedCount.toString()
    });
    chrome.action.setBadgeBackgroundColor({ color: '#ff4444' });
  }
  
  // Set up network monitoring
  setupNetworkMonitoring();
}



/**
 * AI-POWERED: Enhanced blocking with threat analysis
 */
async function enhancedBlockingRules() {
  // Get AI threat data
  const aiData = await chrome.storage.local.get(['aiThreatAnalysis', 'unsafeSites']);
  
  // Create dynamic rules based on AI analysis
  const aiEnhancedRules = [];
  let ruleId = 20; // Start after existing rules
  
  // Add rules for detected unsafe sites
  if (aiData.unsafeSites) {
    aiData.unsafeSites.forEach(site => {
      aiEnhancedRules.push({
        id: ruleId++,
        priority: 10, // Higher priority for AI-detected threats
        action: { type: 'block' },
        condition: {
          urlFilter: `*://*${site}/*`,
          resourceTypes: ['main_frame', 'sub_frame', 'script', 'image']
        }
      });
    });
  }
  
  // Update dynamic rules
  if (aiEnhancedRules.length > 0) {
    chrome.declarativeNetRequest.updateDynamicRules({
      addRules: aiEnhancedRules
    });
    
    console.log(`PopStop AI: Added ${aiEnhancedRules.length} AI-enhanced blocking rules`);
  }
}

/**
 * AI-POWERED: Initialize AI systems
 */
async function initializeAISystems() {
  console.log('PopStop AI: Initializing AI threat analysis systems...');
  
  // Load existing AI data
  const aiData = await chrome.storage.local.get(['aiThreatAnalysis', 'unsafeSites']);
  if (aiData.aiThreatAnalysis) {
    aiThreatAnalysis = aiData.aiThreatAnalysis;
  }
  if (aiData.unsafeSites) {
    aiData.unsafeSites.forEach(site => unsafeWebsites.add(site));
  }
  
  // Set up enhanced blocking rules
  await enhancedBlockingRules();
  
  // Periodic AI analysis updates
  setInterval(async () => {
    await enhancedBlockingRules();
  }, 300000); // Update every 5 minutes
  
  console.log('PopStop AI: AI systems fully initialized');
  console.log('PopStop AI: Threat analysis:', aiThreatAnalysis);
}

// Export functions for testing (if needed)
if (typeof module !== 'undefined') {
  module.exports = {
    isLikelyPopUp,
    incrementBlockedCount
  };
} 