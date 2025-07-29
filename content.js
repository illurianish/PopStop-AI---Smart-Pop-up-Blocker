/**
 * PopStop Content Script
 * Runs on all pages to prevent pop-ups at the webpage level
 * Overrides window.open and other pop-up creation methods
 */

(function() {
  'use strict';
  
  // Prevent multiple script injections
  if (window.popStopLoaded) {
    console.log('PopStop: Script already loaded, skipping');
    return;
  }
  window.popStopLoaded = true;
  
  // Store the original window.open function
  const originalWindowOpen = window.open;
  let isBlockingEnabled = true;
  let blockedAttempts = 0;
  
  // Error handling wrapper
  function safeExecute(fn, context = 'unknown') {
    try {
      return fn();
    } catch (error) {
      console.error(`PopStop AI: Error in ${context}:`, error);
      return null;
    }
  }
  
  // AI-Enhanced Threat Detection Patterns
  const SUSPICIOUS_PATTERNS = [
    // Basic Pop-up Patterns
    /popup/i, /popunder/i, /advertisement/i, /promo/i, /offer/i,
    
    // Adult Site Patterns
    /casino/i, /dating/i, /cam.*show/i, /live.*cam/i, /adult.*chat/i,
    /xxx.*free/i, /porn.*free/i, /sex.*dating/i, /hookup.*tonight/i,
    
    // Scam/Malware Patterns (AI-Detected)
    /win.*prize/i, /congratulations/i, /you.*winner/i, /claim.*reward/i,
    /virus.*detected/i, /system.*infected/i, /security.*alert/i,
    /update.*required/i, /flash.*player/i, /java.*update/i,
    /your.*computer.*at.*risk/i, /click.*here.*to.*fix/i,
    
    // Phishing Patterns
    /verify.*account/i, /suspended.*account/i, /unusual.*activity/i,
    /confirm.*identity/i, /update.*payment/i, /expired.*card/i,
    
    // Fake Download/Software Patterns
    /download.*now/i, /install.*free/i, /speed.*up.*pc/i,
    /clean.*registry/i, /remove.*virus/i, /boost.*performance/i,
    
    // Cryptocurrency Scam Patterns
    /free.*bitcoin/i, /crypto.*mining/i, /invest.*cryptocurrency/i,
    /double.*bitcoin/i, /guaranteed.*profit/i,
    
    // General Suspicious Patterns
    /limited.*time/i, /act.*now/i, /urgent/i, /expires.*today/i,
    /streaming.*ads/i, /free.*movie/i, /survey/i, /redirect/i,
    /landing/i, /affiliate/i, /tracker/i, /referral/i
  ];
  
  // Comprehensive Ad Network Database - Universal Coverage
  const AD_DOMAINS = [
    // General Ad Networks
    'googleads.g.doubleclick.net', 'googlesyndication.com', 'amazon-adsystem.com',
    'facebook.com/tr', 'outbrain.com', 'taboola.com', 'adsystem.amazon.com',
    'ads.yahoo.com', 'bing.com/ads', 'adnxs.com', 'bidswitch.net',
    'casalemedia.com', 'contextweb.com', 'doubleclick.net', 'rubiconproject.com',
    'scorecardresearch.com', 'turn.com', 'adsystem.amazon.co.uk',
    
    // Adult Site Ad Networks (Essential for sites like Pornhub, etc.)
    'exoclick.com', 'juicyads.com', 'trafficjunky.net', 'plugrush.com',
    'exosrv.com', 'tsyndicate.com', 'streamate.com', 'cams.com',
    'chaturbate.com/affiliates', 'livejasmin.com/landing', 'stripchat.com/promo',
    'bongacams.com/promo', 'cam4.com/ads', 'flirt4free.com/go',
    'adsterra.com', 'hilltopads.net', 'propellerads.com', 'popcash.net',
    'popads.net', 'popunder.net', 'adcash.com', 'clickadu.com',
    'mgid.com', 'revcontent.com', 'contentad.net', 'nativeads.com',
    
    // Malicious/Unsafe Ad Networks
    'malware-traffic.com', 'phishing-ads.net', 'fake-download.com',
    'virus-ads.com', 'scam-popups.net', 'dating-scam.com',
    'fake-virus-alert.com', 'browser-hijack.net', 'crypto-mining.ads',
    
    // Cryptocurrency Mining & Scam Networks
    'coinhive.com', 'coin-hive.com', 'cryptoloot.pro', 'jsecoin.com',
    'mineralt.io', 'authedmine.com', 'cryptonoter.com',
    
    // Fake Software/Download Networks
    'softonic.com/go', 'download.com/redir', 'cnet-fake.com',
    'fake-adobe.com', 'fake-chrome.net', 'malware-download.org',
    
    // Dating Scam Networks
    'meet-singles.fake', 'adult-dating.scam', 'hookup-tonight.fake',
    'local-singles.scam', 'adult-finder.fake'
  ];
  
  /**
   * SIMPLIFIED: Basic threat detection (less prone to errors)
   */
  function analyzeThreatLevel(url, content = '') {
    return safeExecute(() => {
      if (!url) return { isThreat: false, score: 0, reason: 'no-url' };
      
      let threatScore = 0;
      let reasons = [];
      
      // Check against known ad domains
      const isMaliciousDomain = AD_DOMAINS.some(domain => {
        try {
          return url.includes(domain);
        } catch (e) {
          return false;
        }
      });
      
      if (isMaliciousDomain) {
        threatScore += 50;
        reasons.push('ad-domain');
      }
      
      // Check suspicious patterns (simplified)
      try {
        for (const pattern of SUSPICIOUS_PATTERNS) {
          if (pattern.test(url) || (content && pattern.test(content))) {
            threatScore += 10;
            reasons.push('pattern-match');
            break; // Only count one pattern match to avoid excessive scoring
          }
        }
      } catch (e) {
        console.warn('PopStop: Pattern matching error:', e);
      }
      
      // Simple high-risk checks
      const highRiskWords = ['virus', 'malware', 'phishing', 'cryptocurrency', 'bitcoin', 'dating', 'casino'];
      if (highRiskWords.some(word => url.toLowerCase().includes(word))) {
        threatScore += 30;
        reasons.push('high-risk-word');
      }
      
      return {
        isThreat: threatScore > 20,
        score: threatScore,
        reasons: reasons,
        riskLevel: threatScore > 50 ? 'HIGH' : threatScore > 20 ? 'MEDIUM' : 'LOW'
      };
    }, 'analyzeThreatLevel') || { isThreat: false, score: 0, reasons: [] };
  }
  
  /**
   * AI-POWERED: Check if a URL is likely an ad or threat
   */
  function isLikelySuspiciousUrl(url, content = '') {
    if (!url) return false;
    
    // Whitelist legitimate domains (AI-curated)
    const legitimateDomains = [
      'google.com', 'youtube.com', 'github.com', 'stackoverflow.com',
      'wikipedia.org', 'mozilla.org', 'apple.com', 'microsoft.com',
      'netflix.com', 'amazon.com', 'paypal.com', 'ebay.com',
      'reddit.com', 'twitter.com', 'facebook.com', 'instagram.com',
      'linkedin.com', 'dropbox.com', 'spotify.com', 'steam.com'
    ];
    
    // Don't block whitelisted or local content
    if (url.startsWith('file://') || url.startsWith('chrome://') || 
        url.includes('localhost') || url.includes('127.0.0.1') ||
        legitimateDomains.some(domain => url.includes(domain))) {
      return false;
    }
    
    // Use AI threat analysis
    const threatAnalysis = analyzeThreatLevel(url, content);
    
    if (threatAnalysis.isThreat) {
      console.log(`PopStop AI: Threat detected - Score: ${threatAnalysis.score}, Risk: ${threatAnalysis.riskLevel}, Reasons:`, threatAnalysis.reasons);
    }
    
    return threatAnalysis.isThreat;
  }
  
  /**
   * AI-POWERED: Detect unsafe website characteristics
   */
  function isUnsafeWebsite() {
    const currentUrl = window.location.href;
    const currentHost = window.location.hostname.toLowerCase();
    
    // Check for common unsafe website indicators
    const unsafeIndicators = [
      // Suspicious hosting patterns
      /\d+\.\d+\.\d+\.\d+/,  // IP addresses instead of domains
      /[a-z]{20,}\.com/,     // Very long random domain names
      /[0-9]{5,}[a-z]+\./,   // Numbers followed by letters
      
      // Malicious site patterns
      /free.*download.*crack/i,
      /torrent.*download/i,
      /watch.*movies.*online.*free/i,
      /adult.*videos.*free/i,
      /casino.*bonus.*free/i
    ];
    
    const isUnsafe = unsafeIndicators.some(pattern => 
      pattern.test(currentUrl) || pattern.test(currentHost)
    );
    
    if (isUnsafe) {
      console.log('PopStop AI: Unsafe website detected:', currentHost);
      // Notify background script about unsafe site
      chrome.runtime.sendMessage({
        action: 'unsafeWebsiteDetected',
        url: currentUrl,
        host: currentHost
      }).catch(() => {});
    }
    
    return isUnsafe;
  }
  
  /**
   * AI-POWERED: Advanced pop-up detection with site-specific optimization
   */
  function isLikelyPopUpAd(url, target, features) {
    const currentHost = window.location.hostname.toLowerCase();
    
    // AI-powered threat analysis
    const threatAnalysis = analyzeThreatLevel(url);
    if (threatAnalysis.isThreat) {
      console.log(`PopStop AI: Threat-based blocking - ${threatAnalysis.riskLevel} risk`);
      return true;
    }
    
    // Site-specific aggressive blocking rules
    const siteSpecificRules = {
      // Adult sites (Pornhub, Xvideos, etc.) - ULTRA AGGRESSIVE
      adult: {
        patterns: [/porn/i, /xxx/i, /sex/i, /adult/i, /cam/i, /tube/i, /xvideos/i, /pornhub/i],
        blockAll: true,  // Block ALL new windows
        whitelist: ['google.com', 'youtube.com', 'twitter.com', 'instagram.com']
      },
      
      // Streaming sites (fmovies, putlocker, etc.) - VERY AGGRESSIVE
      streaming: {
        patterns: [/movie/i, /stream/i, /watch/i, /fmovies/i, /putlocker/i, /123movies/i],
        blockAll: true,
        whitelist: ['google.com', 'youtube.com', 'imdb.com', 'netflix.com']
      },
      
      // Gaming/Torrent sites - AGGRESSIVE
      gaming: {
        patterns: [/torrent/i, /pirate/i, /crack/i, /keygen/i, /hack/i, /cheat/i],
        blockAll: true,
        whitelist: ['steam.com', 'epic.com', 'origin.com']
      },
      
      // Social media - MODERATE (allow more)
      social: {
        patterns: [/facebook/i, /twitter/i, /instagram/i, /tiktok/i, /snapchat/i],
        blockAll: false,
        whitelist: ['facebook.com', 'twitter.com', 'instagram.com']
      }
    };
    
    // Determine site category and apply appropriate rules
    let currentCategory = null;
    let applicableRules = null;
    
    for (const [category, rules] of Object.entries(siteSpecificRules)) {
      if (rules.patterns.some(pattern => pattern.test(currentHost) || pattern.test(document.title))) {
        currentCategory = category;
        applicableRules = rules;
        break;
      }
    }
    
    // Apply site-specific blocking
    if (applicableRules) {
      console.log(`PopStop AI: Applying ${currentCategory} site rules`);
      
      if (applicableRules.blockAll && (target === '_blank' || !target)) {
        // Check if URL is in whitelist
        const isWhitelisted = applicableRules.whitelist.some(domain => 
          url && url.includes(domain)
        );
        
        if (!isWhitelisted) {
          console.log(`PopStop AI: SITE-SPECIFIC blocking on ${currentCategory} site`);
          return true;
        }
      }
    }
    
    // Universal AI-powered blocking logic
    if (target === '_blank' || !target) {
      // Advanced user interaction detection
      const stack = new Error().stack;
      const hasUserInteraction = stack && (
        stack.includes('onclick') || 
        stack.includes('mousedown') || 
        stack.includes('touchstart') ||
        stack.includes('keydown')
      );
      
      if (!hasUserInteraction) {
        console.log('PopStop AI: No user interaction detected - blocking');
        return true;
      }
      
      // Rapid-fire detection (AI-enhanced)
      const now = Date.now();
      if (window.lastPopupAttempt && (now - window.lastPopupAttempt) < 3000) {
        console.log('PopStop AI: Rapid-fire pop-up detected');
        return true;
      }
      window.lastPopupAttempt = now;
    }
    
    // Window feature analysis (AI-enhanced)
    if (features) {
      const suspiciousFeatures = [
        'toolbar=no', 'menubar=no', 'resizable=no', 'scrollbars=no',
        'width=1', 'height=1'  // Hidden windows
      ];
      
      const hasSuspiciousFeatures = suspiciousFeatures.some(feature => 
        features.includes(feature)
      );
      
      if (hasSuspiciousFeatures) {
        console.log('PopStop AI: Suspicious window features detected');
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * SMART AGGRESSIVE: Block pop-ups intelligently without breaking functionality
   */
  window.open = function(url, target, features, replace) {
    return safeExecute(() => {
      // If blocking is disabled, allow all
      if (!isBlockingEnabled) {
        return originalWindowOpen.call(this, url, target, features, replace);
      }
      
      const currentHost = window.location.hostname.toLowerCase();
      
      // Allow essential cases
      const allowedCases = [
        !url || url === '' || url === 'about:blank',
        url && url.startsWith('chrome://'),
        url && url.startsWith('chrome-extension://'),
        url && url.startsWith('data:'),
        url && url.startsWith('blob:'),
        // Allow major legitimate domains
        url && (url.includes('google.com') || url.includes('youtube.com') || 
                url.includes('github.com') || url.includes('stackoverflow.com') ||
                url.includes('mozilla.org') || url.includes('microsoft.com')) && 
                !url.includes('ads') && !url.includes('doubleclick')
      ];
      
      if (allowedCases.some(condition => condition)) {
        console.log('PopStop AI: Allowing whitelisted case:', url);
        return originalWindowOpen.call(this, url, target, features, replace);
      }
      
      // Check if we're on a problematic site
      const problematicSites = [
        /movie|stream|watch|free|film|tv|show/i,
        /porn|xxx|sex|adult|cam|tube/i,
        /torrent|pirate|download|crack|keygen/i,
        /casino|bet|poker|slots/i,
        /fmovies|putlocker|gomovies|123movies|pornhub|xvideos/i
      ];
      
      const isProblematicSite = problematicSites.some(pattern => {
        try {
          return pattern.test(currentHost) || pattern.test(document.title || '');
        } catch (e) {
          return false;
        }
      });
      
      // Smart blocking logic
      let shouldBlock = false;
      let blockReason = '';
      
      // 1. Always block on problematic sites unless whitelisted
      if (isProblematicSite && (target === '_blank' || !target)) {
        shouldBlock = true;
        blockReason = 'problematic-site-new-window';
      }
      
      // 2. Block suspicious URLs
      else if (url && isLikelySuspiciousUrl(url)) {
        shouldBlock = true;
        blockReason = 'suspicious-url';
      }
      
      // 3. Block suspicious features
      else if (features && (features.includes('popup') || 
                           (features.includes('width=') && features.includes('height=') && 
                            !features.includes('width=100%')))) {
        shouldBlock = true;
        blockReason = 'suspicious-features';
      }
      
      // 4. Rapid-fire protection
      const now = Date.now();
      if (window.lastPopupAttempt && (now - window.lastPopupAttempt) < 3000) {
        shouldBlock = true;
        blockReason = 'rapid-fire';
      }
      window.lastPopupAttempt = now;
      
      if (shouldBlock) {
        blockedAttempts++;
        console.log(`PopStop AI: BLOCKED - ${blockReason}:`, url || 'unknown');
        notifyBackgroundBlocked(url, blockReason);
        return createDummyWindow();
      }
      
      // Allow if all checks pass
      console.log('PopStop AI: Allowing:', url);
      return originalWindowOpen.call(this, url, target, features, replace);
      
    }, 'window.open override') || createDummyWindow();
  };
  
  /**
   * Helper function to notify background script about blocks
   */
  function notifyBackgroundBlocked(url, source) {
    chrome.runtime.sendMessage({
      action: 'popupBlocked',
      url: url || 'unknown',
      source: source
    }).catch(err => {
      console.log('PopStop AI: Could not communicate with background script');
    });
  }
  
  /**
   * Create a dummy window object to prevent errors
   */
  function createDummyWindow() {
    return {
      closed: true,
      close: function() {},
      focus: function() {},
      blur: function() {},
      postMessage: function() {},
      location: { href: 'about:blank' },
      document: { write: function() {}, writeln: function() {} }
    };
  }
  
  /**
   * Override other methods that can create pop-ups
   */
  
  // Override window.showModalDialog (deprecated but still used)
  if (window.showModalDialog) {
    const originalShowModalDialog = window.showModalDialog;
    window.showModalDialog = function(url, argument, features) {
      if (!isBlockingEnabled) {
        return originalShowModalDialog.call(this, url, argument, features);
      }
      
      if (isLikelySuspiciousUrl(url)) {
        console.log('PopStop: Blocked modal dialog to:', url);
        return null;
      }
      
      return originalShowModalDialog.call(this, url, argument, features);
    };
  }
  
  /**
   * Prevent focus stealing (common pop-up behavior)
   */
  try {
    const originalFocus = window.focus;
    window.focus = function() {
      if (!isBlockingEnabled) {
        return originalFocus.call(this);
      }
      
      // Only allow focus if it's from user interaction
      const stack = new Error().stack;
      if (stack && (stack.includes('onclick') || stack.includes('onmousedown') || stack.includes('onkeydown'))) {
        return originalFocus.call(this);
      }
      
      // Block automatic focus attempts
      console.log('PopStop: Blocked automatic focus attempt');
      return false;
    };
  } catch (error) {
    console.log('PopStop: Could not override window.focus');
  }
  
  /**
   * Note: We skip location.replace override due to browser security restrictions
   * Network-level blocking handles redirects effectively
   */
  
  /**
   * Listen for messages from background script
   */
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'updateBlockingStatus') {
      isBlockingEnabled = message.enabled;
      sendResponse({ success: true });
    } else if (message.action === 'getBlockedAttempts') {
      sendResponse({ blockedAttempts: blockedAttempts });
    }
    
    return true;
  });
  
  /**
   * Get initial blocking status from storage
   */
  chrome.storage.sync.get(['blockingEnabled']).then(result => {
    isBlockingEnabled = result.blockingEnabled !== false;
  }).catch(err => {
    console.log('PopStop: Could not load blocking status from storage');
  });
  
  /**
   * SMART EVENT BLOCKING: Target suspicious events without breaking functionality
   */
  const originalAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, listener, options) {
    return safeExecute(() => {
      if (!isBlockingEnabled) {
        return originalAddEventListener.call(this, type, listener, options);
      }
      
      const currentHost = window.location.hostname.toLowerCase();
      
      // Only block on clearly problematic sites
      const problematicSites = [
        /fmovies|putlocker|gomovies|123movies|pornhub|xvideos/i,
        /popads|popcash|adcash|exoclick/i
      ];
      
      const isProblematicSite = problematicSites.some(pattern => {
        try {
          return pattern.test(currentHost);
        } catch (e) {
          return false;
        }
      });
      
      // Only block specific dangerous events on problematic sites
      if (isProblematicSite && ['beforeunload', 'unload', 'pagehide'].includes(type)) {
        const listenerString = listener ? listener.toString() : '';
        
        // Only block if the listener contains suspicious code
        const hasSuspiciousCode = listenerString.includes('window.open') ||
                                 listenerString.includes('popup') ||
                                 listenerString.includes('alert(') ||
                                 listenerString.includes('redirect');
        
        if (hasSuspiciousCode) {
          console.log('PopStop AI: Blocked suspicious', type, 'event listener');
          notifyBackgroundBlocked(`${type}-blocked`, 'event_blocking');
          return; // Block this event listener
        }
      }
      
      // Allow all other event listeners
      return originalAddEventListener.call(this, type, listener, options);
    }, 'addEventListener override') || undefined;
  };
  
  /**
   * Monitor for dynamically created iframes that might be ads
   */
  const originalCreateElement = document.createElement;
  document.createElement = function(tagName) {
    const element = originalCreateElement.call(this, tagName);
    
    if (isBlockingEnabled && tagName.toLowerCase() === 'iframe') {
      // Override iframe src setter to check for ad URLs
      const originalSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
      
      Object.defineProperty(element, 'src', {
        get: function() {
          return originalSrcDescriptor.get.call(this);
        },
        set: function(value) {
          if (isLikelySuspiciousUrl(value)) {
            console.log('PopStop: Blocked suspicious iframe:', value);
            return; // Don't set the src
          }
          return originalSrcDescriptor.set.call(this, value);
        }
      });
    }
    
    return element;
  };
  
  /**
   * AGGRESSIVE: Block document.write injection attacks
   */
  const originalDocumentWrite = document.write;
  const originalDocumentWriteln = document.writeln;
  
  document.write = function(content) {
    if (!isBlockingEnabled) {
      return originalDocumentWrite.call(this, content);
    }
    
    // Block suspicious document.write content
    if (typeof content === 'string' && 
        (SUSPICIOUS_PATTERNS.some(pattern => pattern.test(content)) ||
         AD_DOMAINS.some(domain => content.includes(domain)))) {
      console.log('PopStop: Blocked suspicious document.write:', content.substring(0, 100));
      
      // Notify background script
      chrome.runtime.sendMessage({
        action: 'documentWriteBlocked',
        content: content.substring(0, 200)
      }).catch(() => {});
      
      return;
    }
    
    return originalDocumentWrite.call(this, content);
  };
  
  document.writeln = function(content) {
    if (!isBlockingEnabled) {
      return originalDocumentWriteln.call(this, content);
    }
    
    if (typeof content === 'string' && 
        (SUSPICIOUS_PATTERNS.some(pattern => pattern.test(content)) ||
         AD_DOMAINS.some(domain => content.includes(domain)))) {
      console.log('PopStop: Blocked suspicious document.writeln');
      
      // Notify background script
      chrome.runtime.sendMessage({
        action: 'documentWriteBlocked',
        content: content.substring(0, 200)
      }).catch(() => {});
      
      return;
    }
    
    return originalDocumentWriteln.call(this, content);
  };
  
  /**
   * AGGRESSIVE: Remove overlay pop-up elements
   */
  function removeOverlays() {
    if (!isBlockingEnabled) return;
    
    // Common overlay selectors used by ad networks
    const overlaySelectors = [
      '[id*="popup"]', '[class*="popup"]',
      '[id*="overlay"]', '[class*="overlay"]', 
      '[id*="modal"]', '[class*="modal"]',
      '[id*="advertisement"]', '[class*="advertisement"]',
      '[id*="ads"]', '[class*="ads"]',
      '[style*="position: fixed"]', '[style*="position:fixed"]',
      '[style*="z-index: 999"]', '[style*="z-index:999"]',
      'div[style*="width: 100%"][style*="height: 100%"]'
    ];
    
    overlaySelectors.forEach(selector => {
      try {
        const elements = document.querySelectorAll(selector);
        elements.forEach(element => {
          const style = window.getComputedStyle(element);
          const rect = element.getBoundingClientRect();
          
          // Remove if it looks like a full-screen overlay or pop-up
          if ((style.position === 'fixed' || style.position === 'absolute') &&
              (style.zIndex > 100 || rect.width > window.innerWidth * 0.8 || rect.height > window.innerHeight * 0.8)) {
            console.log('PopStop: Removed overlay element:', element.className || element.id);
            element.remove();
            
            // Notify background script
            chrome.runtime.sendMessage({
              action: 'overlayRemoved',
              element: element.className || element.id || 'unknown'
            }).catch(() => {});
          }
        });
      } catch (e) {
        // Ignore errors for invalid selectors
      }
    });
  }
  
  /**
   * AGGRESSIVE: Block form submission pop-ups
   */
  const originalFormSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() {
    if (!isBlockingEnabled) {
      return originalFormSubmit.call(this);
    }
    
    const currentHost = window.location.hostname.toLowerCase();
    const isStreamingSite = /movie|stream|watch|free|film|tv|show|series|fmovies/i.test(currentHost);
    
    if (isStreamingSite && this.action && isLikelySuspiciousUrl(this.action)) {
      console.log('PopStop: AGGRESSIVE - Blocked suspicious form submission to:', this.action);
      return false;
    }
    
    return originalFormSubmit.call(this);
  };
  
  /**
   * AGGRESSIVE: Monitor for dynamically created suspicious elements
   */
  const observer = new MutationObserver(function(mutations) {
    if (!isBlockingEnabled) return;
    
    mutations.forEach(function(mutation) {
      mutation.addedNodes.forEach(function(node) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          // Check for suspicious new elements
          if (node.tagName === 'IFRAME' || node.tagName === 'SCRIPT') {
            const src = node.src || node.getAttribute('src');
            if (src && isLikelySuspiciousUrl(src)) {
              console.log('PopStop: Removed dynamically added suspicious element:', src);
              node.remove();
              
              // Notify background script
              chrome.runtime.sendMessage({
                action: 'popupBlocked',
                url: src,
                source: 'dynamic_element_removal'
              }).catch(() => {});
            }
          }
          
          // Check for overlay-like elements
          if (node.style) {
            const style = window.getComputedStyle(node);
            if (style.position === 'fixed' && style.zIndex > 999) {
              console.log('PopStop: Removed suspicious overlay element');
              node.remove();
              
              // Notify background script
              chrome.runtime.sendMessage({
                action: 'overlayRemoved',
                element: 'dynamic_overlay'
              }).catch(() => {});
            }
          }
        }
      });
    });
  });
  
  // Start observing
  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true
  });
  
  /**
   * SIMPLIFIED: Initialize protection system with error handling
   */
  function initializeProtection() {
    safeExecute(() => {
      console.log('PopStop AI: Initializing protection system...');
      
      // Get initial blocking status from storage
      chrome.storage.sync.get(['blockingEnabled']).then(result => {
        isBlockingEnabled = result.blockingEnabled !== false;
        console.log('PopStop AI: Blocking enabled:', isBlockingEnabled);
      }).catch(err => {
        console.log('PopStop AI: Could not load blocking status, using default (enabled)');
        isBlockingEnabled = true;
      });
      
      // Simple periodic monitoring (less frequent to avoid performance issues)
      setInterval(() => {
        if (isBlockingEnabled) {
          safeExecute(() => {
            removeOverlays();
          }, 'overlay removal');
        }
      }, 3000); // Less frequent monitoring
      
      // Simplified mutation observer
      const observer = new MutationObserver(function(mutations) {
        if (!isBlockingEnabled) return;
        
        safeExecute(() => {
          mutations.forEach(function(mutation) {
            mutation.addedNodes.forEach(function(node) {
              if (node.nodeType === Node.ELEMENT_NODE) {
                if (node.tagName === 'IFRAME' || node.tagName === 'SCRIPT') {
                  const src = node.src || node.getAttribute('src');
                  if (src && isLikelySuspiciousUrl(src)) {
                    console.log('PopStop AI: Removed suspicious element:', src);
                    node.remove();
                    notifyBackgroundBlocked(src, 'element_removal');
                  }
                }
              }
            });
          });
        }, 'mutation observer');
      });
      
      // Start observing when DOM is ready
      if (document.body) {
        observer.observe(document.body, { childList: true, subtree: true });
      } else {
        document.addEventListener('DOMContentLoaded', () => {
          observer.observe(document.body, { childList: true, subtree: true });
        });
      }
      
      console.log('PopStop AI: Protection system initialized');
    }, 'protection initialization');
  }
  

  

  
  /**
   * SIMPLIFIED: Basic additional protections without breaking functionality
   */
  function enableBasicProtection() {
    console.log('PopStop AI: Enabling basic additional protections');
    
    // Only override setTimeout/setInterval with very specific checks
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(func, delay) {
      return safeExecute(() => {
        if (typeof func === 'string' && func.includes('window.open')) {
          console.log('PopStop AI: Blocked setTimeout with window.open');
          notifyBackgroundBlocked('setTimeout-blocked', 'timer_blocking');
          return 0;
        }
        return originalSetTimeout.apply(this, arguments);
      }, 'setTimeout override') || 0;
    };
    
    // Simple alert blocking for obvious scams
    const originalAlert = window.alert;
    window.alert = function(message) {
      return safeExecute(() => {
        if (message && (message.includes('virus') || message.includes('infected') || 
                       message.includes('winner') || message.includes('congratulations'))) {
          console.log('PopStop AI: Blocked suspicious alert:', message);
          notifyBackgroundBlocked('alert-blocked', 'alert_blocking');
          return undefined;
        }
        return originalAlert.apply(this, arguments);
      }, 'alert override');
    };
  }
  
  // Enable basic protection
  enableBasicProtection();
  
  // Initialize protection system
  initializeProtection();
  
  console.log('PopStop AI: SMART PROTECTION LOADED - Advanced pop-up prevention active');
  
})(); 