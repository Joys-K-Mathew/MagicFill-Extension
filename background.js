/**
 * Magic Fill - Background Service Worker
 * Centralizes security state, auto-lock timers, and idle detection.
 */

try {
    importScripts('browser-polyfill.js');
} catch (e) {
    // browser-polyfill.js might not be available or needed in this context
}

// Note: In MV3, the service worker is ephemeral.
// We use chrome.storage.session for states that should survive worker sleep
// but clear when the browser is closed.

// 1. Initialize Alarms, Idle Listeners, and Context Menus
chrome.runtime.onInstalled.addListener(() => {
    console.log('Magic Fill security layer initialized.');
    setupAlarms();
    createContextMenus();
    updateBadge(true);
    // Ensure session state is cleared on fresh install
    if (chrome.storage.session) chrome.storage.session.remove('isSessionUnlocked');
    cleanupHistory();
});

chrome.runtime.onStartup.addListener(async () => {
    setupAlarms();
    // Validate lock state immediately on startup
    const state = await checkLockState();
    updateBadge(state.isLocked);
    cleanupHistory();
});

function cleanupHistory() {
    chrome.storage.local.get(['appHistory', 'appHistoryRetention'], (res) => {
        const retention = res.appHistoryRetention;
        if (!retention || retention === 0) return; // 0 = keep forever
        const cutoff = Date.now() - (retention * 86400000);
        const history = res.appHistory || [];
        const cleaned = history.filter(h => new Date(h.date).getTime() >= cutoff);
        if (cleaned.length !== history.length) {
            chrome.storage.local.set({ appHistory: cleaned });
        }
    });
}

function setupAlarms() {
    chrome.alarms.create('checkLockAlarm', { periodInMinutes: 1 });
}

function createContextMenus() {
    chrome.storage.local.get(['isWidgetHidden'], (res) => {
        const isHidden = res.isWidgetHidden || false;
        chrome.contextMenus.removeAll(() => {
            chrome.contextMenus.create({
                id: 'toggle-widget-menu',
                title: isHidden ? 'Unhide Floating Button' : 'Hide Floating Button',
                contexts: ['all']
            });
        });
    });
}

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId === 'toggle-widget-menu') {
        chrome.storage.local.get(['isWidgetHidden'], (res) => {
            const isHidden = !res.isWidgetHidden;
            chrome.storage.local.set({ isWidgetHidden: isHidden }, () => {
                chrome.contextMenus.update('toggle-widget-menu', {
                    title: isHidden ? 'Unhide Floating Button' : 'Hide Floating Button'
                });
                chrome.tabs.query({}, (tabs) => {
                    for (const tab of tabs) {
                        chrome.tabs.sendMessage(tab.id, { action: 'toggleWidgetVisibility', isHidden }).catch(() => {});
                    }
                });
            });
        });
    }
});

// Handle keyboard shortcuts
chrome.commands.onCommand.addListener((command) => {
    if (command === 'lock-vault') {
        performLock();
    }
});

// Security state management (Visual updates removed for stability)
function updateBadge(isLocked) {
    // Logic removed to ensure extension stability and maintain original brand icon.
    // The vault still locks/unlocks securely in the background.
}

// 2. Idle Detection: Lock when system is locked or idle
chrome.idle.setDetectionInterval(60); 
chrome.idle.onStateChanged.addListener((state) => {
    if (state === 'locked' || state === 'idle') {
        performLock();
    }
});

// 3. Alarm listener
chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'checkLockAlarm') {
        const state = await checkLockState();
        if (state.isLocked) {
            await performLock();
        }
    }
});

// 4. Centralized Locking Logic
async function performLock() {
    if (chrome.storage.session) await chrome.storage.session.remove('isSessionUnlocked');
    await chrome.storage.local.set({ lastUnlocked: 0 });
    updateBadge(true);
    
    // Notify all tabs
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
        // In MV3 sendMessage returns a promise; must catch to avoid "Receiving end does not exist" errors
        chrome.tabs.sendMessage(tab.id, { action: 'vaultLocked' }).catch(() => {
            // Silently ignore: tab might be a restricted page, or content script not yet loaded/orphaned
        });
    }
}

// 5. Listener for messages from popup or content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkLockState') {
        checkLockState().then(sendResponse);
        return true; // Keep channel open for async response
    }
    
    if (request.action === 'unlockSession') {
        if (chrome.storage.session) {
            chrome.storage.session.set({ isSessionUnlocked: true }).then(() => {
                chrome.storage.local.set({ lastUnlocked: Date.now() }, () => {
                    updateBadge(false);
                    sendResponse({ success: true });
                });
            });
        } else {
            // Fallback for older browsers
            chrome.storage.local.set({ lastUnlocked: Date.now() }, () => {
                updateBadge(false);
                sendResponse({ success: true });
            });
        }
        return true;
    }

    if (request.action === 'lockSession') {
        performLock().then(() => sendResponse({ success: true }));
        return true;
    }
});

async function checkLockState() {
    return Promise.race([
        new Promise((resolve) => {
            chrome.storage.sync.get(['pin', 'lockTimeout'], (syncRes) => {
                if (chrome.runtime.lastError) {
                    resolve({ isLocked: true, error: 'Storage access failed' });
                    return;
                }

                if (!syncRes.pin) {
                    resolve({ isLocked: false, noPin: true });
                    return;
                }

                chrome.storage.local.get(['lastUnlocked', 'lockoutUntil'], (localRes) => {
                    const now = Date.now();
                    
                    // Brute-force lockout check
                    if (localRes.lockoutUntil && now < localRes.lockoutUntil) {
                        resolve({ isLocked: true, lockedUntil: localRes.lockoutUntil });
                        return;
                    }

                    const to = parseInt(syncRes.lockTimeout || '5', 10);
                    const last = localRes.lastUnlocked || 0;
                    
                    let isLocked = false;
                    
                    // Get session state from storage
                    const checkSession = () => {
                       return new Promise((res) => {
                           if (chrome.storage.session) {
                               chrome.storage.session.get(['isSessionUnlocked'], (sRes) => res(!!sRes.isSessionUnlocked));
                           } else {
                               res(false);
                           }
                       });
                    };

                    checkSession().then(async (unlocked) => {
                        if (to === 0) {
                            // Immediate Lock: 30s grace period
                            if (now - last > 30000) isLocked = true;
                        } else if (to === -1) {
                            // Browser Session: survives SW suspension but clears on browser close
                            if (!unlocked) isLocked = true;
                        } else {
                            // Timeout Lock
                            if (now - last > (to * 60000)) isLocked = true;
                        }

                        // If it's supposed to be locked, clear the session flag
                        if (isLocked && unlocked && chrome.storage.session) {
                            await chrome.storage.session.remove('isSessionUnlocked');
                        }

                        resolve({ isLocked, timeout: to });
                    });
                });
            });
        }),
        new Promise((resolve) =>
            setTimeout(() => resolve({ isLocked: true, error: 'timeout' }), 5000)
        )
    ]);
}
