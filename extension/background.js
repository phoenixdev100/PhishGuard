let retryCount = 0;
const MAX_RETRIES = 3;
const API_BASE = 'http://localhost:5000';

async function sendWarningToTab(tabId, payload) {
    try {
        await chrome.tabs.sendMessage(tabId, payload);
        return true;
    } catch (_) {
        // If content script isn't ready yet, inject and retry once.
        try {
            await chrome.scripting.insertCSS({ target: { tabId }, files: ['content.css'] });
        } catch (_) {
            // CSS may already be present or page may not allow injection.
        }

        try {
            await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
            await chrome.tabs.sendMessage(tabId, payload);
            return true;
        } catch (error) {
            console.log('Could not deliver warning popup to tab:', error);
            return false;
        }
    }
}

// Show notification
async function showNotification(title, message) {
    try {
        // Ensure we have valid title and message
        const notificationTitle = title || 'PhishDash';
        const notificationMessage = message || 'Website safety check completed';

        await chrome.notifications.create({
            type: 'basic',
            title: notificationTitle,
            message: notificationMessage,
            priority: 2,
            requireInteraction: false,
            silent: false
        });
    } catch (error) {
        // Log the error but don't throw it to prevent extension from breaking
        console.error('Failed to show notification:', error);
    }
}

// Check URL and handle response
async function checkUrl(tabId, url) {
    if (!tabId || typeof url !== 'string' || !/^https?:\/\//i.test(url)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/check_url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        const data = await response.json();
        retryCount = 0; // Reset retry count on success

        const details = data.details || {};
        const status = details.analysis_status || 'dangerous';
        const riskScore = typeof details.risk_score === 'number' && !isNaN(details.risk_score)
            ? Math.max(0, Math.min(1, details.risk_score))
            : 1;
        const isPhishing = status === 'dangerous' || status === 'suspicious';
        const riskFactors = Array.isArray(details.risk_factors) ? details.risk_factors : [];

        // Confidence-like value shown in UI banner/notification.
        const displayConfidence = isPhishing ? riskScore : (1 - riskScore);

        // Update badge
        if (isPhishing) {
            chrome.action.setBadgeText({ text: "!", tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
            showNotification("Phishing Warning", `This website might be unsafe (${(displayConfidence * 100).toFixed(1)}% confidence)`);
        } else {
            chrome.action.setBadgeText({ text: "", tabId });
        }

        // Send message to content script, with fallback injection if needed.
        await sendWarningToTab(tabId, {
            action: 'showWarning',
            isPhishing,
            confidence: displayConfidence,
            riskFactors
        });

        // Update history
        chrome.storage.local.get({ history: [] }, function (result) {
            const history = result.history;
            history.unshift({
                url: url,
                status,
                riskPct: Math.round(riskScore * 100),
                ts: Date.now()
            });

            // Keep only the last 10 entries
            if (history.length > 10) {
                history.pop();
            }

            chrome.storage.local.set({ history: history });
        });

    } catch (error) {
        console.error('Error checking URL:', error);
        if (retryCount < MAX_RETRIES) {
            retryCount++;
            setTimeout(() => checkUrl(tabId, url), 1000 * retryCount);
        } else {
            showNotification("Error", "Failed to check website safety after multiple attempts");
        }
    }
}

// Listen for tab updates
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // Check if auto-check is enabled
        chrome.storage.local.get({ autoCheck: true }, function (data) {
            if (data.autoCheck) {
                checkUrl(tabId, tab.url);
            }
        });
    }
});

// Also scan when switching to an already loaded tab.
chrome.tabs.onActivated.addListener(({ tabId }) => {
    chrome.storage.local.get({ autoCheck: true }, function (data) {
        if (!data.autoCheck) {
            return;
        }

        chrome.tabs.get(tabId, function (tab) {
            if (chrome.runtime.lastError || !tab || !tab.url) {
                return;
            }
            checkUrl(tabId, tab.url);
        });
    });
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkUrl') {
        const tabId = request.tabId || (sender.tab && sender.tab.id);
        checkUrl(tabId, request.url);
    }
});