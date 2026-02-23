let retryCount = 0;
const MAX_RETRIES = 3;

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
    try {
        const response = await fetch("http://127.0.0.1:5000/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }
        
        const data = await response.json();
        retryCount = 0; // Reset retry count on success

        // Ensure confidence is a valid number and calculate display confidence
        const rawConfidence = typeof data.confidence === 'number' && !isNaN(data.confidence) ? data.confidence : 0;
        const displayConfidence = data.is_phishing ? rawConfidence : (1 - rawConfidence);
        
        // Update badge
        if (data.is_phishing) {
            chrome.action.setBadgeText({ text: "!", tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
            showNotification("Phishing Warning", `This website might be unsafe (${(displayConfidence * 100).toFixed(1)}% confidence)`);
        } else {
            chrome.action.setBadgeText({ text: "", tabId });
        }

        // Send message to content script
        try {
            await chrome.tabs.sendMessage(tabId, {
                action: 'showWarning',
                isPhishing: data.is_phishing,
                confidence: displayConfidence,
                riskFactors: data.risk_factors || []
            });
        } catch (error) {
            console.log('Content script not ready:', error);
        }

        // Update history
        chrome.storage.local.get({history: []}, function(result) {
            const history = result.history;
            history.unshift({
                url: url,
                phishing: data.is_phishing,
                confidence: displayConfidence,
                timestamp: new Date().toISOString()
            });
            
            // Keep only the last 10 entries
            if (history.length > 10) {
                history.pop();
            }
            
            chrome.storage.local.set({history: history});
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
        chrome.storage.local.get({autoCheck: true}, function(data) {
            if (data.autoCheck) {
                checkUrl(tabId, tab.url);
            }
        });
    }
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkUrl') {
        const tabId = request.tabId || (sender.tab && sender.tab.id);
        checkUrl(tabId, request.url);
    }
});