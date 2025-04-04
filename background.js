let debounceTimeout;

function checkUrl(tabId, url) {
    fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
    })
    .then(response => {
        if (!response.ok) throw new Error("Server error");
        return response.json();
    })
    .then(data => {
        if (data.phishing) {
            chrome.action.setBadgeText({ text: "!", tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
        } else {
            chrome.action.setBadgeText({ text: "", tabId });
        }
        chrome.storage.local.get({ history: [] }, (result) => {
            const updatedHistory = [{ url, phishing: data.phishing, confidence: data.confidence, timestamp: Date.now() }, ...result.history].slice(0, 5);
            chrome.storage.local.set({ history: updatedHistory });
        });
    })
    .catch(error => console.error("Background check failed:", error));
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete" || !tab.url || tab.url.startsWith("chrome://")) return;

    clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(() => {
        chrome.storage.local.get({ autoCheck: true }, (data) => {
            if (data.autoCheck) checkUrl(tabId, tab.url);
        });
    }, 500);
});