function updateHistory(url, phishing, confidence) {
    chrome.storage.local.get({ history: [] }, (data) => {
        const newEntry = { url, phishing, confidence, timestamp: Date.now() };
        const updatedHistory = [newEntry, ...data.history].slice(0, 5);
        chrome.storage.local.set({ history: updatedHistory }, renderHistory);
    });
}

function renderHistory() {
    chrome.storage.local.get({ history: [] }, (data) => {
        document.getElementById("history").innerHTML = data.history.map(entry => 
            `<div class="history-item">${entry.url} - ${entry.phishing ? "⚠️" : "✅"} (${(entry.confidence * 100).toFixed(1)}%)</div>`
        ).join("");
    });
}

async function checkPhishing() {
    const urlInput = document.getElementById("urlInput").value;
    const resultElement = document.getElementById("result");
    const spinner = document.getElementById("spinner");
    
    if (!urlInput) {
        resultElement.innerText = "Please enter a URL";
        return;
    }

    resultElement.innerText = "";
    spinner.style.display = "block";

    try {
        const response = await fetch("http://127.0.0.1:5000/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlInput })
        });

        if (!response.ok) throw new Error(`Server error: ${response.status}`);

        const data = await response.json();
        const isPhishing = data.phishing;
        const confidence = data.confidence * 100;
        resultElement.innerText = `${isPhishing ? "⚠️ Phishing Detected" : "✅ Safe"} (${confidence.toFixed(1)}%)`;
        resultElement.style.color = isPhishing ? "red" : "green";
        
        updateHistory(urlInput, isPhishing, data.confidence);
    } catch (error) {
        resultElement.innerText = "Error: Server unavailable";
        resultElement.style.color = "gray";
        console.error(error);
    } finally {
        spinner.style.display = "none";
    }
}

window.onload = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) document.getElementById("urlInput").value = tab.url;

    chrome.storage.local.get({ autoCheck: true }, (data) => {
        const toggle = document.getElementById("autoCheckToggle");
        toggle.checked = data.autoCheck;
        toggle.onchange = () => chrome.storage.local.set({ autoCheck: toggle.checked });
    });

    renderHistory();
};