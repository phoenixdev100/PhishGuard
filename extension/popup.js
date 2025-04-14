let isServerRunning = false;

// Check if server is running
async function checkServerStatus() {
    try {
        const response = await fetch("http://127.0.0.1:5000/");
        isServerRunning = response.ok;
    } catch (error) {
        isServerRunning = false;
    }
    return isServerRunning;
}

function updateHistory(url, isPhishing, confidence) {
    chrome.storage.local.get({history: []}, function(data) {
        const history = data.history;
        history.unshift({
            url: url,
            phishing: isPhishing,
            confidence: isPhishing ? confidence : (1 - confidence),
            timestamp: new Date().toISOString()
        });
        
        // Keep only the last 10 entries
        if (history.length > 10) {
            history.pop();
        }
        
        chrome.storage.local.set({history: history}, function() {
            renderHistory();
        });
    });
}

function renderHistory() {
    chrome.storage.local.get({history: []}, function(data) {
        const historyElement = document.getElementById('history');
        if (data.history.length === 0) {
            historyElement.innerHTML = '<div style="color: #7f8c8d; text-align: center;">No scan history</div>';
            return;
        }
        
        historyElement.innerHTML = data.history.map(entry => {
            const confidence = entry.confidence || 0;
            return `
                <div class="history-item ${entry.phishing ? 'phishing' : 'safe'}">
                    <div>${entry.url}</div>
                    <div style="font-size: 11px; margin-top: 3px;">
                        ${entry.phishing ? '⚠️ Unsafe' : '✅ Safe'} (${(confidence * 100).toFixed(1)}%)
                    </div>
                </div>
            `;
        }).join('');
    });
}

async function checkPhishing() {
    console.log('Starting phishing check');
    const urlInput = document.getElementById('urlInput');
    const resultElement = document.getElementById('result');
    const spinner = document.getElementById('spinner');
    
    if (!urlInput || !resultElement || !spinner) {
        console.error('Required elements not found');
        return;
    }

    const url = urlInput.value.trim();
    if (!url) {
        console.log('No URL provided');
        resultElement.textContent = 'Please enter a URL';
        return;
    }

    console.log('Checking URL:', url);
    spinner.style.display = 'block';
    resultElement.textContent = '';

    try {
        console.log('Sending request to server');
        const response = await fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        console.log('Server response received');
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const data = await response.json();
        console.log('Response data:', data);

        const isPhishing = data.is_phishing;
        const rawConfidence = typeof data.confidence === 'number' && !isNaN(data.confidence) ? data.confidence : 0;
        const confidence = isPhishing ? rawConfidence : (1 - rawConfidence);
        const riskFactors = data.risk_factors || [];

        // Update result display
        let resultHTML = '';
        if (isPhishing) {
            resultHTML = `
                <div style="color: #e74c3c;">
                    <i class="fas fa-exclamation-triangle"></i> Unsafe Website
                </div>
                <div style="font-size: 12px; margin-top: 5px;">
                    Confidence: ${(confidence * 100).toFixed(1)}%
                </div>
                <div style="font-size: 12px; margin-top: 5px;">
                    Risk Factors:
                    <ul style="margin: 5px 0; padding-left: 20px;">
                        ${riskFactors.map(factor => `<li>${factor}</li>`).join('')}
                    </ul>
                </div>
            `;
        } else {
            resultHTML = `
                <div style="color: #2ecc71;">
                    <i class="fas fa-check-circle"></i> Safe Website
                </div>
                <div style="font-size: 12px; margin-top: 5px;">
                    Confidence: ${(confidence * 100).toFixed(1)}%
                </div>
            `;
        }
        resultElement.innerHTML = resultHTML;

        // Get current tab ID and update history
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            const tabId = tabs[0]?.id;
            // Update badge and show notification through background script
            chrome.runtime.sendMessage({
                action: 'checkUrl',
                url: url,
                tabId: tabId
            });
        });

        // Update history directly
        updateHistory(url, isPhishing, confidence);
    } catch (error) {
        console.error('Error during phishing check:', error);
        resultElement.innerHTML = `
            <div style="color: #c0392b;">
                <i class="fas fa-exclamation-circle"></i> Error: ${error.message}
            </div>
            <div style="font-size: 12px; margin-top: 5px;">
                Please make sure the Flask server is running
            </div>
        `;
    } finally {
        spinner.style.display = 'none';
    }
}

// Initialize the popup
document.addEventListener('DOMContentLoaded', function() {
    console.log('Popup initialized');
    
    // Get current tab URL
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs[0]?.url) {
            document.getElementById('urlInput').value = tabs[0].url;
        }
    });

    // Set up auto-check toggle
    chrome.storage.local.get({autoCheck: true}, function(data) {
        const toggle = document.getElementById('autoCheckToggle');
        toggle.checked = data.autoCheck;
        toggle.onchange = function() {
            chrome.storage.local.set({autoCheck: toggle.checked});
        };
    });

    // Add event listener for the check button
    const checkButton = document.getElementById('checkButton');
    if (checkButton) {
        console.log('Adding click listener to check button');
        checkButton.addEventListener('click', function() {
            console.log('Check button clicked');
            checkPhishing();
        });
    } else {
        console.error('Check button not found');
    }

    // Add event listener for clear history button
    const clearHistoryButton = document.getElementById('clearHistory');
    if (clearHistoryButton) {
        clearHistoryButton.addEventListener('click', function() {
            chrome.storage.local.set({history: []}, function() {
                renderHistory();
            });
        });
    }

    // Render history
    renderHistory();
});