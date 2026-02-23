// Create and inject warning banner
function createWarningBanner(isPhishing, confidence) {
    const banner = document.createElement('div');
    banner.id = 'phishdash-warning';
    banner.style.cssText = `
        position: fixed;
        top: 12px;
        right: 12px;
        padding: 14px 20px;
        text-align: center;
        font-family: 'Segoe UI', Arial, sans-serif;
        z-index: 999999;
        animation: slideDown 0.5s ease-out;
        border-radius: 12px;
        display: flex;
        align-items: center;
        gap: 15px;
        max-width: 420px;
        font-size: 15px;
        backdrop-filter: blur(8px);
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.15);
    `;

    // Ensure confidence is a valid number
    const confidenceValue = typeof confidence === 'number' && !isNaN(confidence) ? confidence : 0;
    const displayConfidence = (confidenceValue * 100).toFixed(1);

    if (isPhishing) {
        banner.style.backgroundColor = 'rgba(255, 50, 50, 0.95)';
        banner.style.color = 'white';
        banner.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px; flex-grow: 1;">
                <span style="font-weight: bold; font-size: 17px;">⚠️</span>
                <div style="text-align: left;">
                    <div style="font-weight: 600; margin-bottom: 2px;">Warning: Potential Phishing Site</div>
                    <div style="font-size: 13px; opacity: 0.9;">Confidence: ${displayConfidence}%</div>
                </div>
            </div>
            <button id="phishdash-close" style="background: rgba(255, 255, 255, 0.2); border: none; color: white; cursor: pointer; padding: 6px 10px; font-size: 13px; border-radius: 6px; font-weight: 500;">Close</button>
        `;
    } else {
        banner.style.backgroundColor = 'rgba(40, 200, 80, 0.95)';
        banner.style.color = 'white';
        banner.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px; flex-grow: 1;">
                <span style="font-weight: bold; font-size: 17px;">✅</span>
                <div style="text-align: left;">
                    <div style="font-weight: 600; margin-bottom: 2px;">Safe Website</div>
                    <div style="font-size: 13px; opacity: 0.9;">Confidence: ${displayConfidence}%</div>
                </div>
            </div>
            <button id="phishdash-close" style="background: rgba(255, 255, 255, 0.2); border: none; color: white; cursor: pointer; padding: 6px 10px; font-size: 13px; border-radius: 6px; font-weight: 500;">Close</button>
        `;
    }

    document.body.insertBefore(banner, document.body.firstChild);

    // Add event listener
    document.getElementById('phishdash-close').addEventListener('click', () => {
        banner.style.animation = 'slideUp 0.3s ease-out forwards';
        setTimeout(() => {
            banner.remove();
        }, 300);
    });
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'showWarning') {
        createWarningBanner(message.isPhishing, message.confidence);
    }
}); 