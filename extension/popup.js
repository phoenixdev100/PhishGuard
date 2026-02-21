// ─── Constants ───────────────────────────────────────────────────────────────
const API_BASE = 'http://127.0.0.1:5000';

const SPINNER_TEXTS = [
    'Resolving domain…',
    'Checking SSL…',
    'Querying WHOIS…',
    'Running AI analysis…',
    'Computing risk score…',
];

// ─── Server status check ─────────────────────────────────────────────────────
async function checkServerStatus() {
    const dot = document.getElementById('serverDot');
    const label = document.getElementById('serverLabel');
    try {
        const r = await fetch(`${API_BASE}/`, { method: 'HEAD', signal: AbortSignal.timeout(2000) });
        const ok = r.ok;
        dot.className = `server-dot ${ok ? 'online' : 'offline'}`;
        label.textContent = ok ? 'Server online' : 'Server offline';
        return ok;
    } catch {
        dot.className = 'server-dot offline';
        label.textContent = 'Server offline';
        return false;
    }
}

// ─── History helpers ─────────────────────────────────────────────────────────
function saveHistory(url, status, riskPct) {
    chrome.storage.local.get({ history: [] }, ({ history }) => {
        history.unshift({ url, status, riskPct, ts: Date.now() });
        if (history.length > 15) history.length = 15;
        chrome.storage.local.set({ history }, renderHistory);
    });
}

function renderHistory() {
    chrome.storage.local.get({ history: [] }, ({ history }) => {
        const el = document.getElementById('history');
        if (!history.length) {
            el.innerHTML = `<div class="empty-state">
                <i class="fa-solid fa-shield-halved"></i>
                No scans yet — analyse a URL above
            </div>`;
            return;
        }
        el.innerHTML = history.map(({ url, status, riskPct }) => {
            const cls = status === 'safe' ? 'safe' : status === 'suspicious' ? 'warn' : 'danger';
            const icon = status === 'safe' ? 'fa-check' : status === 'suspicious' ? 'fa-triangle-exclamation' : 'fa-xmark';
            const disp = url.replace(/^https?:\/\//, '').slice(0, 38);
            return `
            <div class="history-item">
                <div class="history-badge ${cls}">
                    <i class="fa-solid ${icon}"></i>
                </div>
                <span class="history-url" title="${url}">${disp}</span>
                <span class="history-score">${riskPct}%</span>
            </div>`;
        }).join('');
    });
}

// ─── Result card renderer ────────────────────────────────────────────────────
function showResult(data, rawUrl) {
    const details = data.details || {};
    const status = details.analysis_status || 'dangerous';
    const risk = details.risk_score ?? 1;
    const riskPct = Math.round(risk * 100);
    const hasSsl = details.has_ssl;
    const age = details.domain_age || 'Unknown';
    const factors = details.risk_factors || [];

    // colour class
    const cls = status === 'safe' ? 'safe' : status === 'suspicious' ? 'warn' : 'danger';
    const icon = status === 'safe' ? 'fa-shield-check' : status === 'suspicious' ? 'fa-triangle-exclamation' : 'fa-skull-crossbones';
    const title = status === 'safe' ? '✓ URL Appears Safe' : status === 'suspicious' ? '⚠ URL is Suspicious' : '✕ URL is Dangerous';

    // header
    document.getElementById('resultHeader').className = `result-header ${cls}`;
    document.getElementById('resultIcon').className = `result-hicon ${cls}`;
    document.getElementById('resultIconIcon').className = `fa-solid ${icon}`;
    document.getElementById('resultTitle').className = `result-htitle ${cls}`;
    document.getElementById('resultTitle').textContent = title;
    const dispUrl = (details.url || rawUrl).replace(/^https?:\/\//, '');
    document.getElementById('resultUrl').textContent = dispUrl.length > 42 ? dispUrl.slice(0, 42) + '…' : dispUrl;

    // stats
    const riskEl = document.getElementById('statRisk');
    riskEl.textContent = riskPct + '%';
    riskEl.className = `stat-val ${cls}`;

    const sslEl = document.getElementById('statSsl');
    sslEl.textContent = hasSsl ? 'Valid' : 'None';
    sslEl.className = `stat-val ${hasSsl ? 'safe' : 'danger'}`;

    const ageEl = document.getElementById('statAge');
    const ageNum = parseInt(age);
    ageEl.textContent = !isNaN(ageNum) ? (ageNum > 365 ? `${Math.floor(ageNum / 365)}y` : `${ageNum}d`) : age;
    ageEl.className = 'stat-val';

    // risk factors
    const fl = document.getElementById('factorsList');
    if (factors.length) {
        fl.innerHTML = factors.slice(0, 6).map(f => {
            const isOk = f.toLowerCase().includes('valid') || f.toLowerCase().includes('safe');
            return `<div class="factor-item ${isOk ? 'ok' : ''}">
                <i class="fa-solid ${isOk ? 'fa-circle-check' : 'fa-circle-exclamation'}"></i>
                <span>${f}</span>
            </div>`;
        }).join('');
    } else {
        fl.innerHTML = `<div class="factor-item ok">
            <i class="fa-solid fa-circle-check"></i>
            <span>No risk factors identified</span>
        </div>`;
    }

    document.getElementById('resultCard').classList.add('active');

    // save to history
    saveHistory(details.url || rawUrl, status, riskPct);

    // badge via background
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        chrome.runtime.sendMessage({ action: 'checkUrl', url: details.url || rawUrl, tabId: tabs[0]?.id });
    });
}

function showError(msg, rawUrl) {
    document.getElementById('resultHeader').className = 'result-header danger';
    document.getElementById('resultIcon').className = 'result-hicon danger';
    document.getElementById('resultIconIcon').className = 'fa-solid fa-circle-xmark';
    document.getElementById('resultTitle').className = 'result-htitle danger';
    document.getElementById('resultTitle').textContent = 'Scan Failed';
    document.getElementById('resultUrl').textContent = msg.slice(0, 50);
    document.getElementById('statRisk').textContent = '–';
    document.getElementById('statSsl').textContent = '–';
    document.getElementById('statAge').textContent = '–';
    document.getElementById('factorsList').innerHTML =
        `<div class="factor-item"><i class="fa-solid fa-circle-exclamation"></i><span>${msg}</span></div>`;
    document.getElementById('resultCard').classList.add('active');
}

// ─── Main scan function ──────────────────────────────────────────────────────
async function checkPhishing() {
    const inputEl = document.getElementById('urlInput');
    const btn = document.getElementById('checkButton');
    const spinner = document.getElementById('spinner');
    const spinText = document.getElementById('spinnerText');
    const card = document.getElementById('resultCard');

    const url = inputEl.value.trim();
    if (!url) {
        inputEl.style.borderColor = '#dc2626';
        setTimeout(() => (inputEl.style.borderColor = ''), 1400);
        return;
    }

    // loading state
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning';
    spinner.classList.add('active');
    card.classList.remove('active');

    let si = 0;
    const interval = setInterval(() => {
        si = (si + 1) % SPINNER_TEXTS.length;
        spinText.textContent = SPINNER_TEXTS[si];
    }, 1100);

    try {
        const res = await fetch(`${API_BASE}/check_url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });
        clearInterval(interval);
        const data = await res.json();
        showResult(data, url);
    } catch (e) {
        clearInterval(interval);
        showError('Could not reach server. Is Flask running?', url);
    } finally {
        spinner.classList.remove('active');
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> Analyse';
    }
}

// ─── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Pre-fill with current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        const u = tabs[0]?.url;
        if (u && u.startsWith('http')) document.getElementById('urlInput').value = u;
    });

    // Server status
    checkServerStatus();

    // Scan button & Enter key
    document.getElementById('checkButton').addEventListener('click', checkPhishing);
    document.getElementById('urlInput').addEventListener('keydown', e => {
        if (e.key === 'Enter') checkPhishing();
    });

    // Auto-check toggle
    chrome.storage.local.get({ autoCheck: true }, ({ autoCheck }) => {
        const toggle = document.getElementById('autoCheckToggle');
        toggle.checked = autoCheck;
        toggle.onchange = () => chrome.storage.local.set({ autoCheck: toggle.checked });
    });

    // Clear history button
    document.getElementById('clearHistory').addEventListener('click', () => {
        chrome.storage.local.set({ history: [] }, renderHistory);
    });

    // Initial history render
    renderHistory();
});