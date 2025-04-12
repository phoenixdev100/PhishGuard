// Initialize AOS
AOS.init({
    duration: 800,
    easing: 'ease-in-out',
    once: true,
    mirror: false
});

// Navbar scroll effect
const navbar = document.querySelector('.navbar');
window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
});

// URL Check functionality
const urlInput = document.getElementById('urlInput');
const checkButton = document.getElementById('checkButton');
const result = document.getElementById('result');

function showLoading() {
    result.innerHTML = `
        <div class="analysis-card loading">
            <div class="text-center p-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <h4 class="mt-3 mb-2">Analyzing URL</h4>
                <p class="text-muted">Please wait while we scan for potential threats...</p>
            </div>
        </div>
    `;
    result.style.display = 'block';
}

function showError(message) {
    result.innerHTML = `
        <div class="analysis-card error">
            <div class="text-center p-4">
                <i class="fas fa-exclamation-circle text-danger fa-3x mb-3"></i>
                <h4 class="text-danger mb-2">Analysis Error</h4>
                <p class="text-muted">${message}</p>
                <button class="btn btn-outline-primary mt-3" onclick="checkButton.click()">
                    <i class="fas fa-redo me-2"></i>Try Again
                </button>
            </div>
        </div>
    `;
    result.style.display = 'block';
}

function showResult(data) {
    const details = data.details;
    const riskScore = details.risk_score * 100;
    const statusClass = details.is_safe ? 'safe' : 'dangerous';
    const statusIcon = details.is_safe ? 'shield-check' : 'shield-exclamation';

    let riskLevel = 'Low Risk';
    let riskClass = 'success';
    if (riskScore > 70) {
        riskLevel = 'High Risk';
        riskClass = 'danger';
    } else if (riskScore > 30) {
        riskLevel = 'Medium Risk';
        riskClass = 'warning';
    }

    // Ensure risk factors is an array
    const riskFactors = Array.isArray(details.risk_factors) ? details.risk_factors : [details.risk_factors];
    const riskFactorsList = riskFactors
        .filter(factor => factor) // Remove null/undefined entries
        .map(factor =>
            `<li class="mb-2">
                <i class="fas fa-exclamation-circle text-${riskClass} me-2"></i>
                ${factor}
            </li>`
        ).join('');

    // Ensure detection methods is an array
    const detectionMethods = Array.isArray(details.detection_methods) ? details.detection_methods : [];
    const detectionBadges = detectionMethods
        .filter(method => method) // Remove null/undefined entries
        .map(method =>
            `<span class="badge bg-info me-2 mb-2">
                <i class="fas fa-robot me-1"></i>${method}
            </span>`
        ).join('');

    // Format domain age
    const domainAge = details.domain_age >= 0
        ? `${details.domain_age} days`
        : 'Unknown';

    result.innerHTML = `
        <div class="analysis-card ${statusClass}">
            <div class="result-header text-center p-4 border-bottom">
                <i class="fas fa-${statusIcon} fa-3x mb-3 text-${riskClass}"></i>
                <h3 class="mb-2">${details.is_safe ? 'Safe Website' : 'Potential Threat Detected'}</h3>
                <p class="text-muted mb-0">${details.url || 'N/A'}</p>
            </div>
            
            <div class="result-body p-4">
                <div class="row">
                    <div class="col-md-6 mb-4 mb-md-0">
                        <div class="analysis-stats">
                            <div class="stat-item mb-3">
                                <h5 class="text-dark">Risk Assessment</h5>
                                <div class="progress mb-2" style="height: 10px;">
                                    <div class="progress-bar bg-${riskClass}" 
                                         role="progressbar" 
                                         style="width: ${riskScore}%"
                                         aria-valuenow="${riskScore}" 
                                         aria-valuemin="0" 
                                         aria-valuemax="100">
                                    </div>
                                </div>
                                <small class="text-${riskClass} fw-bold">${riskLevel} (${riskScore.toFixed(1)}%)</small>
                            </div>
                            
                            <div class="stat-item mb-3">
                                <h5 class="text-dark">Domain Information</h5>
                                <p class="mb-2">
                                    <i class="fas fa-calendar me-2"></i>
                                    <strong>Age:</strong> ${domainAge}
                                </p>
                                <p class="mb-0">
                                    <i class="fas fa-lock me-2"></i>
                                    <strong>SSL:</strong> 
                                    <span class="${details.has_ssl ? 'text-success' : 'text-danger'}">
                                        ${details.has_ssl ? 'Valid Certificate' : 'No SSL Found'}
                                    </span>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="detection-details">
                            <h5 class="text-dark mb-3">Detection Methods</h5>
                            <div class="detection-badges mb-4">
                                ${detectionBadges || '<span class="text-muted">No detection methods used</span>'}
                            </div>
                            
                            <h5 class="text-dark mb-3">Risk Factors</h5>
                            <ul class="risk-factors-list list-unstyled">
                                ${riskFactorsList || '<li class="text-success"><i class="fas fa-check-circle me-2"></i>No risk factors detected</li>'}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    result.style.display = 'block';
}

checkButton.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if (!url) {
        showToast('Please enter a URL to check');
        return;
    }

    showLoading();

    try {
        const response = await fetch('/check_url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (data.status === 'error') {
            showError(data.message || 'Error analyzing URL');
        } else {
            showResult(data);
        }
    } catch (error) {
        showError('Error connecting to server. Please try again.');
        console.error('Error:', error);
    }
});

// Enable checking URL on Enter key press
urlInput.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        checkButton.click();
    }
});

// Particle effect for hero section
function createParticles() {
    const particles = document.querySelector('.hero-particles');
    const particleCount = 50;

    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.cssText = `
            position: absolute;
            width: ${Math.random() * 5 + 1}px;
            height: ${Math.random() * 5 + 1}px;
            background: rgba(255, 255, 255, ${Math.random() * 0.5 + 0.1});
            left: ${Math.random() * 100}%;
            top: ${Math.random() * 100}%;
            border-radius: 50%;
            animation: float ${Math.random() * 10 + 5}s linear infinite;
        `;
        particles.appendChild(particle);
    }
}

// Contact form handling
const contactForm = document.getElementById('contactForm');
if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
        e.preventDefault();
        showToast('Message sent successfully!');
        contactForm.reset();
    });
}

// Newsletter form handling
const newsletterForm = document.querySelector('.newsletter-form');
if (newsletterForm) {
    newsletterForm.addEventListener('submit', (e) => {
        e.preventDefault();
        showToast('Successfully subscribed to newsletter!');
        newsletterForm.reset();
    });
}

// Toast notification
function showToast(message) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(toast);
            }, 300);
        }, 3000);
    }, 100);
}

// Initialize particles on load
window.addEventListener('load', createParticles);
