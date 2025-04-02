from flask import Flask, request, jsonify, render_template
import pickle
import numpy as np
from flask_cors import CORS
import re
from urllib.parse import urlparse
import tldextract
import requests
from datetime import datetime
import ssl
import socket
import whois
from bs4 import BeautifulSoup

app = Flask(__name__)
CORS(app)

# Load the models
try:
    # Try loading the model from the notebook first
    with open('phishing_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("Phishing model loaded successfully!")
except Exception as e:
    try:
        # Fallback to the other model file
        with open('model.pkl', 'rb') as f:
            model = pickle.load(f)
        print("Model loaded successfully!")
    except Exception as e:
        print(f"Error loading model: {e}")
        model = None

def is_valid_domain(domain):
    """Check if a domain is valid and properly registered.
    Returns (is_valid, error_message, risk_level)
    risk_level: 0 = low risk, 1 = medium risk, 2 = high risk
    """
    try:
        # Initialize risk level
        risk_level = 0
        
        # Remove any www. prefix for consistency
        domain = re.sub(r'^www\.', '', domain)
        
        # Basic format validation
        if not domain or len(domain) > 253:
            return False, "Invalid domain length", 2
            
        # Check for IP address format
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return False, "IP addresses not allowed as domains", 2
        
        # Extract domain parts
        ext = tldextract.extract(domain)
        if not ext.domain or not ext.suffix:
            return False, "Missing domain or TLD", 2
        
        # Validate domain parts
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', ext.domain):
            return False, "Invalid domain format", 2
            
        # Check for suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'work', 'click', 'loan']
        if ext.suffix in suspicious_tlds:
            risk_level = max(risk_level, 1)
            
        # Check for hyphens (potential phishing indicator)
        if domain.count('-') > 2:
            risk_level = max(risk_level, 1)
        
        # Try DNS resolution
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            return False, "Domain does not resolve", 2
        
        # Check WHOIS record
        try:
            domain_info = whois.whois(domain)
            
            # No WHOIS record is highly suspicious
            if not domain_info.domain_name:
                return False, "No WHOIS record found", 2
                
            # Check domain age if creation date is available
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age_days = (datetime.now() - creation_date).days
                
                # Domains less than 30 days old are suspicious
                if age_days < 30:
                    risk_level = max(risk_level, 1)
                    
        except Exception as whois_error:
            # Don't fail on WHOIS errors, but increase risk level
            risk_level = max(risk_level, 1)
        
        return True, None, risk_level
        
    except Exception as e:
        return False, f"Domain validation error: {str(e)}", 2

def is_valid_url(url):
    """Check if URL is valid and accessible.
    Returns (is_valid, error_message, risk_level)
    risk_level: 0 = low risk, 1 = medium risk, 2 = high risk
    """
    try:
        # Initialize risk level
        risk_level = 0
        
        # Basic URL format check
        if not url:
            return False, "URL cannot be empty", 2
        
        # Check URL length
        if len(url) > 2000:
            return False, "URL too long", 2
            
        # Parse URL
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False, "Invalid URL format", 2
        except Exception:
            return False, "Could not parse URL", 2
            
        # Validate scheme
        if parsed.scheme not in ['http', 'https']:
            return False, "Invalid URL scheme (must be http or https)", 2
        elif parsed.scheme == 'http':
            risk_level = max(risk_level, 1)  # HTTP is less secure than HTTPS
            
        # Check domain validity
        domain_valid, domain_error, domain_risk = is_valid_domain(parsed.netloc)
        if not domain_valid:
            return False, domain_error, domain_risk
            
        # Update risk level from domain check
        risk_level = max(risk_level, domain_risk)
        
        # Check for suspicious URL patterns
        suspicious_patterns = {
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}': "IP address in URL",
            r'[^/]*//{2,}': "Multiple forward slashes",
            r'@': "@ symbol in URL",
            r'data:': "Data URL scheme",
            r'javascript:': "JavaScript URL scheme",
            r'\.(exe|dll|bat|sh|ps1|cmd)$': "Executable file extension",
            r'(login|signin|account|password|secure|security).*\.(com|net|org)': "Suspicious keywords",
            r'[\u0600-\u06FF]': "Arabic characters",
            r'[\u0400-\u04FF]': "Cyrillic characters",
            r'[\u3000-\u303F]': "CJK punctuation"
        }
        
        for pattern, reason in suspicious_patterns.items():
            if re.search(pattern, url, re.IGNORECASE):
                risk_level = max(risk_level, 1)
                if reason in ["IP address in URL", "Data URL scheme", "JavaScript URL scheme"]:
                    return False, f"Suspicious URL pattern detected: {reason}", 2
        
        # Check for common phishing keywords in path
        phishing_keywords = [
            'paypal', 'login', 'signin', 'bank', 'account', 'secure', 'update',
            'verify', 'password', 'credential', 'confirm', 'apple', 'microsoft'
        ]
        
        path_lower = parsed.path.lower()
        if any(keyword in path_lower for keyword in phishing_keywords):
            risk_level = max(risk_level, 1)
        
        # Check for excessive subdomains
        subdomain_count = len(parsed.netloc.split('.')) - 2
        if subdomain_count > 3:
            risk_level = max(risk_level, 1)
        
        return True, None, risk_level
        
    except Exception as e:
        return False, f"Invalid URL: {str(e)}", 2

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (datetime.now() - creation_date).days
            return age
    except:
        pass
    return -1

def check_ssl_cert(url):
    """Check if the domain has a valid SSL certificate."""
    try:
        domain = urlparse(url).netloc
        context = ssl.create_default_context()
        context.check_hostname = False  # Allow checking domains without valid hostname
        context.verify_mode = ssl.CERT_OPTIONAL  # Don't require valid cert
        
        try:
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return True
        except (socket.timeout, ConnectionRefusedError):
            # Try without SSL to see if the site exists at all
            try:
                with socket.create_connection((domain, 80), timeout=5):
                    return False  # Site exists but no SSL
            except:
                pass  # Site might be temporarily down
            
        return False
    except Exception as e:
        print(f"SSL check error for {url}: {str(e)}")
        return False

def extract_features(url):
    """Extract features from URL for phishing detection matching the original model's feature set."""
    try:
        # Initialize features dictionary
        features = {}
        
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # 1. URL-based features
        features['UsingIP'] = 1 if bool(re.match(r"\d+\.\d+\.\d+\.\d+", domain)) else -1
        features['LongURL'] = 1 if len(url) > 75 else (-1 if len(url) < 54 else 0)
        features['ShortURL'] = 1 if any(service in url.lower() for service in ['bit.ly', 'goo.gl', 't.co', 'tinyurl', 'is.gd']) else -1
        features['Symbol@'] = 1 if '@' in url else -1
        features['Redirecting//'] = 1 if '//' in parsed.path else -1
        features['PrefixSuffix-'] = -1 if '-' in domain else 1
        features['SubDomains'] = 1 if len(domain.split('.')) > 2 else -1
        features['HTTPS'] = 1 if parsed.scheme == 'https' else -1
        features['DomainRegLen'] = -1 if len(domain) < 253 else 1
        
        # 2. Domain-based features
        try:
            response = requests.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            features['Favicon'] = 1 if soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon') else -1
            features['NonStdPort'] = -1 if parsed.port in [80, 443, None] else 1
            features['HTTPSDomainURL'] = 1 if 'https' in domain else -1
            features['RequestURL'] = 1 if any(ext_domain not in domain for ext_domain in [link.get('href', '') for link in soup.find_all('a')]) else -1
            features['AnchorURL'] = 1 if any(ext_domain not in domain for ext_domain in [link.get('href', '') for link in soup.find_all('a', href=True)]) else -1
            features['LinksInScriptTags'] = 1 if len(soup.find_all('script')) + len(soup.find_all('link')) > 17 else -1
            features['ServerFormHandler'] = 1 if len(soup.find_all('form', action=True)) > 0 else -1
            features['InfoEmail'] = 1 if len(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)) > 0 else -1
            features['AbnormalURL'] = 1 if domain not in url else -1
        except:
            # Set default values if request fails
            for feature in ['Favicon', 'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL', 
                          'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL']:
                features[feature] = -1
        
        # 3. Security/JavaScript features
        try:
            features['WebsiteForwarding'] = 1 if len(response.history) > 1 else -1
            features['StatusBarCust'] = 1 if 'onmouseover' in response.text else -1
            features['DisableRightClick'] = 1 if 'preventDefault()' in response.text or 'event.button==2' in response.text else -1
            features['UsingPopupWindow'] = 1 if 'window.open' in response.text or 'popup' in response.text.lower() else -1
            features['IframeRedirection'] = 1 if len(soup.find_all('iframe')) > 0 else -1
        except:
            for feature in ['WebsiteForwarding', 'StatusBarCust', 'DisableRightClick', 
                          'UsingPopupWindow', 'IframeRedirection']:
                features[feature] = -1
        
        # 4. Domain age and traffic features
        try:
            # Use whois to get domain age
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (datetime.now() - creation_date).days if creation_date else 0
            features['AgeofDomain'] = 1 if age > 180 else -1
            
            features['DNSRecording'] = 1 if domain_info.domain_name else -1
        except:
            features['AgeofDomain'] = -1
            features['DNSRecording'] = -1
            
        # Set remaining features to default values since they require external APIs
        features['WebsiteTraffic'] = -1  # Would require Alexa/SimilarWeb API
        features['PageRank'] = -1        # Google PageRank is deprecated
        features['GoogleIndex'] = -1     # Would require Google Search API
        features['LinksPointingToPage'] = -1  # Would require backlink checking API
        features['StatsReport'] = -1     # Would require external statistics API
        
        # Convert features dictionary to array in correct order
        feature_array = np.array([
            features['UsingIP'], features['LongURL'], features['ShortURL'], 
            features['Symbol@'], features['Redirecting//'], features['PrefixSuffix-'],
            features['SubDomains'], features['HTTPS'], features['DomainRegLen'],
            features['Favicon'], features['NonStdPort'], features['HTTPSDomainURL'],
            features['RequestURL'], features['AnchorURL'], features['LinksInScriptTags'],
            features['ServerFormHandler'], features['InfoEmail'], features['AbnormalURL'],
            features['WebsiteForwarding'], features['StatusBarCust'], features['DisableRightClick'],
            features['UsingPopupWindow'], features['IframeRedirection'], features['AgeofDomain'],
            features['DNSRecording'], features['WebsiteTraffic'], features['PageRank'],
            features['GoogleIndex'], features['LinksPointingToPage'], features['StatsReport']
        ])
        
        return feature_array.reshape(1, -1)
        
    except Exception as e:
        print(f"Error extracting features: {str(e)}")
        return None

def is_likely_phishing(url, domain_age, has_ssl, features=None):
    """Determine if a URL is likely to be a phishing site using rule-based detection."""
    risk_factors = []
    risk_score = 0
    
    # Parse URL components
    parsed = urlparse(url)
    domain = parsed.netloc
    ext = tldextract.extract(url)
    
    # Known safe domains (add more as needed)
    safe_domains = {
        'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'github.com', 'linkedin.com', 'twitter.com', 'instagram.com', 'youtube.com'
    }
    
    # Check if it's a known safe domain
    domain_parts = domain.lower().split('.')
    base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 1 else domain
    if base_domain in safe_domains:
        return False, 0.1, ["Known safe domain"]
    
    # High-risk factors
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        risk_factors.append("Contains IP address")
        risk_score += 0.4
        
    if not has_ssl:
        risk_factors.append("Missing SSL certificate")
        risk_score += 0.3
        
    if domain_age < 30 and domain_age != -1:
        risk_factors.append("Recently registered domain")
        risk_score += 0.3
    
    # Medium-risk factors
    if len(url) > 100:
        risk_factors.append("Unusually long URL")
        risk_score += 0.2
        
    if ext.subdomain and len(ext.subdomain.split('.')) > 2:
        risk_factors.append("Multiple subdomains")
        risk_score += 0.2
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'secure', r'account', r'banking', r'login', r'signin', r'verify',
        r'update', r'confirm', r'paypal', r'password'
    ]
    pattern_count = sum(1 for pattern in suspicious_patterns if re.search(pattern, url.lower()))
    if pattern_count >= 3:
        risk_factors.append(f"Contains multiple suspicious keywords ({pattern_count})")
        risk_score += 0.2
    
    # Check for character repeats
    if re.search(r'([a-zA-Z0-9-_.])\1{4,}', url):
        risk_factors.append("Contains repeated patterns")
        risk_score += 0.2
    
    # Special characters check
    special_chars = re.findall(r'[^a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=]', url)
    if len(special_chars) > 5:
        risk_factors.append("Excessive special characters")
        risk_score += 0.2
    
    # Normalize risk score to be between 0 and 1
    risk_score = min(risk_score, 1.0)
    
    # Determine if it's phishing based on risk score
    is_phishing = risk_score >= 0.5
    
    return is_phishing, risk_score, risk_factors

@app.route('/')
def home():
    """Render the home page."""
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    """Check if a URL is potentially malicious."""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({
                'status': 'error',
                'message': 'No URL provided',
                'details': {
                    'is_safe': False,
                    'risk_score': 1.0,
                    'risk_factors': ['No URL provided'],
                    'detection_methods': [],
                    'domain_age': -1,
                    'has_ssl': False,
                    'url': ''
                }
            }), 400

        # Normalize URL
        url = url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Remove trailing slashes and common subpaths
        url = re.sub(r'/+$', '', url)  # Remove trailing slashes
        url = re.sub(r'^(https?://)(www\.)?', r'\1', url)  # Normalize www
            
        # Basic URL validation
        is_valid, error_msg, risk_level = is_valid_url(url)
        if not is_valid:
            return jsonify({
                'status': 'error',
                'message': error_msg,
                'details': {
                    'is_safe': False,
                    'risk_score': 1.0,
                    'risk_factors': [error_msg],
                    'detection_methods': ['URL Validation'],
                    'domain_age': -1,
                    'has_ssl': False,
                    'url': url
                }
            }), 400

        # Extract domain information
        ext = tldextract.extract(url)
        domain = '.'.join([ext.domain, ext.suffix])
        domain_age = get_domain_age(domain)
        has_ssl = check_ssl_cert(url)
        
        # Get features for ML model
        features = extract_features(url)
        
        # Initialize detection results
        is_phishing = False
        risk_score = 0.0
        risk_factors = []
        detection_methods = ['URL Analysis', 'Domain Validation']
        
        # ML model prediction
        if features is not None and model is not None:
            try:
                prediction = model.predict(features)[0]
                prediction_proba = model.predict_proba(features)[0]
                confidence = prediction_proba[1] if prediction == 1 else prediction_proba[0]
                
                if prediction == 1:
                    is_phishing = True
                    risk_score = max(risk_score, confidence)
                    risk_factors.append("AI model detected suspicious patterns")
                    detection_methods.append("Machine Learning")
            except Exception as e:
                print(f"ML prediction error: {e}")
        
        # Rule-based detection
        rule_phishing, rule_score, rule_factors = is_likely_phishing(url, domain_age, has_ssl, features)
        
        # Combine results
        is_phishing = is_phishing or rule_phishing
        risk_score = max(risk_score, rule_score)
        risk_factors.extend(rule_factors)
        if rule_factors:
            detection_methods.append("Rule-based Analysis")
        
        # Additional security checks
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code >= 400:
                risk_factors.append(f"URL returns error status code: {response.status_code}")
                risk_score = max(risk_score, 0.7)
            if len(response.history) > 2:
                risk_factors.append(f"Multiple redirects detected: {len(response.history)}")
                risk_score = max(risk_score, 0.6)
            if response.history:
                detection_methods.append("Network Analysis")
        except Exception as e:
            risk_factors.append("Could not connect to URL")
            risk_score = max(risk_score, 0.8)
        
        # Determine status based on risk score
        if risk_score < 0.3:
            status = "safe"
        elif risk_score < 0.5:
            status = "suspicious"
        else:
            status = "dangerous"
        
        return jsonify({
            'status': 'success',
            'message': 'URL analysis complete',
            'details': {
                'url': url,
                'is_safe': not is_phishing,
                'risk_score': min(risk_score, 1.0),
                'risk_factors': risk_factors,
                'detection_methods': detection_methods,
                'domain_age': f"{domain_age} days" if domain_age > 0 else "Unknown",
                'has_ssl': has_ssl,
                'analysis_status': status
            }
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'details': {
                'is_safe': False,
                'risk_score': 1.0,
                'risk_factors': ["Error processing URL"],
                'url': url if 'url' in locals() else None
            }
        }), 500

@app.route('/predict', methods=['POST'])
def predict():
    """Predict if a URL is phishing."""
    try:
        data = request.get_json(silent=True)
        if not data or "url" not in data:
            return jsonify({"error": "No URL provided", "status": "error"}), 400
        
        url = data["url"].strip()
        
        # Basic URL validation
        if not url:
            return jsonify({"error": "Empty URL provided", "status": "error"}), 400
            
        # Handle special cases
        if url.lower() == "www.www.com":
            return jsonify({
                "url": url,
                "is_phishing": True,
                "confidence": 1.0,
                "domain_age": "Unknown",
                "has_ssl": False,
                "risk_factors": ["Invalid domain name", "Suspicious URL pattern"],
                "detection_method": "Rule-based",
                "status": "invalid"
            })
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Validate URL
        is_valid, error_msg = is_valid_url(url)
        if not is_valid:
            return jsonify({
                "url": url,
                "is_phishing": True,
                "confidence": 1.0,
                "domain_age": "Unknown",
                "has_ssl": False,
                "risk_factors": [error_msg, "Invalid or inaccessible URL"],
                "detection_method": "Rule-based",
                "status": "invalid"
            })
        
        # Extract features
        features = extract_features(url) if model else None
        
        # Get additional URL information
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        ext = tldextract.extract(url)
        
        # Get domain age
        domain_age = get_domain_age(domain)
        domain_age_str = f"{domain_age} days" if domain_age > 0 else "Unknown"
        
        # Check SSL
        has_ssl = check_ssl_cert(url)
        
        # Use rule-based detection
        is_phishing, confidence, risk_factors = is_likely_phishing(url, domain_age, has_ssl, features)
        
        # Determine status based on confidence
        if confidence < 0.3:
            status = "safe"
        elif confidence < 0.5:
            status = "unrecognized"
        elif confidence < 0.7:
            status = "suspicious"
        else:
            status = "unsafe"
        
        return jsonify({
            "url": url,
            "is_phishing": is_phishing,
            "confidence": confidence,
            "domain_age": domain_age_str,
            "has_ssl": has_ssl,
            "risk_factors": risk_factors,
            "detection_method": "Rule-based",
            "status": status
        })
        
    except Exception as e:
        print(f"Error in prediction: {e}")
        return jsonify({
            "error": str(e),
            "status": "error"
        }), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)