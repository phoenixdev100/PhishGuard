"""
PhishGuard — Comprehensive URL Security Analyser
All network checks run in parallel via ThreadPoolExecutor.
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pickle, re, ssl, socket, struct, hashlib, difflib
import numpy as np
from urllib.parse import urlparse, urlencode, urljoin
import tldextract
import requests
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────
#  LOAD ML MODEL
# ─────────────────────────────────────────────────────────────
model = None
for fname in ('phishing_model.pkl', 'model.pkl'):
    try:
        with open(fname, 'rb') as f:
            model = pickle.load(f)
        print(f"[✓] ML model loaded: {fname}")
        break
    except Exception as e:
        print(f"[!] Could not load {fname}: {e}")

if model is None:
    print("[!] Running in rule-based mode only (no ML model).")

# ─────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────
KNOWN_SAFE = {
    'google.com', 'googleapis.com', 'facebook.com', 'fb.com', 'microsoft.com',
    'office.com', 'live.com', 'outlook.com', 'apple.com', 'icloud.com',
    'amazon.com', 'aws.amazon.com', 'github.com', 'githubusercontent.com',
    'linkedin.com', 'twitter.com', 'x.com', 'instagram.com', 'youtube.com',
    'netflix.com', 'spotify.com', 'reddit.com', 'wikipedia.org', 'mozilla.org',
    'adobe.com', 'dropbox.com', 'slack.com', 'zoom.us', 'discord.com',
    'cloudflare.com', 'paypal.com', 'stripe.com', 'shopify.com',
    'wordpress.com', 'stackoverflow.com', 'twitch.tv', 'tiktok.com',
    'whatsapp.com', 'telegram.org', 'protonmail.com',
}

POPULAR_BRANDS = [
    'google', 'gmail', 'facebook', 'instagram', 'microsoft', 'outlook', 'office',
    'apple', 'icloud', 'amazon', 'paypal', 'netflix', 'spotify', 'twitter',
    'linkedin', 'dropbox', 'adobe', 'github', 'yahoo', 'live', 'hotmail',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays',
    'ebay', 'walmart', 'coinbase', 'binance', 'robinhood',
]

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'work', 'click', 'loan', 'top',
    'club', 'online', 'site', 'fun', 'icu', 'buzz', 'vip', 'rest',
    'fit', 'stream', 'bid', 'win', 'download', 'racing',
}

SHORTENERS = {
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'ow.ly', 'buff.ly',
    'rb.gy', 'qps.ru', 'cutt.ly', 'shorturl.at', 'clck.ru', 'url.ie',
}

PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'account', 'secure', 'security', 'verify',
    'verification', 'update', 'confirm', 'password', 'credential', 'wallet',
    'banking', 'payment', 'invoice', 'reward', 'winner', 'prize', 'free',
    'limited-offer', 'urgent', 'alert', 'suspended', 'locked', 'unusual',
    'recover', 'restore', 'support', 'helpdesk', 'service', 'portal',
]

NET_TIMEOUT = 4   # seconds for all individual network calls

# ─────────────────────────────────────────────────────────────
#  HELPER: levenshtein distance for typosquatting
# ─────────────────────────────────────────────────────────────
def _lev(a, b):
    if len(a) < len(b):
        return _lev(b, a)
    if len(b) == 0:
        return len(a)
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        new_row = [i + 1]
        for j, cb in enumerate(b):
            new_row.append(min(row[j + 1] + 1, new_row[-1] + 1, row[j] + (ca != cb)))
        row = new_row
    return row[-1]

# ─────────────────────────────────────────────────────────────
#  CHECK 1: URL structure & heuristics (pure Python, instant)
# ─────────────────────────────────────────────────────────────
def check_url_structure(url, parsed, ext):
    issues = []
    score  = 0.0

    # Length
    if len(url) > 100:
        issues.append(f"Long URL ({len(url)} chars)")
        score += 0.15 if len(url) > 150 else 0.05

    # IP address used as host
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', parsed.netloc.split(':')[0]):
        issues.append("IP address used instead of domain")
        score += 0.55

    # @ symbol
    if '@' in url:
        issues.append("@ symbol redirects browser")
        score += 0.45

    # Double slash in path
    if '//' in parsed.path:
        issues.append("Double slash in path (redirect obfuscation)")
        score += 0.2

    # Non-standard port
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        issues.append(f"Non-standard port: {parsed.port}")
        score += 0.2

    # URL shortener
    netloc = parsed.netloc.lower().lstrip('www.')
    if netloc in SHORTENERS or any(s in url.lower() for s in SHORTENERS):
        issues.append("URL shortener detected (hides real destination)")
        score += 0.25

    # Excessive subdomains
    sub = ext.subdomain
    sub_count = len(sub.split('.')) if sub else 0
    if sub_count > 2:
        issues.append(f"Excessive subdomains ({sub_count})")
        score += 0.2

    # Hyphen count in domain
    h = (ext.domain or '').count('-')
    if h >= 3:
        issues.append(f"Many hyphens in domain ({h})")
        score += 0.2
    elif h >= 1:
        score += 0.05

    # Suspicious TLD
    if ext.suffix in SUSPICIOUS_TLDS:
        issues.append(f"Suspicious TLD: .{ext.suffix}")
        score += 0.3

    # HTTP (not HTTPS)
    if parsed.scheme == 'http':
        issues.append("Unencrypted HTTP (no TLS)")
        score += 0.2

    # Phishing keywords in full URL
    url_lower = url.lower()
    hits = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if len(hits) >= 3:
        issues.append(f"Many phishing keywords in URL: {', '.join(hits[:4])}")
        score += 0.3
    elif len(hits) >= 1:
        issues.append(f"Phishing keyword(s) in URL: {', '.join(hits[:3])}")
        score += 0.1

    # Encoded characters (obfuscation)
    pct_count = url.count('%')
    if pct_count > 5:
        issues.append(f"Heavy URL encoding ({pct_count} encoded chars)")
        score += 0.2

    # Executable extension
    if re.search(r'\.(exe|dll|bat|sh|ps1|cmd|vbs|msi|dmg|apk)(\?|$)', url, re.I):
        issues.append("Executable file extension in URL")
        score += 0.4

    # Punycode / IDN (homograph attack)
    if 'xn--' in url.lower():
        issues.append("Punycode / IDN domain (possible homograph attack)")
        score += 0.35

    return {'issues': issues, 'score': min(score, 1.0)}


# ─────────────────────────────────────────────────────────────
#  CHECK 2: Typosquatting (pure Python)
# ─────────────────────────────────────────────────────────────
def check_typosquatting(domain_name, base_domain):
    issues = []
    score  = 0.0
    for brand in POPULAR_BRANDS:
        if brand == domain_name:
            continue  # exact match = probably the real brand
        d = _lev(domain_name.lower(), brand)
        ratio = d / max(len(domain_name), len(brand))
        if d == 1:
            issues.append(f"Very close to brand '{brand}' (edit distance 1)")
            score = max(score, 0.7)
        elif d == 2 and ratio < 0.35:
            issues.append(f"Similar to brand '{brand}' (edit distance 2)")
            score = max(score, 0.4)
        # Brand embedded in domain but domain is not the brand
        if brand in domain_name.lower() and domain_name.lower() != brand:
            issues.append(f"Brand '{brand}' embedded in domain")
            score = max(score, 0.35)
    return {'issues': issues, 'score': min(score, 1.0)}


# ─────────────────────────────────────────────────────────────
#  CHECK 3: WHOIS / domain registration
# ─────────────────────────────────────────────────────────────
def check_whois(domain):
    result = {
        'domain_age_days': -1,
        'registrar': None,
        'expiry_days': None,
        'updated_days': None,
        'privacy_protected': False,
        'issues': [],
        'score': 0.0,
    }
    try:
        w = whois.whois(domain)
        if not w or not w.domain_name:
            result['issues'].append("No WHOIS record found")
            result['score'] = 0.5
            return result

        # Creation date → age
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if cd:
            age = (datetime.now() - cd).days
            result['domain_age_days'] = age
            if age < 30:
                result['issues'].append(f"Domain is only {age} days old")
                result['score'] += 0.45
            elif age < 180:
                result['issues'].append(f"Domain is relatively new ({age} days)")
                result['score'] += 0.15

        # Expiry date
        ed = w.expiration_date
        if isinstance(ed, list): ed = ed[0]
        if ed:
            exp_days = (ed - datetime.now()).days
            result['expiry_days'] = exp_days
            if exp_days < 90:
                result['issues'].append(f"Domain expires in {exp_days} days (throwaway domain?)")
                result['score'] += 0.2

        # Updated date
        ud = w.updated_date
        if isinstance(ud, list): ud = ud[0]
        if ud:
            result['updated_days'] = (datetime.now() - ud).days

        # Registrar
        result['registrar'] = str(w.registrar) if w.registrar else None

        # Privacy / proxy protection
        emails = w.emails or []
        if isinstance(emails, str): emails = [emails]
        priv_keywords = ['privacy', 'proxy', 'redacted', 'protect', 'whoisguard']
        if any(pk in str(w).lower() for pk in priv_keywords):
            result['privacy_protected'] = True
            result['issues'].append("WHOIS privacy-protected registration")
            result['score'] += 0.1

        result['score'] = min(result['score'], 1.0)
    except Exception as e:
        result['issues'].append(f"WHOIS lookup failed: {str(e)[:60]}")
        result['score'] = 0.15
    return result


# ─────────────────────────────────────────────────────────────
#  CHECK 4: SSL certificate analysis
# ─────────────────────────────────────────────────────────────
def check_ssl(url, parsed):
    result = {
        'has_ssl': False,
        'cert_valid': False,
        'cert_issuer': None,
        'cert_subject': None,
        'cert_expiry_days': None,
        'san_match': None,
        'issues': [],
        'score': 0.0,
    }
    domain = parsed.netloc.split(':')[0]

    if parsed.scheme != 'https':
        result['issues'].append("Site uses plain HTTP (no SSL/TLS)")
        result['score'] = 0.4
        return result

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL
        with socket.create_connection((domain, 443), timeout=NET_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result['has_ssl'] = True

                if cert:
                    result['cert_valid'] = True
                    # Issuer
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    result['cert_issuer'] = issuer_dict.get('organizationName', 'Unknown')

                    # Subject
                    subj_dict = dict(x[0] for x in cert.get('subject', []))
                    result['cert_subject'] = subj_dict.get('commonName')

                    # Expiry
                    not_after = cert.get('notAfter')
                    if not_after:
                        exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        exp_days = (exp - datetime.utcnow()).days
                        result['cert_expiry_days'] = exp_days
                        if exp_days < 0:
                            result['issues'].append("SSL certificate has EXPIRED")
                            result['score'] += 0.6
                        elif exp_days < 14:
                            result['issues'].append(f"SSL certificate expires in {exp_days} days")
                            result['score'] += 0.2

                    # SAN match check
                    sans = [v for _, v in cert.get('subjectAltName', [])]
                    match = any(
                        domain == s or domain.endswith('.' + s.lstrip('*.'))
                        for s in sans
                    )
                    result['san_match'] = match
                    if not match and sans:
                        result['issues'].append("Domain doesn't match certificate SAN")
                        result['score'] += 0.5

                    # Free/DV cert from suspicious issuer
                    issuer_low = result['cert_issuer'].lower() if result['cert_issuer'] else ''
                    if "let's encrypt" in issuer_low or "zerossl" in issuer_low:
                        result['issues'].append("Free DV certificate (common in phishing)")
                        result['score'] += 0.1

    except ssl.SSLCertVerificationError:
        result['has_ssl'] = True
        result['cert_valid'] = False
        result['issues'].append("SSL certificate is invalid / self-signed")
        result['score'] += 0.5
    except (socket.timeout, ConnectionRefusedError, OSError):
        result['issues'].append("Could not establish SSL connection")
        result['score'] += 0.3
    except Exception as e:
        result['issues'].append(f"SSL check error: {str(e)[:60]}")
        result['score'] += 0.1

    result['score'] = min(result['score'], 1.0)
    return result


# ─────────────────────────────────────────────────────────────
#  CHECK 5: DNS records (A, MX, NS, TXT)
# ─────────────────────────────────────────────────────────────
def check_dns(domain):
    result = {
        'resolves': False,
        'ip_addresses': [],
        'has_mx': False,
        'has_ns': False,
        'has_spf': False,
        'has_dmarc': False,
        'issues': [],
        'score': 0.0,
    }

    # A records
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        result['ip_addresses'] = list({i[4][0] for i in ips})
        result['resolves'] = True

        # Private / local IPs
        for ip in result['ip_addresses']:
            parts = list(map(int, ip.split('.')))
            if parts[0] in (10, 127) or (parts[0] == 172 and 16 <= parts[1] <= 31) \
               or (parts[0] == 192 and parts[1] == 168):
                result['issues'].append(f"Resolves to private/local IP: {ip}")
                result['score'] += 0.4

    except socket.gaierror:
        result['issues'].append("Domain does not resolve (DNS failure)")
        result['score'] += 0.5
        return result

    # MX (email capability)
    try:
        import dns.resolver
        mx = dns.resolver.resolve(domain, 'MX', lifetime=NET_TIMEOUT)
        result['has_mx'] = True
    except Exception:
        pass  # no MX is fine; just info

    # NS records
    try:
        import dns.resolver
        ns = dns.resolver.resolve(domain, 'NS', lifetime=NET_TIMEOUT)
        result['has_ns'] = bool(ns)
    except Exception:
        pass

    # TXT → SPF / DMARC (email authentication)
    try:
        import dns.resolver
        txts = dns.resolver.resolve(domain, 'TXT', lifetime=NET_TIMEOUT)
        for rdata in txts:
            txt = rdata.to_text().lower()
            if 'v=spf1' in txt:
                result['has_spf'] = True
            if 'v=dmarc1' in txt:
                result['has_dmarc'] = True
    except Exception:
        pass

    result['score'] = min(result['score'], 1.0)
    return result


# ─────────────────────────────────────────────────────────────
#  CHECK 6: HTTP response — headers + redirect chain
# ─────────────────────────────────────────────────────────────
def check_http(url):
    result = {
        'status_code': None,
        'redirect_count': 0,
        'redirect_chain': [],
        'final_url': url,
        'security_headers': {},
        'server': None,
        'content_type': None,
        'issues': [],
        'score': 0.0,
    }

    SEC_HEADERS = [
        'strict-transport-security', 'content-security-policy',
        'x-frame-options', 'x-content-type-options',
        'referrer-policy', 'permissions-policy',
    ]

    try:
        resp = requests.get(
            url, timeout=NET_TIMEOUT, verify=False,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (PhishGuard-Security-Scanner/2.0)'},
            stream=True   # don't download body yet
        )
        # Close the stream immediately — we only need headers
        resp.close()

        result['status_code'] = resp.status_code
        result['final_url'] = resp.url
        result['redirect_count'] = len(resp.history)
        result['redirect_chain'] = [r.url for r in resp.history] + [resp.url]
        result['server'] = resp.headers.get('Server')
        result['content_type'] = resp.headers.get('Content-Type', '')

        # Missing security headers
        missing = []
        for h in SEC_HEADERS:
            val = resp.headers.get(h)
            result['security_headers'][h] = val
            if not val:
                missing.append(h)

        if len(missing) >= 5:
            result['issues'].append(f"Missing critical security headers: {', '.join(missing[:3])}…")
            result['score'] += 0.15
        elif len(missing) >= 3:
            result['issues'].append(f"Missing security headers: {', '.join(missing[:3])}")
            result['score'] += 0.08

        # Redirect depth
        if result['redirect_count'] > 3:
            result['issues'].append(f"Deep redirect chain ({result['redirect_count']} hops)")
            result['score'] += 0.3
        elif result['redirect_count'] > 1:
            result['issues'].append(f"Multiple redirects ({result['redirect_count']} hops)")
            result['score'] += 0.1

        # Cross-domain redirect
        parsed_orig = urlparse(url)
        parsed_final = urlparse(resp.url)
        orig_d = tldextract.extract(parsed_orig.netloc)
        final_d = tldextract.extract(parsed_final.netloc)
        if orig_d.registered_domain != final_d.registered_domain:
            result['issues'].append(f"Redirects to different domain: {parsed_final.netloc}")
            result['score'] += 0.25

        # HTTP error
        if resp.status_code >= 400:
            result['issues'].append(f"Server returned HTTP {resp.status_code}")
            result['score'] += 0.2 if resp.status_code >= 500 else 0.1

    except requests.exceptions.SSLError:
        result['issues'].append("SSL handshake failed during HTTP check")
        result['score'] += 0.3
    except requests.exceptions.ConnectionError:
        result['issues'].append("Connection refused / unreachable")
        result['score'] += 0.3
    except requests.exceptions.Timeout:
        result['issues'].append("HTTP request timed out")
        result['score'] += 0.2
    except Exception as e:
        result['issues'].append(f"HTTP check error: {str(e)[:60]}")
        result['score'] += 0.1

    result['score'] = min(result['score'], 1.0)
    return result


# ─────────────────────────────────────────────────────────────
#  CHECK 7: Page content analysis
# ─────────────────────────────────────────────────────────────
def check_page_content(url, parsed):
    result = {
        'has_password_field': False,
        'form_count': 0,
        'external_form_action': False,
        'iframe_count': 0,
        'hidden_element_count': 0,
        'external_resource_ratio': 0.0,
        'has_right_click_disable': False,
        'has_popup': False,
        'has_obfuscated_js': False,
        'favicon_different_domain': False,
        'issues': [],
        'score': 0.0,
    }
    try:
        resp = requests.get(
            url, timeout=NET_TIMEOUT, verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (PhishGuard-Security-Scanner/2.0)'},
        )
        html = resp.text
        soup = BeautifulSoup(html, 'html.parser')
        base_domain = tldextract.extract(parsed.netloc).registered_domain

        # Password fields
        pwd_fields = soup.find_all('input', type='password')
        result['has_password_field'] = bool(pwd_fields)
        if pwd_fields and parsed.scheme != 'https':
            result['issues'].append("Password field on non-HTTPS page!")
            result['score'] += 0.6

        # Forms
        forms = soup.find_all('form')
        result['form_count'] = len(forms)
        for form in forms:
            action = form.get('action', '')
            if action and action.startswith(('http://', 'https://')):
                action_domain = tldextract.extract(action).registered_domain
                if action_domain and action_domain != base_domain:
                    result['external_form_action'] = True
                    result['issues'].append(f"Form submits to external domain: {action_domain}")
                    result['score'] += 0.55

        # iFrames
        iframes = soup.find_all('iframe')
        result['iframe_count'] = len(iframes)
        if len(iframes) > 2:
            result['issues'].append(f"Multiple hidden iframes ({len(iframes)})")
            result['score'] += 0.2

        # Hidden elements
        hidden = soup.find_all(style=re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden'))
        result['hidden_element_count'] = len(hidden)
        if len(hidden) > 10:
            result['issues'].append(f"Many hidden elements ({len(hidden)}) — possible cloaking")
            result['score'] += 0.15

        # External resource ratio
        all_srcs = [t.get('src', '') for t in soup.find_all(src=True)]
        all_hrefs = [t.get('href', '') for t in soup.find_all(href=True)]
        all_resources = all_srcs + all_hrefs
        if all_resources:
            ext_count = sum(
                1 for r in all_resources
                if r.startswith('http') and tldextract.extract(r).registered_domain != base_domain
            )
            ratio = ext_count / len(all_resources)
            result['external_resource_ratio'] = round(ratio, 2)
            if ratio > 0.7:
                result['issues'].append(f"High external resource ratio ({ratio:.0%}) — cloned page?")
                result['score'] += 0.3
            elif ratio > 0.5:
                result['score'] += 0.1

        # JS tricks
        if 'onmouseover' in html or 'window.status' in html:
            result['has_right_click_disable'] = True
            result['issues'].append("JS status bar manipulation detected")
            result['score'] += 0.15

        if 'preventdefault' in html.lower() or 'contextmenu' in html.lower():
            result['has_right_click_disable'] = True
            result['issues'].append("Right-click disabled via JS")
            result['score'] += 0.15

        if 'window.open' in html and html.lower().count('window.open') > 2:
            result['has_popup'] = True
            result['issues'].append("Multiple popup windows opened via JS")
            result['score'] += 0.1

        # Obfuscated JS (heavy eval / unescape / atob use)
        obf_count = html.count('eval(') + html.count('unescape(') + html.count('atob(')
        if obf_count > 3:
            result['has_obfuscated_js'] = True
            result['issues'].append(f"Obfuscated JavaScript detected ({obf_count} decoders)")
            result['score'] += 0.25

        # Favicon from different domain
        fav_tags = soup.find_all('link', rel=lambda r: r and 'icon' in r)
        for tag in fav_tags:
            href = tag.get('href', '')
            if href.startswith('http'):
                fav_domain = tldextract.extract(href).registered_domain
                if fav_domain and fav_domain != base_domain:
                    result['favicon_different_domain'] = True
                    result['issues'].append("Favicon loaded from different domain")
                    result['score'] += 0.2

    except Exception as e:
        result['issues'].append(f"Page content check failed: {str(e)[:60]}")

    result['score'] = min(result['score'], 1.0)
    return result


# ─────────────────────────────────────────────────────────────
#  CHECK 8: ML model prediction
# ─────────────────────────────────────────────────────────────
def check_ml_model(url, parsed, whois_result, ssl_result, http_result, page_result):
    if model is None:
        return {'used': False, 'prediction': None, 'confidence': None, 'issues': [], 'score': 0.0}

    try:
        domain = parsed.netloc
        ext = tldextract.extract(url)
        age = whois_result.get('domain_age_days', -1)

        features = np.array([
            1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else -1,          # UsingIP
            1 if len(url) > 75 else (-1 if len(url) < 54 else 0),           # LongURL
            1 if any(s in url.lower() for s in SHORTENERS) else -1,         # ShortURL
            1 if '@' in url else -1,                                         # Symbol@
            1 if '//' in parsed.path else -1,                                # Redirecting//
            -1 if '-' in domain else 1,                                      # PrefixSuffix-
            1 if len(domain.split('.')) > 2 else -1,                         # SubDomains
            1 if parsed.scheme == 'https' else -1,                           # HTTPS
            -1 if len(domain) < 253 else 1,                                  # DomainRegLen
            1 if page_result.get('favicon_different_domain') else -1,        # Favicon
            1 if parsed.port not in (80, 443, None) else -1,                 # NonStdPort
            1 if 'https' in domain else -1,                                  # HTTPSDomainURL
            1 if page_result.get('external_resource_ratio', 0) > 0.5 else -1, # RequestURL
            1 if page_result.get('external_resource_ratio', 0) > 0.5 else -1, # AnchorURL
            -1,                                                               # LinksInScriptTags
            1 if page_result.get('form_count', 0) > 0 else -1,              # ServerFormHandler
            -1,                                                               # InfoEmail
            1 if page_result.get('external_form_action') else -1,           # AbnormalURL
            1 if http_result.get('redirect_count', 0) > 1 else -1,          # WebsiteForwarding
            1 if page_result.get('has_right_click_disable') else -1,        # StatusBarCust
            1 if page_result.get('has_right_click_disable') else -1,        # DisableRightClick
            1 if page_result.get('has_popup') else -1,                      # UsingPopupWindow
            1 if page_result.get('iframe_count', 0) > 0 else -1,            # IframeRedirection
            1 if age > 180 else -1,                                          # AgeofDomain
            -1,                                                               # DNSRecording
            -1,                                                               # WebsiteTraffic
            -1,                                                               # PageRank
            -1,                                                               # GoogleIndex
            -1,                                                               # LinksPointingToPage
            -1,                                                               # StatsReport
        ]).reshape(1, -1)

        pred = model.predict(features)[0]
        proba = model.predict_proba(features)[0]
        confidence = float(proba[1]) if pred == 1 else float(proba[0])

        issues = []
        ml_score = 0.0
        if pred == 1:
            issues.append(f"ML model flagged as phishing (confidence: {confidence:.0%})")
            ml_score = confidence

        return {
            'used': True,
            'prediction': int(pred),
            'confidence': round(confidence, 3),
            'issues': issues,
            'score': min(ml_score, 1.0),
        }
    except Exception as e:
        return {'used': False, 'prediction': None, 'confidence': None, 'issues': [], 'score': 0.0}


# ─────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/check_url', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        raw_url = (data.get('url') or '').strip()

        if not raw_url:
            return _err("URL cannot be empty"), 400

        # Normalise
        url = raw_url
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        url = re.sub(r'/+$', '', url)

        # Quick parse
        parsed = urlparse(url)
        if not parsed.netloc:
            return _err("Invalid URL (no host)"), 400
        if parsed.scheme not in ('http', 'https'):
            return _err("Only http/https URLs are supported"), 400

        ext  = tldextract.extract(url)
        domain       = parsed.netloc.split(':')[0]
        base_domain  = ext.registered_domain or domain
        domain_name  = ext.domain or domain

        # ── Early TLD validation ─────────────────────────────
        # If tldextract found no suffix, the domain has no valid TLD at all
        if not ext.suffix:
            return jsonify({
                'status': 'success',
                'message': 'URL analysis complete',
                'details': {
                    'url': url,
                    'is_safe': False,
                    'analysis_status': 'dangerous',
                    'risk_score': 0.92,
                    'risk_factors': [
                        'No valid TLD — not a real domain',
                        'Domain does not resolve',
                        'No SSL/HTTPS possible',
                        'No WHOIS record exists',
                    ],
                    'detection_methods': ['URL Structure Analysis', 'Domain Validation'],
                    'domain_age': 'Unknown',
                    'has_ssl': False,
                    'checks': {
                        'url_structure': {'score': 0.9, 'issues': ['No valid TLD — not a real domain']},
                        'typosquatting':  {'score': 0.0, 'issues': []},
                        'whois':  {'score': 1.0, 'domain_age_days': -1, 'registrar': None, 'expiry_days': None, 'privacy_protected': False, 'issues': ['No WHOIS record (invalid domain)']},
                        'ssl':    {'score': 1.0, 'has_ssl': False, 'cert_valid': False, 'cert_issuer': None, 'cert_expiry_days': None, 'san_match': False, 'issues': ['No SSL (invalid domain)']},
                        'dns':    {'score': 1.0, 'resolves': False, 'ip_addresses': [], 'has_mx': False, 'has_spf': False, 'has_dmarc': False, 'issues': ['Domain does not resolve']},
                        'http':   {'score': 1.0, 'status_code': None, 'redirect_count': 0, 'final_url': url, 'server': None, 'security_headers': {}, 'issues': ['Unreachable (invalid domain)']},
                        'page_content': {'score': 0.0, 'has_password_field': False, 'form_count': 0, 'external_form_action': False, 'iframe_count': 0, 'external_resource_ratio': 0.0, 'has_obfuscated_js': False, 'issues': []},
                        'ml_model': {'score': 0.0, 'used': False, 'confidence': None, 'issues': []},
                    }
                }
            })

        # ── Instant checks (no network) ─────────────────────
        struct_result = check_url_structure(url, parsed, ext)
        typo_result   = check_typosquatting(domain_name, base_domain)

        # ── Known safe fast-pass ─────────────────────────────
        if base_domain in KNOWN_SAFE:
            return jsonify(_safe_response(url, base_domain, struct_result, typo_result))

        # ── Parallel network checks ─────────────────────────
        results = {}
        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = {
                'whois':   pool.submit(check_whois, base_domain),
                'ssl':     pool.submit(check_ssl, url, parsed),
                'dns':     pool.submit(check_dns, domain),
                'http':    pool.submit(check_http, url),
                'content': pool.submit(check_page_content, url, parsed),
            }
            for name, fut in futs.items():
                try:
                    results[name] = fut.result(timeout=12)
                except FuturesTimeout:
                    results[name] = {'issues': [f'{name} check timed out'], 'score': 0.1}
                except Exception as e:
                    results[name] = {'issues': [f'{name} check error: {e}'], 'score': 0.0}

        whois_r   = results['whois']
        ssl_r     = results['ssl']
        dns_r     = results['dns']
        http_r    = results['http']
        content_r = results['content']

        # ── ML model (uses outputs of other checks) ─────────
        ml_r = check_ml_model(url, parsed, whois_r, ssl_r, http_r, content_r)

        # ── Weighted risk aggregation ────────────────────────
        #   Weights reflect how reliable each signal is
        WEIGHTS = {
            'structure': 0.15,
            'typo':      0.12,
            'whois':     0.15,
            'ssl':       0.15,
            'dns':       0.10,
            'http':      0.10,
            'content':   0.15,
            'ml':        0.08,
        }
        scores = {
            'structure': struct_result['score'],
            'typo':      typo_result['score'],
            'whois':     whois_r.get('score', 0.0),
            'ssl':       ssl_r.get('score', 0.0),
            'dns':       dns_r.get('score', 0.0),
            'http':      http_r.get('score', 0.0),
            'content':   content_r.get('score', 0.0),
            'ml':        ml_r.get('score', 0.0),
        }
        risk_score = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)
        risk_score = min(risk_score / sum(WEIGHTS.values()), 1.0)

        # ── Hard-floor overrides (weighted average can't dilute critical failures) ──
        dns_fail   = not dns_r.get('resolves', True)
        whois_fail = not whois_r.get('domain_age_days', 0) and whois_r.get('score', 0) >= 0.4
        ssl_fail   = ssl_r.get('score', 0) >= 0.4

        if dns_fail and whois_fail:
            # Domain doesn't exist in DNS AND has no WHOIS → definitely not legit
            risk_score = max(risk_score, 0.80)
        elif dns_fail:
            # Can't resolve = extremely suspicious
            risk_score = max(risk_score, 0.68)
        elif whois_fail and ssl_fail:
            # No WHOIS + bad SSL = very suspicious
            risk_score = max(risk_score, 0.62)

        # ── Collect all issues ────────────────────────────────
        all_issues = (
            struct_result['issues'] +
            typo_result['issues'] +
            whois_r.get('issues', []) +
            ssl_r.get('issues', []) +
            dns_r.get('issues', []) +
            http_r.get('issues', []) +
            content_r.get('issues', []) +
            ml_r.get('issues', [])
        )

        # ── Detection methods used ───────────────────────────
        detection_methods = ['URL Structure Analysis', 'Domain Reputation']
        if whois_r.get('domain_age_days', -1) >= 0:
            detection_methods.append('WHOIS / Domain Age')
        if ssl_r.get('has_ssl') is not None:
            detection_methods.append('SSL Certificate')
        if dns_r.get('resolves'):
            detection_methods.append('DNS Analysis')
        if http_r.get('status_code'):
            detection_methods.append('HTTP Headers & Redirects')
        if content_r.get('form_count', 0) >= 0:
            detection_methods.append('Page Content Analysis')
        if ml_r.get('used'):
            detection_methods.append('Machine Learning Model')
        if typo_result['issues']:
            detection_methods.append('Typosquatting Detection')

        # ── Status ───────────────────────────────────────────
        if risk_score < 0.25:
            status = 'safe'
        elif risk_score < 0.50:
            status = 'suspicious'
        else:
            status = 'dangerous'

        domain_age = whois_r.get('domain_age_days', -1)

        return jsonify({
            'status': 'success',
            'message': 'URL analysis complete',
            'details': {
                'url': url,
                'is_safe': status == 'safe',
                'analysis_status': status,
                'risk_score': round(risk_score, 3),
                'risk_factors': all_issues,
                'detection_methods': detection_methods,
                'domain_age': f"{domain_age} days" if domain_age > 0 else "Unknown",
                'has_ssl': ssl_r.get('has_ssl', False),
                # Extended fields for the UI
                'checks': {
                    'url_structure': {
                        'score': round(scores['structure'], 3),
                        'issues': struct_result['issues'],
                    },
                    'typosquatting': {
                        'score': round(scores['typo'], 3),
                        'issues': typo_result['issues'],
                    },
                    'whois': {
                        'score': round(scores['whois'], 3),
                        'domain_age_days': whois_r.get('domain_age_days', -1),
                        'registrar': whois_r.get('registrar'),
                        'expiry_days': whois_r.get('expiry_days'),
                        'privacy_protected': whois_r.get('privacy_protected', False),
                        'issues': whois_r.get('issues', []),
                    },
                    'ssl': {
                        'score': round(scores['ssl'], 3),
                        'has_ssl': ssl_r.get('has_ssl', False),
                        'cert_valid': ssl_r.get('cert_valid', False),
                        'cert_issuer': ssl_r.get('cert_issuer'),
                        'cert_expiry_days': ssl_r.get('cert_expiry_days'),
                        'san_match': ssl_r.get('san_match'),
                        'issues': ssl_r.get('issues', []),
                    },
                    'dns': {
                        'score': round(scores['dns'], 3),
                        'resolves': dns_r.get('resolves', False),
                        'ip_addresses': dns_r.get('ip_addresses', []),
                        'has_mx': dns_r.get('has_mx', False),
                        'has_spf': dns_r.get('has_spf', False),
                        'has_dmarc': dns_r.get('has_dmarc', False),
                        'issues': dns_r.get('issues', []),
                    },
                    'http': {
                        'score': round(scores['http'], 3),
                        'status_code': http_r.get('status_code'),
                        'redirect_count': http_r.get('redirect_count', 0),
                        'final_url': http_r.get('final_url', url),
                        'server': http_r.get('server'),
                        'security_headers': http_r.get('security_headers', {}),
                        'issues': http_r.get('issues', []),
                    },
                    'page_content': {
                        'score': round(scores['content'], 3),
                        'has_password_field': content_r.get('has_password_field', False),
                        'form_count': content_r.get('form_count', 0),
                        'external_form_action': content_r.get('external_form_action', False),
                        'iframe_count': content_r.get('iframe_count', 0),
                        'external_resource_ratio': content_r.get('external_resource_ratio', 0.0),
                        'has_obfuscated_js': content_r.get('has_obfuscated_js', False),
                        'issues': content_r.get('issues', []),
                    },
                    'ml_model': {
                        'score': round(scores['ml'], 3),
                        'used': ml_r.get('used', False),
                        'confidence': ml_r.get('confidence'),
                        'issues': ml_r.get('issues', []),
                    },
                },
            }
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return _err(str(e)), 500


def _err(msg):
    return jsonify({
        'status': 'error',
        'message': msg,
        'details': {
            'is_safe': False, 'risk_score': 1.0,
            'risk_factors': [msg], 'detection_methods': [],
            'domain_age': 'Unknown', 'has_ssl': False,
            'analysis_status': 'dangerous', 'url': '',
        }
    })


def _safe_response(url, base_domain, struct_result, typo_result):
    """Fast-path response for known-safe domains."""
    return {
        'status': 'success',
        'message': 'URL analysis complete',
        'details': {
            'url': url,
            'is_safe': True,
            'analysis_status': 'safe',
            'risk_score': 0.05,
            'risk_factors': [],
            'detection_methods': ['Domain Reputation (Known Safe)'],
            'domain_age': 'Established domain',
            'has_ssl': True,
            'checks': {
                'url_structure': {'score': struct_result['score'], 'issues': struct_result['issues']},
                'typosquatting':  {'score': 0.0, 'issues': []},
                'whois':  {'score': 0.0, 'domain_age_days': -1, 'registrar': None, 'expiry_days': None, 'privacy_protected': False, 'issues': []},
                'ssl':    {'score': 0.0, 'has_ssl': True, 'cert_valid': True, 'cert_issuer': None, 'cert_expiry_days': None, 'san_match': True, 'issues': []},
                'dns':    {'score': 0.0, 'resolves': True, 'ip_addresses': [], 'has_mx': True, 'has_spf': True, 'has_dmarc': True, 'issues': []},
                'http':   {'score': 0.0, 'status_code': 200, 'redirect_count': 0, 'final_url': url, 'server': None, 'security_headers': {}, 'issues': []},
                'page_content': {'score': 0.0, 'has_password_field': False, 'form_count': 0, 'external_form_action': False, 'iframe_count': 0, 'external_resource_ratio': 0.0, 'has_obfuscated_js': False, 'issues': []},
                'ml_model': {'score': 0.0, 'used': False, 'confidence': None, 'issues': []},
            }
        }
    }


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)