import re
import urllib.parse
import tldextract
import numpy as np

SUSPICIOUS_WORDS = [
    'login','signin','bank','update','confirm','secure','account',
    'webscr','ebayisapi','verify','password','authenticate','paypal'
]

# Map reason keywords to possible attacks, prevention tips, and OSI layers
ATTACK_MAPPING = {
    "Long URL": (
        "Phishing / URL spoofing",
        "Avoid clicking suspicious links; verify URL length and domain.",
        "Application Layer"
    ),
    "Long path": (
        "Path-based attacks",
        "Limit URL length; check for unusual paths.",
        "Application Layer"
    ),
    "@": (
        "Phishing / Credential harvesting",
        "Do not trust URLs with '@'; verify domain.",
        "Application Layer"
    ),
    "Hyphen in domain": (
        "Phishing / Brand impersonation",
        "Verify domain spelling; avoid suspicious hyphens.",
        "Application Layer"
    ),
    "Suspicious word": (
        "Phishing / Credential theft",
        "Do not enter credentials on suspicious sites.",
        "Application Layer"
    ),
    "IP address used as host": (
        "Direct IP attacks / Malware",
        "Use domain names; avoid direct IP access.",
        "Network Layer"
    ),
    "Many subdomains": (
        "Subdomain takeover / phishing",
        "Check certificate and domain authenticity.",
        "Application Layer"
    ),
    "High character entropy": (
        "Obfuscated URL / Malware",
        "Be cautious with random-looking URLs; scan before visiting.",
        "Application Layer"
    )
}

def has_ip(host: str) -> bool:
    """Check if the host is an IP address."""
    host_only = host.split(':')[0]
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host_only))

def extract_url_parts(url: str):
    """Extract domain, subdomain, path, query from a URL."""
    if not url.startswith(('http://', 'https://')):
        url_to_parse = 'http://' + url
    else:
        url_to_parse = url

    parsed = urllib.parse.urlparse(url_to_parse)
    ext = tldextract.extract(parsed.netloc)
    domain = ext.domain + ('.' + ext.suffix if ext.suffix else '')
    subdomain = ext.subdomain or ''
    return {
        'full': url_to_parse,
        'host': parsed.netloc or '',
        'domain': domain,
        'subdomain': subdomain,
        'path': parsed.path or '',
        'query': parsed.query or ''
    }

def heuristic_score(url: str):
    """Score a URL based on heuristic rules."""
    parts = extract_url_parts(url)
    full = parts['full'].lower()
    host = parts['host']

    score = 0
    reasons = []

    if len(full) > 75:
        score += 1
        reasons.append("Long URL (>75 chars)")
    if len(parts['path']) > 50:
        score += 1
        reasons.append("Long path (>50 chars)")
    if '@' in full:
        score += 1
        reasons.append("Contains '@' (often used in obfuscation)")
    if '-' in parts['domain']:
        score += 1
        reasons.append("Hyphen in domain (may be suspicious)")

    for w in SUSPICIOUS_WORDS:
        if w in full:
            score += 2
            reasons.append(f"Suspicious word found: '{w}'")
            break

    if has_ip(host):
        score += 2
        reasons.append("IP address used as host")

    if parts['subdomain'] and parts['subdomain'].count('.') >= 2:
        score += 1
        reasons.append("Many subdomains")

    if len(full) > 0:
        vals, counts = np.unique(list(full), return_counts=True)
        probs = counts / counts.sum()
        entropy = -np.sum(probs * np.log2(probs))
        if entropy > 4.0:
            score += 1
            reasons.append("High character entropy (looks random/obfuscated)")

    return int(score), reasons

def classify_url(url: str):
    """Classify a URL and return details."""
    score, reasons = heuristic_score(url)
    label = "🔴 Malicious" if score >= 3 else "🟢 safe"

    attack_types = []
    prevention_tips = []
    osi_layers = []

    for r in reasons:
        for key, (attack, prevention, layer) in ATTACK_MAPPING.items():
            if key.lower() in r.lower():
                attack_types.append(attack)
                prevention_tips.append(prevention)
                osi_layers.append(layer)

    attack_types = "; ".join(list(set(attack_types))) or "N/A"
    prevention_tips = "; ".join(list(set(prevention_tips))) or "N/A"
    osi_layers = "; ".join(list(set(osi_layers))) or "N/A"

    return label, score, reasons, attack_types, prevention_tips, osi_layers
