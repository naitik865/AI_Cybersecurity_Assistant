from urllib.parse import urlparse
import re


def extract_features(url):

    # Auto-add HTTPS if missing (helps with urlparse netloc extraction)
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Dataset bias normalization:
    # Almost all legitimate domains in the training set start with 'www.' (2 dots, 1 subdomain).
    # Bare domains (like 'google.com') split into 2 parts (1 dot, 0 subdomains).
    # If the domain is a bare domain (2 parts, no www), we normalize it to 'www.' to prevent the model
    # from overfitting to the absence of 'www.' for legitimate domains.
    parts = domain.split('.')
    if len(parts) == 2 and not parts[0].startswith('www'):
        new_netloc = 'www.' + parsed.netloc
        url = url.replace(parsed.netloc, new_netloc, 1)
        parsed = urlparse(url)

    features = []

    # 1. URL Length
    url_length = len(url)
    features.append(url_length)

    # 2. Number of dots
    dot_count = url.count('.')
    features.append(dot_count)

    # 3. HTTPS presence
    https = 1 if parsed.scheme == 'https' else 0
    features.append(https)

    # 4. Special characters count (Optimized to ignore @ in paths like YouTube channels)
    authority_special_chars = len(re.findall(r'[@]', parsed.netloc))
    path_query_special_chars = len(re.findall(r'[?&=%]', url))
    special_char_count = authority_special_chars + path_query_special_chars
    features.append(special_char_count)

    # 5. IP Address presence (Fixed regex)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    has_ip = 1 if re.search(ip_pattern, url) else 0
    features.append(has_ip)

    # 6. Hyphen count
    hyphen_count = url.count('-')
    features.append(hyphen_count)

    # 7. Digit count
    digit_count = sum(c.isdigit() for c in url)
    features.append(digit_count)

    # 8. Suspicious keywords
    suspicious_keywords = [
        'login',
        'verify',
        'secure',
        'account',
        'update',
        'banking',
        'paypal',
        'signin',
        'password'
    ]

    keyword_flag = 0

    for word in suspicious_keywords:
        if word in url.lower():
            keyword_flag = 1
            break

    features.append(keyword_flag)

    # 9. Subdomain count
    subdomain_count = len(parsed.netloc.split('.')) - 2

    if subdomain_count < 0:
        subdomain_count = 0

    features.append(subdomain_count)

    # 10. URL shortening service
    shortening_services = [
        'bit.ly',
        'tinyurl',
        'goo.gl',
        't.co'
    ]

    shortener_flag = 0
    
    # Extract just the domain (e.g., 'www.lenskart.com' or 'lenskart.com')
    domain = parsed.netloc.lower()

    for service in shortening_services:
        # Only flag if the domain IS the shortener, or ends with it (like www.t.co)
        if domain == service or domain.endswith('.' + service):
            shortener_flag = 1
            break

    features.append(shortener_flag)

    return features