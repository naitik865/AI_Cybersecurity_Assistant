def generate_explanation(features):

    explanations = []

    # Feature values
    url_length = features[0]
    dot_count = features[1]
    https = features[2]
    special_chars = features[3]
    ip_address = features[4]
    hyphen_count = features[5]
    digit_count = features[6]
    suspicious_keywords = features[7]
    subdomains = features[8]
    shortener = features[9]

    # HTTPS
    if https == 1:
        explanations.append({
            'message': 'HTTPS detected → lowers phishing probability',
            'severity': 'safe'
        })
    else:
        explanations.append({
            'message': 'HTTP detected → insecure connection',
            'severity': 'danger'
        })

    # Suspicious keywords
    if suspicious_keywords == 1:
        explanations.append({
            'message': 'Suspicious phishing keywords detected in URL',
            'severity': 'danger'
        })

    # Hyphens
    if hyphen_count >= 2:
        explanations.append({
            'message': 'Multiple hyphens detected → common in fake domains',
            'severity': 'warning'
        })

    # IP Address
    if ip_address == 1:
        explanations.append({
            'message': 'IP address used instead of domain name',
            'severity': 'danger'
        })

    # URL shortener
    if shortener == 1:
        explanations.append({
            'message': 'URL shortening service detected',
            'severity': 'warning'
        })

    # Long URL
    if url_length > 50:
        explanations.append({
            'message': 'Very long URL detected → potentially suspicious',
            'severity': 'warning'
        })

    # Many dots
    if dot_count > 3:
        explanations.append({
            'message': 'Too many subdomains detected',
            'severity': 'warning'
        })

    # Digits
    if digit_count > 5:
        explanations.append({
            'message': 'High number of digits detected in URL',
            'severity': 'warning'
        })

    # Default safe message
    if len(explanations) == 1 and https == 1:
        explanations.append({
            'message': 'No major phishing indicators detected',
            'severity': 'safe'
        })

    return explanations