import re

def check_ip_address(url):
    pattern = r'http[s]?://\d+\.\d+\.\d+\.\d+'
    return re.search(pattern, url) is not None


def check_suspicious_keywords(url):
    keywords = ["login", "verify", "secure", "account", "update", "bank"]
    for word in keywords:
        if word in url.lower():
            return True
    return False


def check_too_many_dots(url):
    return url.count('.') > 3


def normalize_url(url):
    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "@": "a"
    }

    normalized = url.lower()
    for fake, real in replacements.items():
        normalized = normalized.replace(fake, real)

    return normalized


def extract_domain(url):
    url = url.replace("https://", "").replace("http://", "")
    domain = url.split("/")[0]

    parts = domain.split(".")

    # Get last 2 parts (root domain)
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    
    return domain


def check_fake_brands(url):
    brands = ["paypal.com", "google.com", "amazon.com", "apple.com"]

    normalized_url = normalize_url(url)
    domain = extract_domain(normalized_url)

    for brand in brands:
        if brand.split(".")[0] in domain:
            if domain != brand:
                return True
    return False


def check_typosquatting(url):
    suspicious_patterns = ["0", "1", "3", "@"]

    domain = extract_domain(url.lower())

    # Skip if it's an IP address
    if domain.replace(".", "").isdigit():
        return False

    for char in suspicious_patterns:
        if char in domain:
            return True
    return False


def check_url_shortener(url):
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]

    for s in shorteners:
        if s in url.lower():
            return True
    return False


def check_subdomain_trick(url):
    brands = ["paypal", "google", "amazon", "apple", "bank"]

    url_clean = url.replace("https://", "").replace("http://", "")
    domain_parts = url_clean.split("/")[0].split(".")

    root_domain = extract_domain(url)

    for brand in brands:
        if brand in url.lower() and brand not in root_domain:
            return True

    return False


def analyze_url(url):
    print("\n" + "="*40)
    print("🔍 PHISHING ANALYSIS REPORT")
    print("="*40)

    print(f"URL: {url}\n")

    score = 0
    reasons = []

    if check_ip_address(url):
        reasons.append("Uses IP address instead of domain")
        score += 40

    if check_suspicious_keywords(url):
        reasons.append("Contains suspicious keywords")
        score += 10

    if check_too_many_dots(url):
        reasons.append("Too many subdomains")
        score += 15

    if check_typosquatting(url):
        reasons.append("Possible typosquatting")
        score += 50

    if check_fake_brands(url):
        reasons.append("Brand impersonation detected")
        score += 40

    if check_subdomain_trick(url):
        reasons.append("Fake subdomain trick detected")
        score += 40

    if check_url_shortener(url):
        reasons.append("Uses URL shortener")
        score += 20

    score = min(score, 100)

    if score < 20:
        risk = "LOW"
    elif score < 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    print(f"Risk Score: {score}/100")
    print(f"Risk Level: {risk}\n")

    print("Indicators:")
    if reasons:
        for r in reasons:
            print(f" - {r}")
    else:
        print(" - None")

    print("\nConclusion:")
    if risk == "HIGH":
        print(" 🚨 This URL is likely a phishing attempt. Avoid interacting with it.")
    elif risk == "MEDIUM":
        print(" ⚠️ This URL is suspicious. Proceed with caution.")
    else:
        print(" ✅ This URL appears safe.")

    print("="*40)


# Test URLs
urls = [
    "https://google.com",
    "http://192.168.1.1/login",
    "https://secure-login-paypal.com.verify-user.ru",
    "https://amazon.com",
    "https://g00gle.com",
    "https://apple.verify-account-security.com",
    "https://bit.ly/3fakeLogin"
]

for url in urls:
    analyze_url(url)

