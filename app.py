from flask import Flask, render_template, request
import re

app = Flask(__name__)

# ---- Your existing functions ----

def check_ip_address(url):
    pattern = r'http[s]?://\d+\.\d+\.\d+\.\d+'
    return re.search(pattern, url) is not None

def check_suspicious_keywords(url):
    keywords = ["login", "verify", "secure", "account", "update", "bank"]
    return any(word in url.lower() for word in keywords)

def check_too_many_dots(url):
    return url.count('.') > 3

def normalize_url(url):
    replacements = {"0": "o", "1": "l", "3": "e", "@": "a"}
    normalized = url.lower()
    for fake, real in replacements.items():
        normalized = normalized.replace(fake, real)
    return normalized

def extract_domain(url):
    url = url.replace("https://", "").replace("http://", "")
    domain = url.split("/")[0]
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain

def check_typosquatting(url):
    domain = extract_domain(url.lower())
    if domain.replace(".", "").isdigit():
        return False
    return any(char in domain for char in ["0", "1", "3", "@"])

def check_fake_brands(url):
    brands = ["paypal.com", "google.com", "amazon.com", "apple.com"]
    normalized_url = normalize_url(url)
    domain = extract_domain(normalized_url)
    return any(brand.split(".")[0] in domain and domain != brand for brand in brands)

def check_subdomain_trick(url):
    brands = ["paypal", "google", "amazon", "apple", "bank"]
    root_domain = extract_domain(url)
    return any(brand in url.lower() and brand not in root_domain for brand in brands)

def check_url_shortener(url):
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
    return any(s in url.lower() for s in shorteners)

# ---- Analysis logic ----

def analyze(url):
    score = 0
    reasons = []

    if check_ip_address(url):
        reasons.append("Uses IP address")
        score += 40

    if check_suspicious_keywords(url):
        reasons.append("Suspicious keywords")
        score += 10

    if check_too_many_dots(url):
        reasons.append("Too many subdomains")
        score += 15

    if check_typosquatting(url):
        reasons.append("Typosquatting detected")
        score += 50

    if check_fake_brands(url):
        reasons.append("Brand impersonation")
        score += 40

    if check_subdomain_trick(url):
        reasons.append("Fake subdomain trick")
        score += 40

    if check_url_shortener(url):
        reasons.append("URL shortener used")
        score += 20

    score = min(score, 100)

    if score < 20:
        risk = "Low"
    elif score < 50:
        risk = "Medium"
    else:
        risk = "High"

    return score, risk, reasons

# ---- Routes ----

@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        url = request.form.get("url")
        score, risk, reasons = analyze(url)
        result = {
            "url": url,
            "score": score,
            "risk": risk,
            "reasons": reasons
        }

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)