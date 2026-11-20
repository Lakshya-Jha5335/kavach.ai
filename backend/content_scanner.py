from urllib.parse import urlparse
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import httpx

OFFICIAL_DOMAINS = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
    "google": ["google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "login.live.com"],
    "gov": ["gov.in", "nic.in"],
}

TRAINING_TEXTS = [
    "verify your bank account immediately suspended kyc update pan card otp password",
    "urgent security alert confirm your login credentials to avoid account block",
    "congratulations you won lottery prize claim reward enter upi pin card details",
    "official government portal income tax refund claim enter netbanking password",
    "university student portal login enter roll number password fee payment urgent",
    "welcome to our documentation engineering blog tutorials and open source projects",
    "read latest news articles technology weather sports and science updates",
    "shop electronics books clothing with free delivery and easy returns",
    "about us contact our support team privacy policy terms of service",
    "course syllabus lecture notes academic calendar and faculty directory",
]
TRAINING_LABELS = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]

_vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
_X = _vectorizer.fit_transform(TRAINING_TEXTS)
_clf = LogisticRegression()
_clf.fit(_X, TRAINING_LABELS)


async def analyze_page_content(url: str) -> dict:
    target = url if url.startswith(("http://", "https://")) else f"https://{url}"
    domain = urlparse(target).netloc.split(":")[0].lower()
    flags = []
    deduction = 0

    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(target)
            html = resp.text
    except Exception as e:
        return {"error": f"Could not fetch page content: {e}", "deduction": 0, "flags": []}

    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"
    forms = soup.find_all("form")
    password_inputs = soup.find_all("input", {"type": "password"})
    visible_text = " ".join(soup.stripped_strings)[:2000]
    combined_text = f"{title} {visible_text}".lower()

    vec = _vectorizer.transform([combined_text])
    phish_prob = float(_clf.predict_proba(vec)[0][1])
    is_phishing_text = phish_prob >= 0.65

    if is_phishing_text:
        flags.append(f"AI NLP model flagged credential-harvesting language ({phish_prob:.0%} confidence)")
        deduction += 25

    impersonated_brand = None
    for brand, valid_domains in OFFICIAL_DOMAINS.items():
        if brand in combined_text:
            if not any(domain == vd or domain.endswith(f".{vd}") for vd in valid_domains):
                impersonated_brand = brand.upper()
                flags.append(
                    f"Brand impersonation suspected: mentions '{impersonated_brand}' on unofficial domain '{domain}'"
                )
                deduction += 35
                break

    if password_inputs:
        flags.append(f"Page contains {len(password_inputs)} password input field(s)")
        deduction += 10

    return {
        "title": title,
        "form_count": len(forms),
        "password_field_count": len(password_inputs),
        "ai_analysis": {
            "model": "Local TF-IDF + LogisticRegression",
            "phishing_probability": round(phish_prob, 3),
            "impersonating": impersonated_brand is not None,
            "target_brand": impersonated_brand,
        },
        "deduction": deduction,
        "flags": flags,
    }