import re
from urllib.parse import urlparse


GOV_IN_SUFFIXES = (
    ".gov.in",
    ".nic.in",
    ".mil.in",
    ".ac.in",
    ".edu.in",
    ".res.in",
    ".सरकार.भारत",
    ".sarkar.bharat"
)

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".zip", ".mov", ".click", ".live", ".mom", ".cam",
    ".gq", ".tk", ".cf", ".ml", ".work", ".link"
}

COMMON_MISSPELLINGS = {
    "urgnet", "urgant", "urgnt", "urg3nt",
    "verfy", "verifiy", "verfication",
    "acount", "accunt", "acc0unt",
    "pasword", "passwrod", "passw0rd",
    "secirity", "securty", "suspiciuos",
    "immediatly", "immidiately"
}

ADVANCE_FEE_KEYWORDS = [
    "minister", "inheritance", "inherit", "late father", "beneficiary",
    "funds", "deposit", "transfer", "lottery", "claim", "compensation",
    "investment", "percentage", "urgent assistance", "global trust",
    "security company", "ghana", "nigeria", "guinea bissau"
]


def extract_urls(text: str) -> list[str]:
    return re.findall(r"(https?://[^\s]+)", text, flags=re.IGNORECASE)


def extract_domain_like(text: str) -> list[str]:
    # captures tokens like www.example.com or example.com/path
    return re.findall(r"\b(?:www\.)[^\s]+|\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}[^\s]*", text)


def normalize_domain(host: str) -> str:
    host = host.lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host


def looks_like_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def invalid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return True
    if host.startswith("-") or host.endswith("-"):
        return True
    if ".." in host:
        return True
    if not re.match(r"^[a-z0-9.-]+$", host):
        return True
    if "." not in host:
        return True
    tld = host.rsplit(".", 1)[-1]
    if len(tld) < 2:
        return True
    return False


def has_invalid_url(message: str) -> bool:
    urls = extract_urls(message)
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
        if invalid_host(host):
            return True

    # also check domain-like tokens without scheme
    for token in extract_domain_like(message):
        normalized = token
        if not normalized.lower().startswith(("http://", "https://")):
            normalized = f"http://{normalized}"
        parsed = urlparse(normalized)
        host = (parsed.netloc or "").lower()
        if invalid_host(host):
            return True

    return False


def has_suspicious_tld(host: str) -> bool:
    return any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)


def is_gov_claim(text: str) -> bool:
    t = text.lower()
    return "gov" in t or "government" in t or "india" in t or "sarkar" in t


def gov_domain_mismatch(host: str) -> bool:
    return not any(host.endswith(suffix) for suffix in GOV_IN_SUFFIXES)


def gov_keyword_in_host(host: str) -> bool:
    return any(keyword in host for keyword in ("gov", "nic", "india", "sarkar"))


def has_misspelling(text: str) -> bool:
    words = re.findall(r"[a-zA-Z0-9]+", text.lower())
    return any(word in COMMON_MISSPELLINGS for word in words)

def advance_fee_scam(text: str) -> bool:
    t = text.lower()
    hits = sum(1 for k in ADVANCE_FEE_KEYWORDS if k in t)
    return hits >= 2


def evaluate_threat_rules(message: str) -> dict | None:
    if has_invalid_url(message):
        return {"verdict": "BLOCK", "action": "block", "reason": "invalid_url"}

    urls = extract_urls(message)
    domain_like = extract_domain_like(message)
    candidates = urls + domain_like

    for raw in candidates:
        url = raw
        if not url.lower().startswith(("http://", "https://")):
            url = f"http://{url}"
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
        if url.lower().startswith("http://"):
            return {"verdict": "BLOCK", "action": "block", "reason": "http_url_block"}
        if "xn--" in host or looks_like_ip(host):
            return {"verdict": "BLOCK", "action": "block", "reason": "suspicious_url_host"}
        if has_suspicious_tld(host):
            return {"verdict": "BLOCK", "action": "block", "reason": "suspicious_tld"}
        if (is_gov_claim(message) or gov_keyword_in_host(host)) and gov_domain_mismatch(host):
            return {"verdict": "BLOCK", "action": "block", "reason": "gov_domain_mismatch"}

    if advance_fee_scam(message):
        return {"verdict": "BLOCK", "action": "block", "reason": "advance_fee_scam"}

    if has_misspelling(message):
        return {"verdict": "BLOCK", "action": "block", "reason": "spelling_anomaly"}

    return None
