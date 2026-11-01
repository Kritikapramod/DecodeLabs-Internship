"""Local, string-only URL analysis. URLs are NEVER fetched or opened."""
import re, ipaddress, difflib
from urllib.parse import urlparse

_TLDS = "com|net|org|in|co|io|info|biz|top|xyz|click|icu|tk|ml|ga|cf|gq|work|loan|buzz|me|ly|app|online|site|shop|live|support|country|monster"
# 1) http(s):// or www. links, or 2) bare domains such as "paypal-login.top/verify" (never the domain part of an e-mail address)
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+|(?<![@\w./-])(?:[a-z0-9-]+\.)+(?:%s)\b(?![@\w-])(?:/[^\s<>\"']*)?" % _TLDS)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"}
RISKY_TLDS = {"xyz", "top", "click", "icu", "tk", "ml", "ga", "cf", "gq", "work", "zip", "loan", "country", "support", "buzz", "monster"}
SENSITIVE_WORDS = ("login", "signin", "verify", "secure", "update", "account", "password", "confirm", "reset", "claim")
# brand -> (aliases seen in text/hostnames, official registered domains)
BRANDS = {
    "HDFC Bank": (["hdfc", "hdfcbank"], ["hdfcbank.com"]), "SBI": (["sbi", "onlinesbi"], ["sbi.co.in", "onlinesbi.sbi"]),
    "PayPal": (["paypal"], ["paypal.com"]), "Amazon": (["amazon"], ["amazon.com", "amazon.in"]),
    "Microsoft": (["microsoft"], ["microsoft.com", "live.com", "office.com"]), "Apple": (["apple"], ["apple.com", "icloud.com"]),
    "Google": (["google"], ["google.com"]), "Netflix": (["netflix"], ["netflix.com"]),
    "DHL": (["dhl"], ["dhl.com"]), "FedEx": (["fedex"], ["fedex.com"]), "Paytm": (["paytm"], ["paytm.com"]),
}
IMPERSONATION_IDS = ("lookalike", "brand_domain")


def extract_urls(text, limit=20):
    """Find URLs in text, trim trailing punctuation, de-duplicate, keep order."""
    seen, out = set(), []
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?)]}'\"")
        if u.lower() not in seen:
            seen.add(u.lower()); out.append(u)
    return out[:limit]


def registered_domain(host):
    """Approximate registrable domain (handles co.uk / co.in style suffixes)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def find_brands(text):
    t = text.lower()
    return [b for b, (al, _) in BRANDS.items() if any(re.search(r"\b" + a + r"\b", t) for a in al)]


def _level(score):
    return "Low" if score < 10 else "Moderate" if score < 25 else "High" if score < 45 else "Critical"


def analyze_url(raw):
    ind = []
    def add(i, label, why, pts):
        ind.append({"id": i, "label": label, "why": why, "points": pts})
    given = raw.lower().startswith(("http://", "https://"))
    try:
        p = urlparse(raw if given else "http://" + raw)
        host, _ = (p.hostname or "").lower(), p.port
    except ValueError:
        p, host = urlparse(""), ""
        add("malformed", "Malformed URL", "The URL could not be parsed safely.", 10)
    reg = registered_domain(host)
    if given and p.scheme == "http":
        add("http", "HTTP instead of HTTPS", "Unencrypted; common on old sites, so weak evidence alone.", 6)
    try:
        ipaddress.ip_address(host); is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        add("ip", "IP address instead of domain", "Legitimate brands almost always use a named domain.", 28)
    elif host:
        name = reg.split(".")[0]
        if reg in SHORTENERS:
            add("shortener", "URL shortener", "The real destination is hidden.", 10)
        if len(host.split(".")) - len(reg.split(".")) >= 3:
            add("subdomains", "Excessive subdomains", "Deep subdomain chains can hide the true domain.", 8)
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            add("tld", "Frequently abused TLD", "Cheap TLDs are over-represented in phishing; many sites using them are harmless.", 8)
        if name.count("-") >= 2:
            add("hyphens", "Many hyphens in domain", "Long hyphenated names often imitate brands.", 5)
        if "xn--" in host:
            add("punycode", "Punycode / non-ASCII domain", "Can disguise lookalike characters.", 15)
        if "@" in p.netloc:
            add("at_sign", "'@' in URL", "Text before '@' is ignored by browsers and used to mislead.", 15)
        norm = name.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")
        look = None
        for b, (al, officials) in BRANDS.items():
            if reg in officials:
                look = False; break
            if any(name != c and (norm == c or difflib.SequenceMatcher(None, name, c).ratio() >= 0.86)
                   for c in (o.split(".")[0] for o in officials)):
                look = b; break
        if look:
            add("lookalike", "Lookalike of " + look, "The domain closely resembles %s's official domain." % look, 28)
        elif look is None:
            toks = re.split(r"[.\-_]", host)
            for b, (al, officials) in BRANDS.items():
                if any(t == a or (len(a) >= 5 and t.startswith(a)) for t in toks for a in al):
                    add("brand_domain", "Brand name in unofficial domain", "'%s' appears in a domain %s does not own." % (b, b), 25); break
    path = (p.path + "?" + p.query).lower()
    if any(w in path for w in SENSITIVE_WORDS):
        add("path_words", "Sensitive word in path", "Words like login/verify are typical of credential pages.", 4)
    if len(re.findall(r"%[0-9a-fA-F]{2}", raw)) >= 3:
        add("encoding", "Heavy percent-encoding", "Encoding can obscure the real address.", 5)
    if p.port not in (None, 80, 443):
        add("port", "Non-standard port", "Unusual for ordinary websites.", 6)
    if len(raw) > 100:
        add("long", "Very long URL", "Long URLs can hide the important part.", 3)
    score = sum(i["points"] for i in ind)
    if not ind:
        expl = "No suspicious structural indicators found. This does not prove the site is safe."
    elif len(ind) == 1:
        expl = "One indicator only (%s); on its own this is not proof of malicious intent." % ind[0]["label"]
    else:
        expl = "Combination of indicators: " + "; ".join(i["label"] for i in ind) + "."
    return {"url": raw, "domain": host or "(unparseable)", "registered": reg, "indicators": ind,
            "score": score, "risk_level": _level(score), "explanation": expl}
