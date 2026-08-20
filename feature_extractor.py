import re
import requests
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from datetime import datetime

class FeatureExtractor:

    SUSPICIOUS_DOMAINS = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
    ]

    KNOWN_MALICIOUS = [
        "testsafebrowsing.appspot.com", "go2jump.org",
        "cpabounty.go2jump.org", "malware.wicar.org",
        "phishtank.com", "eicar.org",
    ]

    PHISHING_KEYWORDS = [
        "verify", "suspended", "urgent", "confirm", "login-secure",
        "banking", "paypal", "amazon-", "apple-id", "free-gift",
        "claim-now", "you-won", "kyc", "otp", "aadhar", "pan-verify",
        "refund", "phishing", "malware", "update-account",
    ]

    GAMBLING_KEYWORDS = [
        "betway", "bet365", "poker", "casino", "slots",
        "lottery", "jackpot", "winning", "prize", "gamble",
    ]

    TRUSTED_DOMAINS = [
        "google.com", "youtube.com", "github.com", "wikipedia.org",
        "microsoft.com", "apple.com", "amazon.com", "linkedin.com",
        "twitter.com", "instagram.com", "facebook.com",
    ]

    def extract(self, url: str, source_app: str = "unknown",
                unknown_sender: bool = False) -> dict:
        features = {}
        url_lower = url.lower()
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # ── Signal 1: URL Structure Analysis ─────────────────────────
        features["is_shortener"] = int(
            any(s in url_lower for s in self.SUSPICIOUS_DOMAINS))
        features["is_known_malicious"] = int(
            any(m in url_lower for m in self.KNOWN_MALICIOUS))
        features["has_phishing_keyword"] = int(
            any(k in url_lower for k in self.PHISHING_KEYWORDS))
        features["has_gambling_keyword"] = int(
            any(k in url_lower for k in self.GAMBLING_KEYWORDS))
        features["is_trusted_domain"] = int(
            any(t in url_lower for t in self.TRUSTED_DOMAINS))
        features["url_length"] = min(len(url) / 200.0, 1.0)
        features["has_ip_address"] = int(
            bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain)))
        features["has_at_symbol"] = int("@" in url)
        features["has_double_slash"] = int(url.count("//") > 1)
        features["subdomain_count"] = min(domain.count(".") / 5.0, 1.0)
        features["has_https"] = int(url.startswith("https://"))
        features["has_suspicious_tld"] = int(
            any(domain.endswith(t) for t in [
                ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                ".top", ".click", ".download", ".loan"]))

        # ── Signal 2: Sender Trust ────────────────────────────────────
        features["unknown_sender"] = int(unknown_sender)
        features["from_messaging_app"] = int(
            any(app in source_app for app in [
                "whatsapp", "telegram", "instagram", "sms"]))

        # ── Signal 3: HTML Analysis ───────────────────────────────────
        html_features = self._analyze_html(url)
        features.update(html_features)

        # ── Signal 4: Domain Age ──────────────────────────────────────
        features["domain_age_score"] = self._get_domain_age_score(domain)

        return features

    def _analyze_html(self, url: str) -> dict:
        result = {
            "has_password_field": 0,
            "has_hidden_fields": 0,
            "has_suspicious_js": 0,
            "external_links_ratio": 0.0,
            "has_favicon_mismatch": 0,
            "page_load_failed": 0,
        }
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, timeout=4, headers=headers,
                                allow_redirects=True)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Password fields
            result["has_password_field"] = int(
                bool(soup.find("input", {"type": "password"})))

            # Hidden fields
            hidden = soup.find_all("input", {"type": "hidden"})
            result["has_hidden_fields"] = int(len(hidden) > 3)

            # Suspicious JS patterns
            scripts = " ".join(
                s.string or "" for s in soup.find_all("script"))
            suspicious_js = [
                "eval(", "document.write(", "window.location",
                "unescape(", "fromCharCode", "atob(",
            ]
            result["has_suspicious_js"] = int(
                any(p in scripts for p in suspicious_js))

            # External links ratio
            all_links = soup.find_all("a", href=True)
            if all_links:
                parsed_host = urlparse(url).netloc
                external = sum(
                    1 for a in all_links
                    if parsed_host not in a["href"]
                    and a["href"].startswith("http")
                )
                result["external_links_ratio"] = min(
                    external / len(all_links), 1.0)

        except Exception:
            result["page_load_failed"] = 1

        return result

    def _get_domain_age_score(self, domain: str) -> float:
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                age_days = (datetime.now() - creation).days
                # New domain (< 30 days) = suspicious score 1.0
                # Old domain (> 365 days) = safe score 0.0
                return max(0.0, 1.0 - (age_days / 365.0))
        except Exception:
            pass
        return 0.5  # unknown = neutral
