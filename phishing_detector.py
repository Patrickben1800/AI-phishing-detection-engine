import re
import socket
from collections import Counter
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


class PhishingDetector:
    """Lightweight phishing detector combining URL heuristics and text classification."""

    def __init__(self) -> None:
        self.text_model = self._build_text_model()
        self.suspicious_tlds = {
            "tk",
            "ml",
            "ga",
            "cf",
            "gq",
            "xyz",
            "top",
            "work",
            "support",
        }
        self.suspicious_keywords = {
            "login",
            "verify",
            "account",
            "password",
            "update",
            "gift",
            "prize",
            "bank",
            "secure",
            "wallet",
            "credential",
            "invoice",
            "helpdesk",
        }

    def _build_text_model(self) -> Pipeline:
        """Train a compact TF-IDF + LogisticRegression model on seed phrases."""

        phishing_samples = [
            "verify your account now",
            "update billing information",
            "login secure bank account",
            "your password will expire soon",
            "confirm your wallet by clicking the link",
            "we detected unusual activity",
            "claim your prize now",
            "reset your account immediately",
            "invoice needs your confirmation",
        ]

        benign_samples = [
            "welcome to our official website",
            "read the latest blog post about security",
            "download the product documentation",
            "contact support for assistance",
            "view your dashboard and analytics",
            "learn more about our company",
            "privacy policy and terms of service",
            "developer guide and api reference",
            "news and updates from the team",
        ]

        corpus = phishing_samples + benign_samples
        labels = [1] * len(phishing_samples) + [0] * len(benign_samples)

        model = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(ngram_range=(1, 2), min_df=1, stop_words="english"),
                ),
                ("clf", LogisticRegression(max_iter=500)),
            ]
        )
        model.fit(corpus, labels)
        return model

    def fetch_page(self, url: str) -> Tuple[str, str]:
        """Fetch page content and return raw HTML and extracted visible text."""

        response = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        html = response.text

        soup = BeautifulSoup(html, "html.parser")

        for element in soup(["script", "style", "noscript", "template"]):
            element.decompose()

        texts = [chunk.strip() for chunk in soup.stripped_strings if chunk.strip()]
        visible_text = " ".join(texts[:1200])
        return html, visible_text

    def analyze_url(self, url: str) -> Dict[str, float]:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        hostname = parsed.hostname or ""

        has_ip = self._is_ip(hostname)
        num_dots = hostname.count(".")
        num_hyphens = hostname.count("-")
        has_at = "@" in url
        is_https = parsed.scheme == "https"
        url_length = len(url)
        path_length = len(parsed.path)
        query_length = len(parsed.query)
        digit_ratio = sum(char.isdigit() for char in hostname) / max(len(hostname), 1)
        tld_suspicious = ext.suffix.split(".")[-1] in self.suspicious_tlds if ext.suffix else False
        keyword_hits = sum(1 for kw in self.suspicious_keywords if kw in url.lower())

        score = 0.0
        score += 0.3 if has_ip else 0
        score += 0.15 if num_dots >= 3 else 0
        score += 0.1 if num_hyphens >= 2 else 0
        score += 0.05 if has_at else 0
        score += 0.15 if not is_https else 0
        score += 0.1 if url_length > 80 else 0
        score += 0.05 if path_length > 40 else 0
        score += 0.05 if query_length > 60 else 0
        score += 0.1 if digit_ratio > 0.25 else 0
        score += 0.1 if tld_suspicious else 0
        score += min(0.2, 0.05 * keyword_hits)

        return {
            "score": min(score, 1.0),
            "has_ip": float(has_ip),
            "num_dots": float(num_dots),
            "num_hyphens": float(num_hyphens),
            "has_at": float(has_at),
            "is_https": float(is_https),
            "url_length": float(url_length),
            "path_length": float(path_length),
            "query_length": float(query_length),
            "digit_ratio": digit_ratio,
            "tld_suspicious": float(tld_suspicious),
            "keyword_hits": float(keyword_hits),
        }

    def analyze_html(self, html: str, page_text: str, hostname: str) -> Dict[str, float]:
        lower_html = html.lower()
        lower_text = page_text.lower()
        brand_tokens = {token for token in re.findall(r"[a-zA-Z]{4,}", hostname)}
        text_tokens = Counter(re.findall(r"[a-zA-Z]{4,}", lower_text))

        external_forms = re.findall(r"<form[^>]+action=\"(http[^\"]+)\"", lower_html)
        encoded_scripts = re.findall(r"(eval\(|base64|fromcharcode)", lower_html)
        iframe_count = lower_html.count("<iframe")

        brand_mismatch = False
        if brand_tokens:
            common = sum(text_tokens[token] for token in brand_tokens if token in text_tokens)
            brand_mismatch = common == 0 and ("login" in lower_text or "account" in lower_text)

        suspicious_keywords = sum(1 for kw in self.suspicious_keywords if kw in lower_text)

        score = 0.0
        score += 0.1 if external_forms else 0
        score += 0.1 if encoded_scripts else 0
        score += 0.05 if iframe_count > 0 else 0
        score += 0.1 if brand_mismatch else 0
        score += min(0.2, 0.04 * suspicious_keywords)

        return {
            "score": min(score, 1.0),
            "external_forms": float(len(external_forms)),
            "encoded_scripts": float(len(encoded_scripts)),
            "iframe_count": float(iframe_count),
            "brand_mismatch": float(brand_mismatch),
            "suspicious_keywords": float(suspicious_keywords),
        }

    def predict(self, url: str) -> Dict[str, object]:
        url_data = self.analyze_url(url)
        html, text = self.fetch_page(url)
        html_data = self.analyze_html(html, text, urlparse(url).hostname or "")

        text_proba = float(self.text_model.predict_proba([text])[0][1])

        combined_score = 0.5 * url_data["score"] + 0.3 * html_data["score"] + 0.2 * text_proba
        verdict = "phishing" if combined_score >= 0.5 else "legitimate"

        reasons = self._collect_reasons(url_data, html_data, text_proba)

        return {
            "verdict": verdict,
            "combined_score": round(combined_score, 3),
            "url_features": url_data,
            "html_features": html_data,
            "text_probability": round(text_proba, 3),
            "page_excerpt": text[:8000],
            "reasons": reasons,
        }

    def _collect_reasons(
        self, url_data: Dict[str, float], html_data: Dict[str, float], text_proba: float
    ) -> List[str]:
        reasons = []
        if url_data["has_ip"]:
            reasons.append("URL uses a raw IP address.")
        if url_data["num_dots"] >= 3:
            reasons.append("URL has many subdomains.")
        if url_data["num_hyphens"] >= 2:
            reasons.append("URL contains multiple hyphens.")
        if url_data["has_at"]:
            reasons.append("URL contains an @ symbol (possible redirection).")
        if not url_data["is_https"]:
            reasons.append("Site does not use HTTPS.")
        if url_data["tld_suspicious"]:
            reasons.append("Uncommon or free top-level domain.")
        if url_data["keyword_hits"]:
            reasons.append("URL contains urgency or credential keywords.")
        if html_data["external_forms"]:
            reasons.append("Form posts to an external domain.")
        if html_data["encoded_scripts"]:
            reasons.append("Obfuscated scripts detected.")
        if html_data["iframe_count"]:
            reasons.append("Uses iframes, which phishers often abuse.")
        if html_data["brand_mismatch"]:
            reasons.append("Brand names in text do not match the domain.")
        if html_data["suspicious_keywords"]:
            reasons.append("Page text contains phishing-related keywords.")
        if text_proba > 0.6:
            reasons.append("AI text model finds the content similar to phishing pages.")
        elif text_proba < 0.25:
            reasons.append("AI text model finds the content similar to legitimate sites.")
        return reasons

    @staticmethod
    def _is_ip(hostname: str) -> bool:
        try:
            socket.inet_aton(hostname)
            return True
        except OSError:
            return False


detector = PhishingDetector()


__all__ = ["detector", "PhishingDetector"]
