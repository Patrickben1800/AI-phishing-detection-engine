# AI Phishing Detection Engine

A lightweight demo web app that scores URLs in real time by combining URL heuristics, HTML inspection, link analysis, and a compact AI text classifier.

## Features
- URL heuristics: IP-in-URL, subdomain depth, punycode/homoglyph, repeated characters, suspicious TLDs, keyword hits, and HTTPS usage.
- HTML checks: external form posts, obfuscated scripts, iframe usage, credential fields, and brand/name mismatches.
- Link + text alignment: counts external link domains, flags suspicious anchor text, and checks whether page brands/urgency/credential requests match the domain.
- AI text model: TF-IDF + logistic regression trained on seed phishing/benign phrases for fast similarity scoring over visible text scraped from the page.
- Web UI + JSON API for quick testing.

## Running locally
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the Flask app:
   ```bash
   python app.py
   ```
3. Open http://localhost:5000 and submit a URL to scan.

> Note: This is a demo tool. Do not rely on it for production security decisions.
