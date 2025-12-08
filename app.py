from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

from phishing_detector import detector

app = Flask(__name__)


def normalize_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = f"https://{raw_url}"
    return raw_url


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw_url = request.form.get("url", "").strip()
        if not raw_url:
            return render_template("index.html", error="Please enter a URL."), 400

        try:
            normalized = normalize_url(raw_url)
            result = detector.predict(normalized)
            return render_template("index.html", result=result, url=normalized)
        except Exception as exc:  # pragma: no cover - shown to the user
            return (
                render_template(
                    "index.html",
                    error=f"Unable to analyze the URL: {exc}",
                    url=raw_url,
                ),
                400,
            )

    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(force=True, silent=True) or {}
    raw_url = str(data.get("url", "")).strip()
    if not raw_url:
        return jsonify({"error": "URL is required"}), 400

    try:
        normalized = normalize_url(raw_url)
        result = detector.predict(normalized)
        return jsonify({"url": normalized, **result})
    except Exception as exc:  # pragma: no cover
        return jsonify({"error": str(exc)}), 400


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
