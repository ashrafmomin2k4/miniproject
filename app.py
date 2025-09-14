import os
import json
import tempfile
import re
from datetime import datetime
from typing import Dict, Any
from urllib.parse import urlparse, urljoin
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

from scanner.analyzer import scan_website

# App config
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), "web_scans")
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")


def is_valid_url(url: str) -> bool:
    """Validate if the provided string is a valid URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def normalize_url(url: str) -> str:
    """Normalize URL by adding https:// if no scheme is provided."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/how-it-works")
def how_it_works():
    return render_template("how.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()
    
    if not url:
        flash("Please enter a URL to scan.", "error")
        return redirect(url_for("index"))

    # Normalize and validate URL
    url = normalize_url(url)
    if not is_valid_url(url):
        flash("Please enter a valid URL.", "error")
        return redirect(url_for("index"))

    try:
        # Perform web vulnerability scan
        scan_result = scan_website(url)
        scan_result["target_url"] = url
        scan_result["scan_time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        return render_template("result.html", result=scan_result)
    except Exception as e:
        flash(f"Failed to scan website: {str(e)}", "error")
        return redirect(url_for("index"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
