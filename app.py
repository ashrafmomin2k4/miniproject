import os
import hashlib
import json
import tempfile
from datetime import datetime
from typing import Dict, Any

from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

from scanner.analyzer import analyze_apk

# App config
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), "apk_scans")
ALLOWED_EXTENSIONS = {"apk"}
MAX_CONTENT_LENGTH = 150 * 1024 * 1024  # 150MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def sha256_file(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def load_blacklist() -> Dict[str, Any]:
    data_path = os.path.join(os.path.dirname(__file__), "data", "blacklist.json")
    if os.path.exists(data_path):
        with open(data_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"sha256": []}


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
    if "file" not in request.files:
        flash("No file part in the request.", "error")
        return redirect(url_for("index"))

    upload = request.files["file"]
    if upload.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    if not allowed_file(upload.filename):
        flash("Unsupported file type. Please upload an .apk file.", "error")
        return redirect(url_for("index"))

    filename = secure_filename(upload.filename)
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{timestamp}_{filename}")
    upload.save(temp_path)

    try:
        file_hash = sha256_file(temp_path)
        blacklist = load_blacklist()
        is_blacklisted = file_hash in set(blacklist.get("sha256", []))

        analysis = analyze_apk(temp_path)
        analysis["sha256"] = file_hash
        analysis["is_blacklisted"] = is_blacklisted

        # Final classification adjustment if blacklisted
        if is_blacklisted:
            analysis["classification"] = "Malicious"
            analysis["score_breakdown"].append({
                "label": "Blacklist match",
                "weight": 100,
                "reason": "SHA256 matched known malware"
            })
            analysis["risk_score"] = max(analysis.get("risk_score", 0), 100)

        return render_template("result.html", result=analysis)
    except Exception as e:
        flash(f"Failed to analyze APK: {e}", "error")
        return redirect(url_for("index"))
    finally:
        # Cleanup uploaded file
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
