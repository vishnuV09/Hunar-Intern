"""
Flask Web Application for Password Strength Checker Dashboard
"""

from flask import Flask, render_template, request, jsonify
from password_checker import PasswordAnalyzer

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze_password():
    data = request.get_json() or {}
    password = data.get("password", "")
    analyzer = PasswordAnalyzer(password)
    result = analyzer.analyze()
    return jsonify(result)


@app.route("/api/generate", methods=["POST"])
def generate_password():
    data = request.get_json() or {}
    length = int(data.get("length", 16))
    include_symbols = bool(data.get("include_symbols", True))
    
    password = PasswordAnalyzer.generate_strong_password(length=length, include_symbols=include_symbols)
    analyzer = PasswordAnalyzer(password)
    result = analyzer.analyze()
    return jsonify({"generated_password": password, "analysis": result})


import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

if __name__ == "__main__":
    print("[*] Starting Password Strength Checker Web App on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
