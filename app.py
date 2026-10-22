import os
import hmac
from flask import Flask, jsonify, request

app = Flask(__name__)
TOKEN = os.environ.get("REMOTE_TOKEN", "")

@app.get("/")
def home():
    return "API du terminal distant"

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

@app.get("/api/ping")
def ping():
    auth = request.headers.get("Authorization", "")
    expected = f"Bearer {TOKEN}"

    if not TOKEN or not hmac.compare_digest(auth, expected):
        return jsonify({"error": "Non autorisé"}), 401

    return jsonify({
        "status": "connected",
        "message": "Le serveur Render répond."
    })
