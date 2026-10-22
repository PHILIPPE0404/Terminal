
import os
import hmac
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
SECRET_KEY = os.environ.get("REMOTE_TOKEN", "")

PAGE = r"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>CMD</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    background: #000;
    color: #fff;
    font: 16px Consolas, monospace;
}
#screen {
    padding: 10px;
    height: 100vh;
    overflow-y: auto;
    white-space: pre-wrap;
}
#line { display: flex; }
#prompt { white-space: pre; }
input {
    flex: 1;
    min-width: 0;
    background: transparent;
    color: white;
    border: 0;
    outline: none;
    font: inherit;
}
</style>
</head>
<body>
<div id="screen"><div>Microsoft Windows [Terminal distant]</div>
<div>Connexion protégée par clé secrète.</div>
<div id="output"></div>
<div id="line"><span id="prompt">Clé secrète : </span><input id="input" type="password" autofocus></div></div>
<script>
const input = document.getElementById("input");
const output = document.getElementById("output");
const prompt = document.getElementById("prompt");
let connected = false;
let key = "";

function print(text) {
    output.textContent += text + "\n";
    window.scrollTo(0, document.body.scrollHeight);
}

input.addEventListener("keydown", async e => {
    if (e.key !== "Enter") return;
    const value = input.value;
    input.value = "";

    if (!connected) {
        try {
            const r = await fetch("/api/auth", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({key: value})
            });
            const data = await r.json();
            if (!r.ok) {
                print("Clé incorrecte.");
                return;
            }
            key = value;
            connected = true;
            prompt.textContent = "C:\\\\Users\\\\PC> ";
            print("Connexion autorisée.");
        } catch {
            print("Erreur de connexion au serveur.");
        }
        return;
    }

    print(prompt.textContent + value);
    if (value.toLowerCase() === "cls") output.textContent = "";
    else if (value.toLowerCase() === "help") print("Commandes disponibles : help, cls");
    else print("Agent Windows non connecté ou commande indisponible.");
});
</script>
</body>
</html>
"""

@app.get("/")
def index():
    return render_template_string(PAGE)

@app.post("/api/auth")
def authenticate():
    supplied = request.get_json(silent=True) or {}
    key = supplied.get("key", "")

    if not SECRET_KEY or not isinstance(key, str):
        return jsonify({"error": "Non autorisé"}), 401

    if not hmac.compare_digest(key, SECRET_KEY):
        return jsonify({"error": "Non autorisé"}), 401

    return jsonify({"ok": True})

@app.get("/health")
def health():
    return jsonify({"status": "ok"})
