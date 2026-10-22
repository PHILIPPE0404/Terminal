
import os
import hmac
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

TOKEN = os.environ.get("REMOTE_TOKEN", "")

HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Terminal distant</title>
<style>
body {
    background: #111;
    color: #eee;
    font-family: Consolas, monospace;
    padding: 25px;
}
h2 { color: #4ade80; }
#terminal {
    background: #000;
    border: 1px solid #333;
    padding: 15px;
    height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    border-radius: 8px;
}
input {
    box-sizing: border-box;
    width: 80%;
    padding: 12px;
    background: #222;
    color: white;
    border: 1px solid #444;
}
button {
    padding: 12px;
    background: #4ade80;
    border: none;
    cursor: pointer;
}
</style>
</head>
<body>
<h2>Terminal distant</h2>
<div id="terminal">Terminal prêt.</div>
<br>
<input id="cmd" placeholder="Tape help, ping ou clear">
<button onclick="send()">Envoyer</button>

<script>
const terminal = document.getElementById("terminal");

function log(text) {
    terminal.textContent += "\\n" + text;
    terminal.scrollTop = terminal.scrollHeight;
}

async function send() {
    const input = document.getElementById("cmd");
    const cmd = input.value.trim().toLowerCase();
    input.value = "";

    if (!cmd) return;

    log("> " + cmd);

    if (cmd === "clear") {
        terminal.textContent = "Terminal prêt.";
    } else if (cmd === "help") {
        log("Commandes disponibles : help, ping, clear");
    } else if (cmd === "ping") {
        try {
            const r = await fetch("/api/ping");
            const data = await r.json();
            log(JSON.stringify(data));
        } catch (e) {
            log("Erreur : " + e.message);
        }
    } else {
        log("Commande inconnue. Tape help.");
    }
}

document.getElementById("cmd").addEventListener("keydown", e => {
    if (e.key === "Enter") send();
});
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/api/ping")
def ping():
    auth = request.headers.get("Authorization", "")
    expected = f"Bearer {TOKEN}"

    if not TOKEN or not hmac.compare_digest(auth, expected):
        return jsonify({"error": "Non autorisé"}), 401

    return jsonify({
        "status": "connected",
        "message": "Le serveur Render fonctionne"
    })

if __name__ == "__main__":
    app.run(debug=False)
