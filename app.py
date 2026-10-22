
import os
import hmac
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, g, make_response
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

TOKEN = os.environ.get("REMOTE_TOKEN", "")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() not in (
    "0", "false", "no"
)

# PostgreSQL sur Render ; SQLite uniquement pour les tests locaux.
db_url = os.environ.get("DATABASE_URL", "sqlite:///termin_all.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

db = SQLAlchemy(app)

SESSION_HOURS = 8
MAX_OUTPUT = 20000
ALLOWED_COMMANDS = {"hostname", "whoami", "pwd", "dir", "ipconfig"}


def utcnow():
    return datetime.utcnow()


class Task(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    stdout = db.Column(db.Text, nullable=False, default="")
    stderr = db.Column(db.Text, nullable=False, default="")
    return_code = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class AgentStatus(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    last_seen = db.Column(db.DateTime, nullable=False)


class WebSession(db.Model):
    # Seul le hash du cookie est conservé en base.
    id_hash = db.Column(db.String(64), primary_key=True)
    csrf_token = db.Column(db.String(100), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)


with app.app_context():
    db.create_all()


PAGE = r"""
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TERMIN-ALL</title>
<style>
* { box-sizing:border-box }
body {
  margin:0; background:#000; color:#b8ffb8;
  font:15px Consolas,"Courier New",monospace;
}
#screen { padding:12px; min-height:100vh; }
#output { white-space:pre-wrap; overflow-wrap:anywhere; }
.line { display:flex; align-items:baseline; gap:8px; }
input {
  min-width:0; flex:1; border:0; outline:0;
  background:#000; color:#b8ffb8;
  font:inherit; caret-color:#b8ffb8;
}
button {
  background:#000; border:1px solid #b8ffb8;
  color:#b8ffb8; font:inherit; padding:4px 8px;
}
button:focus,input:focus { outline:1px solid #b8ffb8 }
.dim { color:#6a9f6a }
.error { color:#ff7777 }
#status { margin-bottom:10px; }
#login { margin-top:20px; }
#main { display:none; }
pre { white-space:pre-wrap; }
</style>
</head>
<body>
<div id="screen">
<pre id="banner"> _____ _____ ____  __  __ ___ _   _
|_   _| ____|  _ \|  \/  |_ _| \ | |
  | | |  _| | |_) | |\/| || ||  \| |
  | | | |___|  _ <| |  | || || |\  |
  |_| |_____|_| \_\_|  |_|___|_| \_|

        REMOTE TERMINAL SYSTEM
        Secure connection required</pre>

<div id="login">
  <div id="loginMessage">REMOTE_TOKEN:</div>
  <form id="loginForm" class="line">
    <input id="secret" type="password" autocomplete="current-password"
           aria-label="Clé secrète" autofocus>
    <button type="submit">CONNECT</button>
  </form>
</div>

<div id="main">
  <div id="status" class="dim">SERVER: checking | AGENT: unknown</div>
  <div id="output"></div>
  <form id="commandForm" class="line">
    <span>TERMIN-ALL&gt;</span>
    <input id="command" autocomplete="off" spellcheck="false"
           aria-label="Commande" autofocus>
  </form>
</div>
</div>

<script>
let csrf = {{ csrf|tojson }};
const initialAuth = {{ authenticated|tojson }};
const login = document.getElementById("login");
const main = document.getElementById("main");
const output = document.getElementById("output");
const statusLine = document.getElementById("status");
const commandInput = document.getElementById("command");
let history = [];
let historyIndex = 0;

function line(text, cls="") {
  const div = document.createElement("div");
  if (cls) div.className = cls;
  div.textContent = text;
  output.appendChild(div);
  window.scrollTo(0, document.body.scrollHeight);
}

function showTerminal() {
  login.style.display = "none";
  main.style.display = "block";
  line("Session authentifiée.");
  line("Commandes autorisées : hostname, whoami, pwd, dir, ipconfig");
  line("Commandes locales : help, clear, logout");
  commandInput.focus();
  refreshStatus();
}

async function api(url, options={}) {
  options.credentials = "same-origin";
  options.headers = {
    ...(options.headers || {}),
    ...(options.method && options.method !== "GET"
      ? {"X-CSRF-Token": csrf} : {})
  };
  const response = await fetch(url, options);
  let data;
  try { data = await response.json(); }
  catch { throw new Error("Réponse serveur invalide (HTTP " + response.status + ")"); }
  if (response.status === 401) {
    logoutLocal();
    throw new Error("Session expirée ou non autorisée.");
  }
  if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
  return data;
}

function logoutLocal() {
  csrf = "";
  main.style.display = "none";
  login.style.display = "block";
  document.getElementById("secret").value = "";
  document.getElementById("loginMessage").textContent = "REMOTE_TOKEN:";
}

document.getElementById("loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const secret = document.getElementById("secret");
  const key = secret.value;
  secret.value = "";

  try {
    const response = await fetch("/login", {
      method:"POST",
      credentials:"same-origin",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({key})
    });
    const data = await response.json();
    if (!response.ok) {
      document.getElementById("loginMessage").textContent =
        response.status === 401 ? "ACCESS DENIED" : "CONNECTION FAILED";
      return;
    }
    csrf = data.csrf;
    showTerminal();
  } catch {
    document.getElementById("loginMessage").textContent = "CONNECTION FAILED";
  }
});

async function refreshStatus() {
  if (!csrf) return;
  try {
    const s = await api("/api/status");
    statusLine.textContent =
      "SERVER: online | AGENT: " + (s.agent_online ? "connected" : "offline");
    statusLine.className = s.agent_online ? "" : "error";
  } catch (e) {
    statusLine.textContent = "CONNECTION FAILED";
    statusLine.className = "error";
  }
}

async function waitForTask(id) {
  for (let i=0; i<90; i++) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    try {
      const task = await api("/api/commands/" + encodeURIComponent(id));
      if (task.status === "completed" || task.status === "failed") {
        if (task.stdout) line(task.stdout);
        if (task.stderr) line(task.stderr, "error");
        line("[exit code: " + task.return_code + "]");
        return;
      }
      statusLine.textContent = "SERVER: online | TASK: " + task.status;
    } catch (e) {
      line("Erreur : " + e.message, "error");
      return;
    }
  }
  line("Délai d'attente dépassé. Vérifie l'état de l'agent.", "error");
}

document.getElementById("commandForm").addEventListener("submit", async e => {
  e.preventDefault();
  const value = commandInput.value.trim().toLowerCase();
  commandInput.value = "";
  if (!value) return;

  history.push(value);
  historyIndex = history.length;
  line("TERMIN-ALL> " + value);

  if (value === "clear") {
    output.textContent = "";
    return;
  }
  if (value === "help") {
    line("Commandes autorisées : hostname, whoami, pwd, dir, ipconfig");
    line("Commandes locales : help, clear, logout");
    return;
  }
  if (value === "logout") {
    try {
      await api("/logout", {method:"POST"});
    } catch {}
    logoutLocal();
    return;
  }

  try {
    const result = await api("/api/commands", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({command:value})
    });
    line("[tâche " + result.id + " : " + result.status + "]");
    await waitForTask(result.id);
  } catch (e) {
    line("Erreur : " + e.message, "error");
  }
});

commandInput.addEventListener("keydown", e => {
  if (e.key === "ArrowUp" && historyIndex > 0) {
    historyIndex--;
    commandInput.value = history[historyIndex];
    e.preventDefault();
  } else if (e.key === "ArrowDown") {
    historyIndex = Math.min(historyIndex + 1, history.length);
    commandInput.value = history[historyIndex] || "";
    e.preventDefault();
  }
});

if (initialAuth) showTerminal();
setInterval(refreshStatus, 5000);
</script>
</body>
</html>
"""


def session_hash(raw_id):
    return hashlib.sha256(raw_id.encode("utf-8")).hexdigest()


def require_web(csrf=False):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            web_session = getattr(g, "web_session", None)
            if web_session is None:
                return jsonify(error="authentication_required"), 401

            if csrf:
                supplied = request.headers.get("X-CSRF-Token", "")
                if not supplied or not hmac.compare_digest(
                    supplied, web_session.csrf_token
                ):
                    return jsonify(error="csrf_failed"), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_agent(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not TOKEN:
            return jsonify(error="server_token_not_configured"), 503

        supplied = request.headers.get("Authorization", "")
        expected = "Bearer " + TOKEN

        if not hmac.compare_digest(supplied, expected):
            return jsonify(error="invalid_agent_token"), 401

        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def load_web_session():
    g.web_session = None
    raw_id = request.cookies.get("terminal_session", "")
    if not raw_id:
        return

    record = db.session.get(WebSession, session_hash(raw_id))
    if record is None:
        return

    if record.expires_at <= utcnow():
        db.session.delete(record)
        db.session.commit()
        return

    g.web_session = record


@app.get("/")
def index():
    current = getattr(g, "web_session", None)
    return render_template_string(
        PAGE,
        authenticated=current is not None,
        csrf=current.csrf_token if current else ""
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/login")
def login():
    if not TOKEN:
        return jsonify(error="server_token_not_configured"), 503

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("key"), str):
        return jsonify(error="invalid_request"), 400

    if not hmac.compare_digest(data["key"], TOKEN):
        return jsonify(error="access_denied"), 401

    raw_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    record = WebSession(
        id_hash=session_hash(raw_id),
        csrf_token=csrf_token,
        expires_at=utcnow() + timedelta(hours=SESSION_HOURS)
    )
    db.session.add(record)
    db.session.commit()

    response = make_response(jsonify(ok=True, csrf=csrf_token))
    response.set_cookie(
        "terminal_session",
        raw_id,
        max_age=SESSION_HOURS * 3600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="Strict",
        path="/"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/logout")
@require_web(csrf=True)
def logout():
    db.session.delete(g.web_session)
    db.session.commit()
    response = make_response(jsonify(ok=True))
    response.delete_cookie(
        "terminal_session", path="/",
        secure=COOKIE_SECURE, httponly=True, samesite="Strict"
    )
    return response


@app.get("/api/status")
@require_web()
def status():
    agent = db.session.get(AgentStatus, "windows-pc")
    online = bool(
        agent and (utcnow() - agent.last_seen).total_seconds() <= 35
    )
    return jsonify(
        server_online=True,
        agent_online=online,
        agent_last_seen=agent.last_seen.isoformat() if agent else None
    )


@app.post("/api/commands")
@require_web(csrf=True)
def create_command():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("command"), str):
        return jsonify(error="invalid_request"), 400

    name = data["command"].strip().lower()
    if name not in ALLOWED_COMMANDS:
        return jsonify(error="command_not_allowed"), 403

    task = Task(id=str(uuid.uuid4()), name=name, status="pending")
    db.session.add(task)
    db.session.commit()
    return jsonify(id=task.id, status=task.status), 201


@app.get("/api/commands/<task_id>")
@require_web()
def get_command(task_id):
    task = db.session.get(Task, task_id)
    if task is None:
        return jsonify(error="task_not_found"), 404

    return jsonify(
        id=task.id,
        command=task.name,
        status=task.status,
        stdout=task.stdout,
        stderr=task.stderr,
        return_code=task.return_code
    )


@app.post("/api/agent/heartbeat")
@require_agent
def agent_heartbeat():
    agent = db.session.get(AgentStatus, "windows-pc")
    if agent is None:
        agent = AgentStatus(id="windows-pc", last_seen=utcnow())
        db.session.add(agent)
    else:
        agent.last_seen = utcnow()

    db.session.commit()
    return jsonify(ok=True, agent="windows-pc")


@app.get("/api/agent/next")
@require_agent
def agent_next():
    # PostgreSQL verrouille la tâche sélectionnée pour éviter
    # qu'elle soit attribuée simultanément à deux agents.
    task = db.session.execute(
        db.select(Task)
        .where(Task.status == "pending")
        .order_by(Task.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    ).scalar_one_or_none()

    if task is None:
        return jsonify(task=None), 200

    task.status = "running"
    task.updated_at = utcnow()
    db.session.commit()

    return jsonify(task={"id": task.id, "name": task.name})


@app.post("/api/agent/result")
@require_agent
def agent_result():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="invalid_json"), 400

    task_id = data.get("id")
    stdout = data.get("stdout", "")
    stderr = data.get("stderr", "")
    return_code = data.get("return_code")

    if (
        not isinstance(task_id, str)
        or not isinstance(stdout, str)
        or not isinstance(stderr, str)
        or not isinstance(return_code, int)
        or isinstance(return_code, bool)
    ):
        return jsonify(error="invalid_fields"), 400

    task = db.session.get(Task, task_id)
    if task is None:
        return jsonify(error="task_not_found"), 404
    if task.status != "running":
        return jsonify(error="task_not_running"), 409

    task.stdout = stdout[:MAX_OUTPUT]
    task.stderr = stderr[:MAX_OUTPUT]
    task.return_code = return_code
    task.status = "completed" if return_code == 0 else "failed"
    task.updated_at = utcnow()
    db.session.commit()

    return jsonify(ok=True, id=task.id, status=task.status)


@app.errorhandler(404)
def not_found(_error):
    return jsonify(error="route_not_found"), 404


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="request_too_large"), 413


@app.errorhandler(500)
def server_error(_error):
    db.session.rollback()
    app.logger.exception("Erreur interne")
    return jsonify(error="internal_server_error"), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)
