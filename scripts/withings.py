#!/usr/bin/env python3
"""Holt die Gewichtsmessungen von Withings und legt sie verschlüsselt für die App ab.

Befehle:
  python scripts/withings.py fetch                       # regelmäßiger Abruf (GitHub Actions)
  python scripts/withings.py auth "<callback-url>"       # einmalige Freigabe: Code gegen Zugang tauschen
  python scripts/withings.py newkey                      # neuen STATE_KEY erzeugen

Umgebungsvariablen (als GitHub-Secrets hinterlegt):
  WITHINGS_CLIENT_ID, WITHINGS_CLIENT_SECRET  – aus dem Withings Developer Dashboard
  STATE_KEY                                   – verschlüsselt den Withings-Zugang im Repository
  DASHBOARD_PASSWORD                          – Passwort, mit dem die App die Daten entschlüsselt
"""
import base64
import datetime as dt
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / "state" / "token.enc"
HEARTBEAT_FILE = ROOT / "state" / "heartbeat.txt"
DATA_FILE = ROOT / "site" / "data.enc.json"
CONFIG_FILE = ROOT / "config.json"
API = "https://wbsapi.withings.net"
TZ = ZoneInfo("Europe/Berlin")
PBKDF2_ITER = 310_000


def env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"Fehlende Einstellung: {name}")
    return value


def output(key: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as f:
            f.write(f"{key}={value}\n")


# ---------- Withings-API ----------

def call(path: str, params: dict, token: str | None = None) -> dict:
    req = urllib.request.Request(API + path, data=urllib.parse.urlencode(params).encode(), method="POST")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                body = json.load(res)
            break
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == 2:
                raise RuntimeError(f"Withings nicht erreichbar: {e}") from e
            time.sleep(3 * (attempt + 1))
    status = body.get("status")
    if status != 0:
        raise RuntimeError(f"Withings {path} antwortet mit Status {status}: {body.get('error', '')}")
    return body["body"]


# ---------- Zugang (verschlüsselt im Repository) ----------

def load_state() -> dict:
    return json.loads(Fernet(env("STATE_KEY")).decrypt(STATE_FILE.read_bytes()))


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(exist_ok=True)
    STATE_FILE.write_bytes(Fernet(env("STATE_KEY")).encrypt(json.dumps(state).encode()))


def state_from(body: dict) -> dict:
    return {
        "access_token": body["access_token"],
        "refresh_token": body["refresh_token"],
        "expires_at": int(time.time()) + int(body["expires_in"]),
        "userid": str(body.get("userid", "")),
    }


def access_token() -> str:
    state = load_state()
    if state["expires_at"] - time.time() > 15 * 60:
        return state["access_token"]
    body = call("/v2/oauth2", {
        "action": "requesttoken",
        "grant_type": "refresh_token",
        "client_id": env("WITHINGS_CLIENT_ID"),
        "client_secret": env("WITHINGS_CLIENT_SECRET"),
        "refresh_token": state["refresh_token"],
    })
    state = state_from(body)
    save_state(state)  # sofort sichern: der alte Refresh-Token ist ab jetzt ungültig
    print("Zugang erneuert")
    return state["access_token"]


# ---------- Messungen ----------

def fetch_measurements(token: str) -> list[dict]:
    raw, offset = [], None
    while True:
        params = {"action": "getmeas", "meastype": "1", "category": "1"}
        if offset:
            params["offset"] = str(offset)
        body = call("/measure", params, token)
        for grp in body.get("measuregrps", []):
            for m in grp.get("measures", []):
                if m.get("type") == 1:
                    raw.append((int(grp["date"]), m["value"] * 10 ** m["unit"]))
        if body.get("more") and body.get("offset"):
            offset = body["offset"]
        else:
            break
    # Pro Tag die erste Messung (morgens nüchtern), deutsche Zeit
    per_day: dict[str, tuple[int, float]] = {}
    for ts, kg in sorted(raw):
        day = dt.datetime.fromtimestamp(ts, TZ).date().isoformat()
        per_day.setdefault(day, (ts, kg))
    return [
        {"datum": day, "zeit": dt.datetime.fromtimestamp(ts, TZ).strftime("%H:%M"), "gewicht_kg": round(kg, 2)}
        for day, (ts, kg) in sorted(per_day.items())
    ]


# ---------- Verschlüsselung für die App (AES-GCM, Schlüssel aus Passwort) ----------

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def derive(password: str, salt: bytes, iterations: int) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(password.encode())


def encrypt(obj: dict, password: str) -> dict:
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive(password, salt, PBKDF2_ITER)).encrypt(iv, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(), None)
    return {"v": 1, "iter": PBKDF2_ITER, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}


def decrypt(file: dict, password: str) -> dict:
    key = derive(password, base64.b64decode(file["salt"]), int(file["iter"]))
    return json.loads(AESGCM(key).decrypt(base64.b64decode(file["iv"]), base64.b64decode(file["ct"]), None))


def write_data(payload: dict) -> bool:
    """Schreibt nur, wenn sich Inhalt oder Passwort geändert haben (sonst kein Commit)."""
    password = env("DASHBOARD_PASSWORD")
    if DATA_FILE.exists():
        try:
            if decrypt(json.loads(DATA_FILE.read_text()), password) == payload:
                return False
        except Exception:
            pass  # Passwort geändert oder Datei beschädigt -> neu schreiben
    DATA_FILE.write_text(json.dumps(encrypt(payload, password)) + "\n")
    return True


def config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except FileNotFoundError:
        return {}


def keep_alive() -> None:
    """GitHub pausiert geplante Abläufe nach 60 Tagen ohne Aktivität. Vorher ein Lebenszeichen setzen."""
    try:
        last = int(subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=ROOT, capture_output=True, text=True).stdout.strip() or 0)
    except Exception:
        return
    if last and time.time() - last > 40 * 86400:
        HEARTBEAT_FILE.write_text(dt.datetime.now(TZ).isoformat(timespec="minutes") + "\n")
        print("Lebenszeichen gesetzt")


# ---------- Befehle ----------

def cmd_fetch() -> None:
    token = access_token()
    messungen = fetch_measurements(token)
    payload = {"messungen": messungen, "einstellungen": config()}
    changed = write_data(payload)
    print(f"{len(messungen)} Tage mit Messung, letzte: {messungen[-1]['datum'] if messungen else '–'}; neu: {changed}")
    output("changed", "true" if changed else "false")
    if not changed:
        keep_alive()


def cmd_auth(callback_url: str) -> None:
    parsed = urllib.parse.urlparse(callback_url.strip())
    query = urllib.parse.parse_qs(parsed.query)
    if "code" not in query:
        sys.exit("In der Adresse steht kein code=…")
    redirect_uri = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    body = call("/v2/oauth2", {
        "action": "requesttoken",
        "grant_type": "authorization_code",
        "client_id": env("WITHINGS_CLIENT_ID"),
        "client_secret": env("WITHINGS_CLIENT_SECRET"),
        "code": query["code"][0],
        "redirect_uri": redirect_uri,
    })
    save_state(state_from(body))
    print("Withings verbunden.")


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "fetch"
    if cmd == "fetch":
        cmd_fetch()
    elif cmd == "auth" and len(sys.argv) > 2:
        cmd_auth(sys.argv[2])
    elif cmd == "newkey":
        print(Fernet.generate_key().decode())
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
