"""
HDFC Securities InvestRight (IR) Open API proxy.

Backend proxy for a minimal order + LTP tool. Holds the multi-step login
session in memory (never persisted to disk), injects secrets from .env,
and forwards trading requests using the access token obtained at login.

Run: python app.py  (see README.md)
"""
import logging
import os
import threading
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

load_dotenv()

API_KEY = os.environ.get("HDFC_API_KEY", "")
API_SECRET = os.environ.get("HDFC_API_SECRET", "")
USERNAME = os.environ.get("HDFC_USERNAME", "")
PASSWORD = os.environ.get("HDFC_PASSWORD", "")
CONSENT = os.environ.get("HDFC_CONSENT", "Y")
BASE_URL = os.environ.get("HDFC_BASE_URL", "https://developer.hdfcsec.com/oapi/v1").rstrip("/")
USER_AGENT = os.environ.get(
    "HDFC_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
)
PORT = int(os.environ.get("PORT", "5000"))
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

REQUIRED_ENV = ["HDFC_API_KEY", "HDFC_API_SECRET", "HDFC_USERNAME", "HDFC_PASSWORD"]
_missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
if _missing:
    raise RuntimeError(
        "Missing required .env values: " + ", ".join(_missing) +
        " -- copy .env.example to .env and fill it in."
    )

# ---------------------------------------------------------------------------
# Logging: never print secret values. redact() scrubs any known secret
# string out of text before it is logged or returned to the browser.
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("hdfc-proxy")


def _secret_values():
    values = [API_KEY, API_SECRET, PASSWORD]
    token = SESSION.get("accessToken")
    if token:
        values.append(token)
    return [v for v in values if v]


def redact(text):
    text = str(text)
    for value in _secret_values():
        text = text.replace(value, "***REDACTED***")
    return text


# ---------------------------------------------------------------------------
# In-memory login session. Single-user tool: one global session object.
# Never written to disk, never logged in full.
# ---------------------------------------------------------------------------
SESSION = {
    "tokenId": None,       # from STEP 1 response: tokenId
    "requestToken": None,  # from STEP 3 response: requestToken (may be
                            # refreshed by STEP 5's response if it returns one)
    "accessToken": None,   # from STEP 6 response
    "loggedIn": False,
}
SESSION_LOCK = threading.Lock()

app = Flask(__name__, static_folder=None)


def hdfc_call(method, path, params=None, json_body=None, auth_token=None):
    """Call an HDFC IR endpoint. Returns (ok, status_code, parsed_json_or_text)."""
    url = f"{BASE_URL}{path}"
    headers = {"User-Agent": USER_AGENT}
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    if auth_token:
        # Curl samples send the raw access token as the Authorization
        # header value (no "Bearer " prefix). Adjust here if HDFC support
        # confirms a different scheme is required.
        headers["Authorization"] = auth_token

    try:
        resp = requests.request(
            method, url, params=params, json=json_body, headers=headers, timeout=20
        )
    except requests.exceptions.RequestException as exc:
        log.error("Upstream request to %s failed: %s", path, redact(str(exc)))
        return False, 502, {"error": "Upstream request failed", "detail": redact(str(exc))}

    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text}

    ok = 200 <= resp.status_code < 300
    if not ok:
        log.warning("HDFC %s %s returned %s", method, path, resp.status_code)
    return ok, resp.status_code, body


def find_field(body, candidates):
    """Case-sensitive lookup of the first matching key in a dict response."""
    if not isinstance(body, dict):
        return None
    for key in candidates:
        if key in body and body[key]:
            return body[key]
    return None


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    with SESSION_LOCK:
        return jsonify({"loggedIn": SESSION["loggedIn"]})


@app.route("/api/auth/start", methods=["POST"])
def auth_start():
    # STEP 1: GET /login?api_key=... -> { tokenId }
    ok, status, body = hdfc_call("GET", "/login", params={"api_key": API_KEY})
    if not ok:
        return jsonify({"error": "Step 1 (get token id) failed", "detail": body}), status

    token_id = find_field(body, ["tokenId", "token_id"])
    if not token_id:
        log.error("Step 1 response missing tokenId. Keys received: %s", list(body.keys()) if isinstance(body, dict) else type(body))
        return jsonify({"error": "Step 1 response did not contain a tokenId", "detail": body}), 502

    with SESSION_LOCK:
        SESSION["tokenId"] = token_id
        SESSION["requestToken"] = None
        SESSION["accessToken"] = None
        SESSION["loggedIn"] = False

    # STEP 2: POST /login/validate?api_key=...&token_id=... {username, password}
    ok, status, body = hdfc_call(
        "POST",
        "/login/validate",
        params={"api_key": API_KEY, "token_id": token_id},
        json_body={"username": USERNAME, "password": PASSWORD},
    )
    if not ok:
        return jsonify({"error": "Step 2 (login validate) failed", "detail": body}), status

    return jsonify({"status": "otp_required"})


@app.route("/api/auth/verify-otp", methods=["POST"])
def auth_verify_otp():
    data = request.get_json(silent=True) or {}
    otp = data.get("otp")
    if not otp:
        return jsonify({"error": "otp is required"}), 400

    with SESSION_LOCK:
        token_id = SESSION.get("tokenId")
    if not token_id:
        return jsonify({"error": "No login in progress. Call /api/auth/start first."}), 409

    # STEP 3: POST /twofa/validate?api_key=...&token_id=... {answer} -> { requestToken }
    ok, status, body = hdfc_call(
        "POST",
        "/twofa/validate",
        params={"api_key": API_KEY, "token_id": token_id},
        json_body={"answer": otp},
    )
    if not ok:
        return jsonify({"error": "Step 3 (validate OTP) failed", "detail": body}), status

    request_token = find_field(body, ["requestToken", "request_token"])
    if not request_token:
        log.error("Step 3 response missing requestToken. Keys received: %s", list(body.keys()) if isinstance(body, dict) else type(body))
        return jsonify({"error": "Step 3 response did not contain a requestToken", "detail": body}), 502

    with SESSION_LOCK:
        SESSION["requestToken"] = request_token

    # STEP 5: GET /authorise?api_key=...&token_id=...&consent=...&request_token=...
    ok, status, body = hdfc_call(
        "GET",
        "/authorise",
        params={
            "api_key": API_KEY,
            "token_id": token_id,
            "consent": CONSENT,
            "request_token": request_token,
        },
    )
    if not ok:
        return jsonify({"error": "Step 5 (authorise) failed", "detail": body}), status

    # Some HDFC deployments return a refreshed request_token from
    # authorise; if present, prefer it for Step 6. Otherwise keep the one
    # from Step 3. (No confirmed sample response for this step was
    # available at build time -- if Step 6 fails, check server logs for
    # "Step 5 response keys" and adjust find_field()'s candidate list.)
    refreshed_token = find_field(body, ["requestToken", "request_token"])
    if refreshed_token:
        log.info("Step 5 response included a request token field; using it for Step 6.")
        with SESSION_LOCK:
            SESSION["requestToken"] = refreshed_token
            request_token = refreshed_token
    else:
        log.info("Step 5 response had no request token field (keys: %s); reusing Step 3's token for Step 6.",
                  list(body.keys()) if isinstance(body, dict) else type(body))

    # STEP 6: POST /access-token?api_key=...&request_token=... {apiSecret} -> { accessToken }
    ok, status, body = hdfc_call(
        "POST",
        "/access-token",
        params={"api_key": API_KEY, "request_token": request_token},
        json_body={"apiSecret": API_SECRET},
    )
    if not ok:
        return jsonify({"error": "Step 6 (get access token) failed", "detail": body}), status

    access_token = find_field(body, ["accessToken", "access_token", "token"])
    if not access_token:
        log.error("Step 6 response missing access token. Keys received: %s", list(body.keys()) if isinstance(body, dict) else type(body))
        return jsonify({"error": "Step 6 response did not contain an access token", "detail": body}), 502

    with SESSION_LOCK:
        SESSION["accessToken"] = access_token
        SESSION["loggedIn"] = True

    log.info("Login complete.")
    return jsonify({"status": "logged_in"})


@app.route("/api/auth/resend-otp", methods=["POST"])
def auth_resend_otp():
    with SESSION_LOCK:
        token_id = SESSION.get("tokenId")
    if not token_id:
        return jsonify({"error": "No login in progress. Call /api/auth/start first."}), 409

    # STEP 4: GET /twofa/resend?api_key=...&token_id=...
    ok, status, body = hdfc_call(
        "GET", "/twofa/resend", params={"api_key": API_KEY, "token_id": token_id}
    )
    if not ok:
        return jsonify({"error": "Step 4 (resend OTP) failed", "detail": body}), status

    return jsonify({"status": "otp_resent"})


# ---------------------------------------------------------------------------
# Trading routes - require a completed login
# ---------------------------------------------------------------------------

def require_login():
    with SESSION_LOCK:
        if not SESSION["loggedIn"] or not SESSION["accessToken"]:
            return None
        return SESSION["accessToken"]


def dry_run_response(method, path, params, headers_preview, body):
    masked_params = dict(params or {})
    if "api_key" in masked_params:
        masked_params["api_key"] = "***REDACTED***"
    preview = {
        "method": method,
        "url": f"{BASE_URL}{path}",
        "params": masked_params,
        "headers": headers_preview,
        "body": body,
    }
    log.info("[DRY RUN] Would send: %s", preview)
    return {
        "dryRun": True,
        "wouldSend": preview,
        "order_id": f"DRYRUN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "message": "DRY RUN is ON - no live request was sent.",
    }


@app.route("/api/ltp", methods=["GET"])
def get_ltp():
    access_token = require_login()
    if not access_token:
        return jsonify({"error": "Not logged in"}), 401

    exchange = request.args.get("exchange", "NSE")
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "token query param is required (the HDFC security token, not a symbol name)"}), 400

    # HDFC's fetch-ltp endpoint is a PUT with a batch body; we wrap the
    # single exchange/token pair the UI collects into that shape.
    ok, status, body = hdfc_call(
        "PUT",
        "/fetch-ltp",
        params={"api_key": API_KEY},
        json_body={"data": [{"exchange": exchange, "token": token}]},
        auth_token=access_token,
    )
    if not ok:
        return jsonify({"error": "LTP fetch failed", "detail": body}), status
    return jsonify(body)


def validate_order_payload(data):
    errors = []
    for field in ("exchange", "security_id", "instrument_segment", "transaction_type", "product", "order_type", "validity"):
        if not str(data.get(field, "")).strip():
            errors.append(f"{field} is required")

    quantity = data.get("quantity")
    try:
        if int(quantity) <= 0:
            errors.append("quantity must be greater than 0")
    except (TypeError, ValueError):
        errors.append("quantity must be a whole number")

    order_type = str(data.get("order_type", "")).upper()
    price = data.get("price", 0) or 0
    trigger_price = data.get("trigger_price", 0) or 0

    if order_type in ("LIMIT", "SL"):
        try:
            if float(price) <= 0:
                errors.append("price is required for LIMIT/SL orders")
        except (TypeError, ValueError):
            errors.append("price must be a number")

    if order_type in ("SL", "SL-M"):
        try:
            if float(trigger_price) <= 0:
                errors.append("trigger_price is required for SL/SL-M orders")
        except (TypeError, ValueError):
            errors.append("trigger_price must be a number")

    return errors


@app.route("/api/order/place", methods=["POST"])
def place_order():
    access_token = require_login()
    if not access_token:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json(silent=True) or {}
    dry_run = bool(data.get("dryRun", True))

    errors = validate_order_payload(data)
    if errors:
        return jsonify({"error": "Validation failed", "detail": errors}), 400

    order_body = {
        "exchange": data["exchange"],
        "security_id": data["security_id"],
        "instrument_segment": data["instrument_segment"],
        "transaction_type": data["transaction_type"],
        "product": data["product"],
        "order_type": data["order_type"],
        "price": data.get("price", 0) or 0,
        "trigger_price": data.get("trigger_price", 0) or 0,
        "quantity": int(data["quantity"]),
        "disclosed_quantity": data.get("disclosed_quantity", 0) or 0,
        "validity": data["validity"],
        "amo": bool(data.get("amo", False)),
        "external_reference_number": data.get("external_reference_number"),
    }

    if dry_run:
        preview = dry_run_response(
            "POST", "/orders/regular", {"api_key": API_KEY},
            {"Authorization": "***REDACTED***", "Content-Type": "application/json"},
            order_body,
        )
        return jsonify(preview)

    ok, status, body = hdfc_call(
        "POST", "/orders/regular", params={"api_key": API_KEY},
        json_body=order_body, auth_token=access_token,
    )
    if not ok:
        return jsonify({"error": "Place order failed", "detail": body}), status
    return jsonify(body)


@app.route("/api/order/modify", methods=["POST"])
def modify_order():
    access_token = require_login()
    if not access_token:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json(silent=True) or {}
    dry_run = bool(data.get("dryRun", True))

    order_id = str(data.get("order_id", "")).strip()
    if not order_id:
        return jsonify({"error": "order_id is required"}), 400

    try:
        quantity = int(data.get("quantity"))
        if quantity <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "quantity must be a whole number greater than 0"}), 400

    order_type = str(data.get("order_type", "")).upper()
    price = data.get("price", 0) or 0
    trigger_price = data.get("trigger_price", 0) or 0
    if order_type in ("LIMIT", "SL") and float(price or 0) <= 0:
        return jsonify({"error": "price is required for LIMIT/SL orders"}), 400
    if order_type in ("SL", "SL-M") and float(trigger_price or 0) <= 0:
        return jsonify({"error": "trigger_price is required for SL/SL-M orders"}), 400

    modify_body = {
        "quantity": quantity,
        "order_type": data.get("order_type"),
        "validity": data.get("validity"),
        "disclosed_quantity": data.get("disclosed_quantity", 0) or 0,
        "product": data.get("product"),
        "price": price,
        "trigger_price": trigger_price,
        "amo": bool(data.get("amo", False)),
    }

    path = f"/orders/regular/{order_id}"

    if dry_run:
        preview = dry_run_response(
            "PUT", path, {"api_key": API_KEY},
            {"Authorization": "***REDACTED***", "Content-Type": "application/json"},
            modify_body,
        )
        return jsonify(preview)

    ok, status, body = hdfc_call(
        "PUT", path, params={"api_key": API_KEY},
        json_body=modify_body, auth_token=access_token,
    )
    if not ok:
        return jsonify({"error": "Modify order failed", "detail": body}), status
    return jsonify(body)


@app.route("/api/order/cancel", methods=["POST"])
def cancel_order():
    access_token = require_login()
    if not access_token:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json(silent=True) or {}
    dry_run = bool(data.get("dryRun", True))

    order_id = str(data.get("order_id", "")).strip()
    if not order_id:
        return jsonify({"error": "order_id is required"}), 400

    path = f"/orders/regular/{order_id}"

    if dry_run:
        preview = dry_run_response(
            "DELETE", path, {"api_key": API_KEY},
            {"Authorization": "***REDACTED***"},
            None,
        )
        return jsonify(preview)

    ok, status, body = hdfc_call(
        "DELETE", path, params={"api_key": API_KEY}, auth_token=access_token,
    )
    if not ok:
        return jsonify({"error": "Cancel order failed", "detail": body}), status
    return jsonify(body)


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
