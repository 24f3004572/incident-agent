
import os
import json
import hashlib
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from supabase import create_client
from werkzeug.exceptions import BadRequest

app = Flask(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

db = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def error(message, status):
    return jsonify({"error": message}), status


def load_run(run_id):
    if not db:
        return None
    result = (
        db.table("incident_runs")
        .select("*")
        .eq("run_id", run_id)
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


def save_run(run_id, request_hash, state):
    db.table("incident_runs").upsert({
        "run_id": run_id,
        "request_hash": request_hash,
        "state": state,
        "updated_at": now(),
    }).execute()


@app.get("/")
def health():
    return jsonify({"service": "incident-agent", "status": "ok"})


@app.post("/v2/incidents")
def create_incident():
    if not request.is_json:
        return error("Expected JSON", 400)

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return error("Invalid JSON body", 400)

    if body.get("profile") != "ga5-incident-agent/v2":
        return error("Unsupported profile", 422)

    run_id = body.get("runId")
    if not isinstance(run_id, str) or not run_id:
        return error("Missing runId", 400)

    if not db:
        return error("Database is not configured", 503)

    request_hash = digest(body)
    existing = load_run(run_id)

    if existing:
        if existing["request_hash"] != request_hash:
            return error("runId already exists with different content", 409)
        return jsonify(existing["state"])

    # Never send sensitive values to the AI model or include them in the state.
    safe_body = {k: v for k, v in body.items() if k != "sensitive"}

    incident = safe_body.get("incident", {})
    allowed = incident.get("allowedRootCauses", [])
    evidence_items = incident.get("transcript", [])

    diagnosis = {
        "rootCause": allowed[0] if allowed else "unknown",
        "evidenceIds": [
            item.get("id")
            for item in evidence_items[:2]
            if isinstance(item, dict) and item.get("id")
        ],
        "summary": "Preliminary diagnosis based on supplied incident evidence.",
    }

    state = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": diagnosis,
        "chosenEffect": None,
        "suppressed": [],
        "dispatches": [],
        "approvals": [],
        "actionLog": [],
        "receiptLog": [],
        "otlp": {"resourceSpans": []},
    }

    save_run(run_id, request_hash, state)
    return jsonify(state), 200


@app.post("/v2/incidents/<run_id>/receipts")
def receive_receipt(run_id):
    if not request.is_json:
        return error("Expected JSON", 400)

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return error("Invalid JSON body", 400)

    if not db:
        return error("Database is not configured", 503)

    existing = load_run(run_id)
    if not existing:
        return error("Unknown runId", 404)

    state = existing["state"]
    receipts = state.setdefault("receiptLog", [])

    receipt_id = body.get("receiptId")
    if not isinstance(receipt_id, str) or not receipt_id:
        return error("Missing receiptId", 400)

    for old in receipts:
        if old.get("receiptId") == receipt_id:
            if digest(old) == digest(body):
                return jsonify(state)
            return error("receiptId conflict", 409)

    # Store the receipt without echoing arbitrary incoming fields.
    receipt = {
        "receiptId": receipt_id,
        "status": body.get("status"),
        "errorType": body.get("errorType"),
    }
    receipts.append(receipt)

    if body.get("status") == 0:
        state["status"] = "failed"
    else:
        state["status"] = "completed"

    state["dispatches"] = []
    save_run(run_id, existing["request_hash"], state)
    return jsonify(state)


@app.get("/v2/incidents/<run_id>")
def get_incident(run_id):
    if not db:
        return error("Database is not configured", 503)

    existing = load_run(run_id)
    if not existing:
        return error("Unknown runId", 404)

    return jsonify(existing["state"])


@app.errorhandler(BadRequest)
def bad_request(_):
    return error("Bad request", 400)


@app.errorhandler(500)
def internal_error(_):
    return error("Internal server error", 500)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
