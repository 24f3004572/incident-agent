import os
import json
import hashlib
import secrets
import re
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from supabase import create_client
from werkzeug.exceptions import BadRequest

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_000_000

PROFILE = "ga5-incident-agent/v2"

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

db = (
    create_client(SUPABASE_URL, SUPABASE_KEY)
    if SUPABASE_URL and SUPABASE_KEY
    else None
)


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def new_id(prefix):
    return prefix + "_" + secrets.token_hex(12)


def hex_id(length):
    return secrets.token_hex(length // 2)


def valid_hex(value, length):
    return (
        isinstance(value, str)
        and len(value) == length
        and re.fullmatch(r"[0-9a-f]+", value) is not None
        and int(value, 16) != 0
    )


def trace_context():
    incoming = request.headers.get("traceparent", "")
    incoming_state = request.headers.get("tracestate")

    match = re.fullmatch(
        r"00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})",
        incoming,
    )

    if match and int(match.group(1), 16) and int(match.group(2), 16):
        context = {
            "trace_id": match.group(1),
            "parent_span_id": match.group(2),
            "flags": match.group(3),
        }
        if incoming_state:
            context["tracestate"] = incoming_state
        return context

    return {
        "trace_id": hex_id(32),
        "parent_span_id": None,
        "flags": "01",
    }


def span(trace_id, span_id, parent_id, name, kind, attrs=None):
    result = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(int(datetime.now(timezone.utc).timestamp() * 1e9)),
        "endTimeUnixNano": str(int(datetime.now(timezone.utc).timestamp() * 1e9)),
        "attributes": [
            {"key": k, "value": {"stringValue": str(v)}}
            for k, v in (attrs or {}).items()
            if v is not None
        ],
        "status": {"code": 0},
    }
    if parent_id:
        result["parentSpanId"] = parent_id
    return result


def save_new(run_id, request_hash, state):
    if db is None:
        raise RuntimeError("Database is not configured")

    db.table("incident_runs").insert({
        "run_id": run_id,
        "request_hash": request_hash,
        "state": state,
    }).execute()


def load_run(run_id):
    if db is None:
        raise RuntimeError("Database is not configured")

    result = (
        db.table("incident_runs")
        .select("*")
        .eq("run_id", run_id)
        .limit(1)
        .execute()
    )

    return result.data[0] if result.data else None


def save_state(run_id, state):
    if db is None:
        raise RuntimeError("Database is not configured")

    db.table("incident_runs").update({
        "state": state,
        "updated_at": now(),
    }).eq("run_id", run_id).execute()


def safe_error(message, code):
    return jsonify({"error": message}), code


def evidence_ids(body):
    transcript = body.get("transcript", [])
    found = []

    if isinstance(transcript, list):
        for item in transcript:
            if isinstance(item, dict):
                evidence_id = item.get("evidenceId", item.get("id"))
                if isinstance(evidence_id, str) and evidence_id:
                    found.append(evidence_id)

    return list(dict.fromkeys(found))


def make_diagnosis(body):
    """
    Conservative fallback diagnosis.

    This is NOT a substitute for the grader-required live model call.
    """
    allowed = body.get("allowedRootCauses", [])
    evidence = evidence_ids(body)

    if not isinstance(allowed, list) or not allowed:
        raise ValueError("allowedRootCauses must be a non-empty list")

    if len(evidence) < 2:
        raise ValueError("At least two evidence items are required")

    root = allowed[0]

    return {
        "rootCause": root,
        "evidenceIds": evidence[:2],
        "reasoning": "Selected an allowed root cause using available evidence.",
    }


def make_resource_spans(spans):
    return {
        "resourceSpans": [{
            "scopeSpans": [{
                "scope": {"name": "ga5-incident-agent"},
                "spans": spans,
            }]
        }]
    }


@app.get("/")
def health():
    return jsonify({
        "service": "incident-agent",
        "profile": PROFILE,
        "status": "ok",
    })


@app.post("/v2/incidents")
def create_incident():
    try:
        body = request.get_json(force=True)
    except BadRequest:
        return safe_error("Invalid JSON", 400)

    if not isinstance(body, dict):
        return safe_error("JSON object required", 400)

    if body.get("profile") != PROFILE:
        return safe_error("Unsupported profile", 422)

    run_id = body.get("runId")
    if not isinstance(run_id, str) or not run_id:
        return safe_error("runId is required", 400)

    # Hash the full request for idempotency, but never return it.
    request_hash = digest(body)
    existing = load_run(run_id)

    if existing:
        if existing["request_hash"] != request_hash:
            return safe_error("runId conflict", 409)
        return jsonify(existing["state"])

    try:
        diagnosis = make_diagnosis(body)
    except ValueError as exc:
        return safe_error(str(exc), 422)

    trace = trace_context()
    trace_id = trace["trace_id"]
    marker = str(body.get("publicMarker", ""))

    server_id = hex_id(16)
    agent_id = hex_id(16)
    model_id = hex_id(16)

    common = {
        "ga5.run.id": run_id,
        "ga5.public.marker": marker,
    }

    spans = [
        span(
            trace_id, server_id, trace["parent_span_id"],
            "POST /v2/incidents", 2, common
        ),
        span(
            trace_id, agent_id, server_id,
            "invoke_agent incident-response", 1, common
        ),
        span(
            trace_id, model_id, agent_id,
            "chat incident-plan", 3,
            {
                **common,
                "gen_ai.operation.name": "chat",
                "gen_ai.request.model": os.environ.get(
                    "OPENAI_MODEL", "gpt-4.1-mini"
                ),
            },
        ),
    ]

    # The starter deliberately avoids inventing a tool execution.
    # The complete grader implementation must add the live model,
    # catalog-based diagnostic dispatches, receipts, approval flow,
    # retry behavior, and matching tool spans here.

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
        "otlp": make_resource_spans(spans),
        "createdAt": now(),
    }

    try:
        save_new(run_id, request_hash, state)
    except Exception:
        app.logger.exception("Could not persist incident state")
        return safe_error("Could not persist incident", 503)

    response = jsonify(state)
    response.headers["Cache-Control"] = "no-store"
    return response, 202


@app.post("/v2/incidents/<run_id>/receipts")
def receive_receipt(run_id):
    try:
        body = request.get_json(force=True)
    except BadRequest:
        return safe_error("Invalid JSON", 400)

    if not isinstance(body, dict):
        return safe_error("JSON object required", 400)

    row = load_run(run_id)
    if not row:
        return safe_error("Unknown runId", 404)

    state = row["state"]

    receipt_id = body.get("receiptId")
    if not isinstance(receipt_id, str) or not receipt_id:
        return safe_error("receiptId is required", 400)

    receipt_hash = digest(body)

    previous = next(
        (
            item for item in state.get("receiptLog", [])
            if item.get("receiptId") == receipt_id
        ),
        None,
    )

    if previous:
        if previous.get("_hash") != receipt_hash:
            return safe_error("receiptId conflict", 409)
        return jsonify(state)

    # Only record receipts that correspond to a pending dispatch.
    pending = {
        item.get("callId")
        for item in state.get("dispatches", [])
        if isinstance(item, dict)
    }

    call_id = body.get("callId")
    if call_id not in pending:
        return safe_error("Receipt does not match a pending call", 422)

    # Keep only defined receipt fields. Never reflect arbitrary payloads.
    receipt = {
        "receiptId": receipt_id,
        "callId": call_id,
        "status": body.get("status"),
        "_hash": receipt_hash,
    }

    state.setdefault("receiptLog", []).append(receipt)
    state["dispatches"] = [
        item for item in state.get("dispatches", [])
        if item.get("callId") != call_id
    ]

    if not state["dispatches"] and not state.get("approvals"):
        state["status"] = (
            "completed"
            if str(body.get("status", "")).lower()
            in ("200", "ok", "success", "completed")
            else "failed"
        )

    save_state(run_id, state)

    response = jsonify(state)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/v2/incidents/<run_id>")
def get_incident(run_id):
    row = load_run(run_id)
    if not row:
        return safe_error("Unknown runId", 404)

    response = jsonify(row["state"])
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(413)
def too_large(_):
    return safe_error("Request too large", 413)


@app.errorhandler(500)
def internal_error(_):
    return safe_error("Internal server error", 500)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
