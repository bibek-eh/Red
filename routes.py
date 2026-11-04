# vulnerable-lab/app/routes.py
from flask import Blueprint, request, jsonify
import sqlite3
import requests
import datetime

lab_bp = Blueprint("vulnerable_lab", __name__, url_prefix="/lab")
TELEMETRY_INGEST_URL = "http://localhost:5000/api/events/ingest"

def emit_telemetry(event_type, endpoint, method, status_code, message, payload):
    try:
        requests.post(TELEMETRY_INGEST_URL, json={
            "session_id": payload.get("session_id", "default_session"),
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event_type": event_type,
            "source": "vulnerable_lab",
            "source_ip": request.remote_addr or "10.10.0.24",
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "severity": "info",
            "message": message,
            "metadata": payload
        }, timeout=0.5)
    except Exception:
        pass # Non-blocking execution fallback

@lab_bp.route("/sqli/search", methods=["GET"])
def sqli_lab():
    """Vulnerability 1: SQL Injection (Unsafe Parameter Concatenation)"""
    search_query = request.args.get("q", "")
    mode = request.args.get("mode", "vulnerable")
    session_id = request.headers.get("X-Session-ID", "default_session")

    # Telemetry dispatch
    emit_telemetry(
        event_type="db_query",
        endpoint=f"/lab/sqli/search?q={search_query}",
        method="GET",
        status_code=200,
        message=f"Database search query processed in mode [{mode}]",
        payload={"query_input": search_query, "session_id": session_id}
    )

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE products (id INT, name TEXT, category TEXT)")
    cursor.execute("INSERT INTO products VALUES (1, 'Encrypted USB Drive', 'Hardware')")
    cursor.execute("INSERT INTO products VALUES (2, 'SOC Terminal Display', 'Hardware')")
    cursor.execute("INSERT INTO products VALUES (3, 'API Security Gateway', 'Software')")

    results = []
    if mode == "vulnerable":
        # INTENTIONALLY UNSAFE FOR TRAINING
        raw_sql = f"SELECT id, name, category FROM products WHERE name LIKE '%{search_query}%'"
        try:
            cursor.executescript(raw_sql)
            rows = cursor.fetchall()
            for r in rows:
                results.append({"id": r[0], "name": r[1], "category": r[2]})
        except Exception as e:
            results = [{"error": str(e)}]
    else:
        # SECURE COMPARISON PATH
        cursor.execute("SELECT id, name, category FROM products WHERE name LIKE ?", (f"%{search_query}%",))
        rows = cursor.fetchall()
        for r in rows:
            results.append({"id": r[0], "name": r[1], "category": r[2]})

    return jsonify({"status": "success", "mode": mode, "results": results})

@lab_bp.route("/documents/<doc_id>", methods=["GET"])
def idor_lab(doc_id):
    """Vulnerability 2: Broken Object-Level Authorization (IDOR)"""
    mode = request.args.get("mode", "vulnerable")
    user_id = request.headers.get("X-User-ID", "usr_blue_01")
    session_id = request.headers.get("X-Session-ID", "default_session")

    # Telemetry dispatch
    emit_telemetry(
        event_type="object_access",
        endpoint=f"/lab/documents/{doc_id}",
        method="GET",
        status_code=200 if mode == "vulnerable" else 403,
        message=f"Document retrieval attempt for [{doc_id}] by user [{user_id}]",
        payload={"doc_id": doc_id, "user_id": user_id, "session_id": session_id}
    )

    doc_store = {
        "doc-001": {"owner": "usr_blue_01", "title": "Network Topology Baseline", "classification": "INTERNAL"},
        "doc-002": {"owner": "usr_blue_01", "title": "Incident Escalation Plan", "classification": "RESTRICTED"},
        "doc-999": {"owner": "usr_admin_00", "title": "Red Team Attack Playbook", "classification": "CONFIDENTIAL"}
    }

    doc = doc_store.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404

    if mode == "vulnerable":
        # UNSAFE: Skips ownership check
        return jsonify({"status": "success", "mode": mode, "document": doc})
    else:
        # SECURE: Validates user ownership
        if doc["owner"] != user_id:
            return jsonify({"status": "denied", "error": "Access unauthorized for this object"}), 403
        return jsonify({"status": "success", "mode": mode, "document": doc})