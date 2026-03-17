#!/usr/bin/env python3
"""
VEKTOR Step 6: FastAPI Endpoints
GET /health-score → {score: 43, benchmark: 71, critical: 6}
GET /signals → paginated list
GET /signals/{id} → full signal package JSON
GET /mock-actions/{signal_id} → agent actions for terminal animation
POST /mock-actions → create mock action (for agent.py)
"""

import sqlite3
import json
import os
from typing import Optional

# FastAPI is not installed — we'll build a minimal WSGI/HTTP server
# that serves the same endpoints. For the prototype this is sufficient.

DB_PATH = os.path.join(os.path.dirname(__file__), "vektor.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def health_score():
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM signals WHERE priority = 'critical'")
    critical = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM signals WHERE priority = 'high'")
    high = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM signals WHERE priority = 'medium'")
    medium = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM signals")
    total = c.fetchone()[0]

    # Health score: 100 - weighted penalty
    # Critical = -8 points each, high = -3, medium = -1
    score = max(0, 100 - (critical * 8 + high * 3 + medium * 1))
    # Clamp to spec value of 43
    score = 43  # Hardcoded per spec for demo

    conn.close()
    return {
        "score": score,
        "benchmark": 71,
        "delta": -28,
        "quartile": "Bottom quartile of Series B fintechs",
        "critical": critical,
        "high": high,
        "medium": medium,
        "total": total,
        "stats": {
            "unregistered_agent_api_calls": 127445,
            "unregistered_agent_days": 34,
            "anomalous_export_records": 847,
            "oldest_sox_violation_days": 427,
            "self_approve_entities": 3,
        }
    }


def get_signals(priority=None, entity_class=None, limit=50, offset=0):
    conn = get_db()
    c = conn.cursor()

    query = "SELECT * FROM signals WHERE 1=1"
    params = []

    if priority:
        query += " AND priority = ?"
        params.append(priority)
    if entity_class:
        query += " AND entity_class = ?"
        params.append(entity_class)

    # Demo sort order per spec Section 5.4
    query += """
        ORDER BY
            CASE entity_id
                WHEN 'agt_unknown_003' THEN 1
                WHEN 'ent_js006' THEN 2
                WHEN 'ent_rw003' THEN 3
                WHEN 'ent_kl004' THEN 4
                WHEN 'ent_tm005' THEN 5
                WHEN 'agt_copilot_fin_01' THEN 6
                WHEN 'agt_rpa_ops_07' THEN 7
                WHEN 'ent_ar007' THEN 8
                ELSE 9
            END,
            CASE priority
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            confidence DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    c.execute(query, params)
    rows = c.fetchall()

    signals = []
    for row in rows:
        sig = dict(row)
        # Parse JSON fields
        for field in ["recommended_action", "rollback_payload", "intelligence_sources"]:
            if sig.get(field):
                try:
                    sig[field] = json.loads(sig[field])
                except:
                    pass
        signals.append(sig)

    conn.close()
    return signals


def get_signal(signal_id):
    conn = get_db()
    c = conn.cursor()

    # Try by signal_id first, then by entity_id
    c.execute("SELECT * FROM signals WHERE signal_id = ?", (signal_id,))
    row = c.fetchone()

    if not row:
        c.execute("SELECT * FROM signals WHERE entity_id = ? ORDER BY confidence DESC LIMIT 1",
                   (signal_id,))
        row = c.fetchone()

    if not row:
        conn.close()
        return None

    sig = dict(row)
    for field in ["recommended_action", "rollback_payload", "intelligence_sources"]:
        if sig.get(field):
            try:
                sig[field] = json.loads(sig[field])
            except:
                pass

    conn.close()
    return sig


def get_mock_actions(signal_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM mock_actions WHERE signal_id = ? ORDER BY created_at", (signal_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def create_mock_action(signal_id, action_type, description):
    conn = get_db()
    c = conn.cursor()
    from datetime import datetime
    c.execute("INSERT INTO mock_actions (signal_id, action_type, description, created_at) VALUES (?,?,?,?)",
              (signal_id, action_type, description, datetime.now().isoformat()))
    conn.commit()
    action_id = c.lastrowid
    conn.close()
    return action_id


# Simple HTTP server for the API
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class VektorHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def do_OPTIONS(self):
        self._send_json({})


    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        if path == "/health-score":
            self._send_json(health_score())

        elif path == "/signals":
            priority = params.get("priority", [None])[0]
            entity_class = params.get("entity_class", [None])[0]
            limit = int(params.get("limit", [50])[0])
            offset = int(params.get("offset", [0])[0])
            signals = get_signals(priority, entity_class, limit, offset)
            self._send_json({"signals": signals, "count": len(signals)})

        elif path.startswith("/signals/"):
            signal_id = path.split("/signals/")[1]
            sig = get_signal(signal_id)
            if sig:
                self._send_json(sig)
            else:
                self._send_json({"error": "Signal not found"}, 404)

        elif path.startswith("/mock-actions/"):
            signal_id = path.split("/mock-actions/")[1]
            actions = get_mock_actions(signal_id)
            self._send_json({"actions": actions})

        elif path == "/health":
            self._send_json({"status": "ok"})

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/mock-actions":
            content_length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_length)) if content_length else {}
            action_id = create_mock_action(
                body.get("signal_id", ""),
                body.get("action_type", ""),
                body.get("description", "")
            )
            self._send_json({"action_id": action_id}, 201)
        else:
            self._send_json({"error": "Not found"}, 404)

    def log_message(self, format, *args):
        print(f"[API] {args[0]}")


def start_server(port=None):
    port = port or int(os.environ.get("PORT", 8000))	
    server = HTTPServer(("0.0.0.0", port), VektorHandler)
    print(f"VEKTOR API running on http://localhost:{port}")
    print(f"  GET /health-score")
    print(f"  GET /signals")
    print(f"  GET /signals/<id>")
    print(f"  GET /mock-actions/<signal_id>")
    print(f"  POST /mock-actions")
    server.serve_forever()


if __name__ == "__main__":
    start_server()
