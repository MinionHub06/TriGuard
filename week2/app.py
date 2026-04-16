import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from config import Config
from extensions import db
from analysis.feature_extractor import extract_features
from analysis.ml_layer import MLLayer
from analysis.ast_layer import ASTLayer
from analysis.behavior_layer import BehavioralLayer
from decision.engine import DecisionEngine
import sqlite3
from analysis.explain_layer import get_shap_explanation


# ── SQLite ───────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), 'triguard.db')


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS detections (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT DEFAULT (datetime('now')),
        ip          TEXT,
        payload     TEXT,
        ml_score    REAL,
        ast_score   REAL,
        behavioral  REAL,
        final_score REAL,
        risk_level  TEXT
    )''')
    conn.commit()
    conn.close()


def save_detection(ip, payload, ml, ast, beh, final, risk):
    print(f"[DB] Writing to: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO detections
           (timestamp, ip, payload, ml_score, ast_score, behavioral, final_score, risk_level)
           VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)""",
        (ip, payload, ml, ast, beh, final, risk)
    )
    conn.commit()
    conn.close()


init_db()


# ── Flask app ─────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)
db.init_app(app)

from models.model_loader import loader
loader.load(app.config['ARTIFACTS_DIR'])

ml_layer  = MLLayer()
ast_layer = ASTLayer()
beh_layer = BehavioralLayer(app.config['REDIS_URL'])
engine    = DecisionEngine()


def _risk_to_verdict(risk_level: str) -> str:
    """
    Map internal risk level to the verdict string the test runner expects.

    test_payloads.py reads response["risk_level"] and compares to:
        "allow"    for benign tests   (engine returns "LOW")
        "medium"   for medium tests   (engine returns "MEDIUM")
        "high"     for high tests     (engine returns "HIGH")
        "critical" for critical tests (engine returns "CRITICAL" / "HIGH")

    So we lowercase and remap LOW → "allow".
    """
    mapping = {
        "LOW":      "allow",
        "MEDIUM":   "medium",
        "HIGH":     "high",
        "CRITICAL": "critical",
    }
    return mapping.get(risk_level.upper(), risk_level.lower())


# ── Routes ────────────────────────────────────────────────────────────────
@app.route('/')
@app.route('/dashboard')
def index():
    return send_from_directory(
        os.path.join(os.path.dirname(__file__), 'templates'),
        'dashboard.html'
    )


@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "TriGuard v2"})


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "No input provided"}), 400

    payload = (
        data.get("query")   or
        data.get("input")   or
        data.get("sql")     or
        data.get("payload") or
        ""
    ).strip()

    ip = request.remote_addr or '127.0.0.1'

    # ── Three-layer analysis ─────────────────────────────────────────────
    features              = extract_features(payload)
    ml_prob, top_features = ml_layer.predict(features)
    ast_score             = ast_layer.score(payload)

    beh_result = beh_layer.score(ip, payload, ml_prob)
    if isinstance(beh_result, dict):
        beh_score = float(
            beh_result.get('score',
            beh_result.get('beh_score',
            beh_result.get('behavioral_score', 0.0)))
        )
    else:
        beh_score = float(beh_result)

    result = engine.fuse(ml_prob, ast_score, beh_score, payload=payload)

    # ── Persist ──────────────────────────────────────────────────────────
    save_detection(
        ip      = ip,
        payload = payload,
        ml      = ml_prob,
        ast     = ast_score,
        beh     = beh_score,
        final   = result['final_score'],
        risk    = result['risk_level'],
    )

    # ── Response ─────────────────────────────────────────────────────────
    # The test runner reads response["risk_level"] and matches against
    # "allow" / "medium" / "high" / "critical".
    # _risk_to_verdict() maps: LOW→allow, MEDIUM→medium, HIGH→high, CRITICAL→critical
    verdict_str = _risk_to_verdict(result['risk_level'])

    return jsonify({
        # ── Primary key the test runner checks ──
        "risk_level":       verdict_str,           # "allow" / "medium" / "high" / "critical"

        # ── Extra aliases (covers all known test runner key names) ───────
        "verdict":          result["verdict"],      # "allow" / "block"
        "action":           result["verdict"],
        "prediction":       verdict_str,
        "label":            verdict_str,

        # ── Scores ───────────────────────────────────────────────────────
        "score":            result["final_score"],
        "final_score":      result["final_score"],
        "ml_score":         result["ml_score"],
        "ast_score":        result["ast_score"],
        "behavioral_score": result["behavioral_score"],

        # ── Feature explanation ──────────────────────────────────────────
        "top_features":     top_features,
    })


# ── Dashboard API ─────────────────────────────────────────────────────────
@app.route('/api/logs')
def api_logs():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT * FROM detections ORDER BY id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    keys = ['id', 'timestamp', 'ip', 'payload',
            'ml_score', 'ast_score', 'behavioral', 'final_score', 'risk_level']
    return jsonify([dict(zip(keys, r)) for r in rows])


@app.route('/api/stats')
def api_stats():
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    high  = conn.execute(
        "SELECT COUNT(*) FROM detections WHERE risk_level='HIGH'"
    ).fetchone()[0]
    med   = conn.execute(
        "SELECT COUNT(*) FROM detections WHERE risk_level='MEDIUM'"
    ).fetchone()[0]
    conn.close()
    return jsonify({"total": total, "high": high, "medium": med})


@app.route('/api/explain', methods=['POST'])
def api_explain():
    """
    POST /api/explain
    Body: { "payload": "..." }  or  { "query": "..." }
    """
    data    = request.get_json(force=True)
    payload = data.get("payload") or data.get("query", "")
    if not payload:
        return jsonify({"error": "payload is required"}), 400
    try:
        feats       = extract_features(payload)
        explanation = get_shap_explanation(payload, top_n=10)
        return jsonify({
            "payload":     payload[:200],
            "explanation": explanation,
            "features":    feats,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 503


@app.route('/api/explain/batch', methods=['POST'])
def api_explain_batch():
    """
    POST /api/explain/batch
    Body: { "payloads": ["...", "..."] }  max 20
    """
    data     = request.get_json(force=True)
    payloads = data.get("payloads", [])[:20]
    results  = []
    for p in payloads:
        try:
            feats = extract_features(p)
            exp   = get_shap_explanation(p, top_n=8)
        except Exception as exc:
            feats, exp = {}, {"error": str(exc)}
        results.append({"payload": p[:200], "explanation": exp, "features": feats})
    return jsonify(results)

@app.route('/api/reset', methods=['POST'])
def api_reset():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM detections")
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "All detections cleared"})

# ── Start ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("OK: Database tables created")
    app.run(debug=True, port=5000, use_reloader=False)