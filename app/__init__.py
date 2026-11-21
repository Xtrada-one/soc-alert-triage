"""SOC Alert Triage Dashboard (Flask)."""
from __future__ import annotations

import os
from pathlib import Path

from flask import Flask

from . import db
from .engine.rules import load_rules
from .routes import bp


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    base = Path(__file__).resolve().parent.parent
    app.config.update(
        DB_PATH=os.environ.get("DB_PATH", str(base / "data" / "soc.db")),
        RULES_PATH=os.environ.get("RULES_PATH", str(Path(__file__).parent / "rules" / "rules.yaml")),
        SAMPLES_DIR=os.environ.get("SAMPLES_DIR", str(base / "sample_logs")),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", "10")) * 1024 * 1024,
        LLM_ENABLED=os.environ.get("LLM_ENABLED", "false").lower() == "true",
        OLLAMA_URL=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        OLLAMA_MODEL=os.environ.get("OLLAMA_MODEL", "qwen2.5:3b"),
        LOG_YEAR=int(os.environ["LOG_YEAR"]) if os.environ.get("LOG_YEAR") else None,
    )
    if test_config:
        app.config.update(test_config)
    app.config["RULES"] = load_rules(app.config["RULES_PATH"])
    db.init_app(app)
    app.register_blueprint(bp)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
        )
        return resp

    @app.errorhandler(413)
    def too_large(_e):
        from flask import jsonify
        limit = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return jsonify({"error": f"File terlalu besar (maksimal {limit} MB)."}), 413

    return app
