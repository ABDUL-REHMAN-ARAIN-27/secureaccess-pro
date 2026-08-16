"""
SecureAccess Pro - Application entry point
==========================================

Zero Trust Network Access Control gateway. Wires together configuration,
extensions, models and route blueprints, and installs the "verify every
request" site-access tracker that embodies the Zero Trust principle.

Run:
    python app.py            # starts on 0.0.0.0:5000 (SQLite by default)
"""

import os

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from config import Config
from extensions import db, jwt
from security import client_ip
# Models must be imported so SQLAlchemy registers the tables.
from models import SiteAccess  # noqa: F401
import models  # noqa: F401


# Endpoints that must NOT be site-access-tracked (avoids log noise / recursion).
_TRACK_SKIP = {
    "static",
    "admin.get_logs",
    "admin.get_login_history",
    "admin.get_site_access",
    "admin.get_metrics",
    "admin.get_alerts",
    "admin.verify_audit",
    "zerotrust.list_risk_events",
    "zerotrust.list_sessions",
    "zerotrust.list_devices",
    "zerotrust.risk_metrics",
    "zerotrust.behavior_profiles",
    "files.list_my_files",
    "files.admin_list_files",
    "files.admin_file_metrics",
}


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    jwt.init_app(app)
    CORS(app)

    _register_jwt_hooks(app)
    _register_blueprints(app)
    _register_request_hooks(app)
    _register_error_handlers(app)

    web_dir = os.path.join(os.path.dirname(__file__), "web")

    @app.route("/")
    def home():
        # Serve the browser app so the deployed URL opens the login/register UI.
        return send_from_directory(web_dir, "index.html")

    @app.route("/api/health")
    def health():
        return jsonify({"service": "SecureAccess Pro", "status": "running"})

    with app.app_context():
        db.create_all()

    # Ensure the private file-storage directories exist (outside the web root).
    try:
        import filevault
        filevault.ensure_dirs(app.config)
    except Exception as exc:  # pragma: no cover
        print(f"File-storage init skipped: {exc}")

    # Auto-seed on first startup (demo accounts + patients) so a fresh
    # deployment is immediately usable. Disable with AUTO_SEED=false.
    if os.environ.get("AUTO_SEED", "true").lower() == "true":
        try:
            from bootstrap import seed_demo, is_empty
            if is_empty(app):
                seed_demo(app)
        except Exception as exc:  # pragma: no cover
            print(f"Auto-seed skipped: {exc}")

    return app


def _register_jwt_hooks(app):
    """Phase 2 — make the stateless JWT revocable via the SessionToken store, so
    continuous verification can kill a live session."""

    @jwt.token_in_blocklist_loader
    def _is_revoked(_jwt_header, jwt_payload):
        from models import SessionToken
        jti = jwt_payload.get("jti")
        if not jti:
            return False
        try:
            return (
                SessionToken.query.filter_by(jti=jti, revoked=True).first() is not None
            )
        except Exception:
            return False

    @jwt.revoked_token_loader
    def _revoked_response(_jwt_header, _jwt_payload):
        return (
            jsonify({
                "error": "Session revoked. Please re-authenticate.",
                "session_revoked": True,
            }),
            401,
        )


def _register_blueprints(app):
    from routes.auth import auth_bp
    from routes.resources import resources_bp
    from routes.admin import admin_bp
    from routes.patients import patients_bp
    from routes.zerotrust import zerotrust_bp
    from routes.files import files_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(resources_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(patients_bp)
    app.register_blueprint(zerotrust_bp)
    app.register_blueprint(files_bp)


def _register_request_hooks(app):
    @app.before_request
    def track_site_access():
        """Zero Trust: record every inbound request for continuous monitoring."""
        if request.endpoint in _TRACK_SKIP:
            return None
        try:
            db.session.add(
                SiteAccess(
                    ip_address=client_ip(),
                    method=request.method,
                    page_accessed=request.path,
                    user_agent=(request.headers.get("User-Agent", "Unknown"))[:300],
                    status="VISITED",
                )
            )
            db.session.commit()
        except Exception:
            db.session.rollback()


def _register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return jsonify({"error": "Method not allowed"}), 405


app = create_app()


if __name__ == "__main__":
    app.run(host=app.config["HOST"], port=app.config["PORT"], debug=app.config["DEBUG"])
