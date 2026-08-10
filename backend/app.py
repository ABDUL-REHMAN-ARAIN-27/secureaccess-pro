"""
SecureAccess Pro - Application entry point
==========================================

Zero Trust Network Access Control gateway. Wires together configuration,
extensions, models and route blueprints, and installs the "verify every
request" site-access tracker that embodies the Zero Trust principle.

Run:
    python app.py            # starts on 0.0.0.0:5000 (SQLite by default)
"""

from flask import Flask, jsonify, request
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
}


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    jwt.init_app(app)
    CORS(app)

    _register_blueprints(app)
    _register_request_hooks(app)
    _register_error_handlers(app)

    @app.route("/")
    def home():
        return jsonify(
            {
                "service": "SecureAccess Pro",
                "description": "Zero Trust Network Access Control System",
                "status": "running",
                "endpoints": [
                    "/api/login",
                    "/api/register",
                    "/api/protected/hr",
                    "/api/protected/finance",
                    "/api/protected/documents",
                    "/api/logs",
                    "/api/login-history",
                    "/api/site-access",
                    "/api/metrics",
                    "/api/users",
                ],
            }
        )

    with app.app_context():
        db.create_all()

    return app


def _register_blueprints(app):
    from routes.auth import auth_bp
    from routes.resources import resources_bp
    from routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(resources_bp)
    app.register_blueprint(admin_bp)


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
