"""
Protected application blueprint (the three apps behind the Zero Trust gateway).

RBAC matrix enforced here:
    HR Portal          -> Admin, User
    Finance Dashboard  -> Admin
    Document Manager   -> Admin, User, Viewer (read)
"""

from flask import Blueprint, jsonify
from flask_jwt_extended import get_jwt_identity

from models import ROLE_ADMIN, ROLE_USER, ROLE_VIEWER
from security import roles_required, record_access

resources_bp = Blueprint("resources", __name__)


@resources_bp.route("/api/protected/hr", methods=["GET"])
@roles_required(ROLE_ADMIN, ROLE_USER)
def hr_portal():
    record_access(get_jwt_identity(), "ACCESS", "HR Portal", "GRANTED")
    return jsonify(
        {
            "message": "Welcome to the HR Portal",
            "resource": "HR Portal",
            "data": {
                "employees": 25,
                "departments": 5,
                "open_positions": 3,
                "pending_leave_requests": 7,
            },
        }
    )


@resources_bp.route("/api/protected/finance", methods=["GET"])
@roles_required(ROLE_ADMIN)
def finance_dashboard():
    record_access(get_jwt_identity(), "ACCESS", "Finance Dashboard", "GRANTED")
    return jsonify(
        {
            "message": "Welcome to the Finance Dashboard",
            "resource": "Finance Dashboard",
            "data": {
                "revenue": 150000,
                "expenses": 75000,
                "net_profit": 75000,
                "invoices_pending": 12,
            },
        }
    )


@resources_bp.route("/api/protected/documents", methods=["GET"])
@roles_required(ROLE_ADMIN, ROLE_USER, ROLE_VIEWER)
def document_manager():
    record_access(get_jwt_identity(), "ACCESS", "Document Manager", "GRANTED")
    return jsonify(
        {
            "message": "Welcome to the Document Manager",
            "resource": "Document Manager",
            "access": "read-only" if False else "read",
            "data": {
                "documents": 42,
                "folders": 7,
                "recent": [
                    "Q3-Security-Policy.pdf",
                    "Onboarding-Guide.docx",
                    "Incident-Response-Plan.pdf",
                ],
            },
        }
    )
