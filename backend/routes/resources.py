"""
Protected application blueprint (the three apps behind the Zero Trust gateway).

RBAC matrix enforced here:
    HR Portal          -> Admin, User
    Finance Dashboard  -> Admin
    Document Manager   -> Admin, User, Viewer (read)

Each app serves real (synthetic) confidential data loaded from backend/data/*.
"""

from flask import Blueprint, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt

import datastore
from models import ROLE_ADMIN, ROLE_USER, ROLE_VIEWER
from security import roles_required, record_access

resources_bp = Blueprint("resources", __name__)

# The full RBAC matrix in one place — used to show each user their own rules.
PERMISSION_MATRIX = [
    ("HR Portal",                       {ROLE_ADMIN, ROLE_USER}),
    ("Finance Dashboard",               {ROLE_ADMIN}),
    ("Patient Records (view)",          {ROLE_ADMIN, ROLE_USER}),
    ("Document Manager",                {ROLE_ADMIN, ROLE_USER, ROLE_VIEWER}),
    ("Security Dashboard / Monitoring", {ROLE_ADMIN}),
    ("Manage Users & Patients (CRUD)",  {ROLE_ADMIN}),
]


@resources_bp.route("/api/my-permissions", methods=["GET"])
@jwt_required()
def my_permissions():
    """Return the signed-in user's role and exactly what it may / may not do."""
    role = get_jwt().get("role", "")
    return jsonify({
        "role": role,
        "permissions": [
            {"feature": feature, "allowed": role in roles}
            for feature, roles in PERMISSION_MATRIX
        ],
    })


@resources_bp.route("/api/protected/hr", methods=["GET"])
@roles_required(ROLE_ADMIN, ROLE_USER)
def hr_portal():
    record_access(get_jwt_identity(), "ACCESS", "HR Portal", "GRANTED")
    return jsonify({
        "message": "Welcome to the HR Portal",
        "resource": "HR Portal",
        "data": datastore.hr_data(),
    })


@resources_bp.route("/api/protected/finance", methods=["GET"])
@roles_required(ROLE_ADMIN)
def finance_dashboard():
    record_access(get_jwt_identity(), "ACCESS", "Finance Dashboard", "GRANTED")
    return jsonify({
        "message": "Welcome to the Finance Dashboard",
        "resource": "Finance Dashboard",
        "data": datastore.finance_data(),
    })


@resources_bp.route("/api/protected/documents", methods=["GET"])
@roles_required(ROLE_ADMIN, ROLE_USER, ROLE_VIEWER)
def document_manager():
    record_access(get_jwt_identity(), "ACCESS", "Document Manager", "GRANTED")
    return jsonify({
        "message": "Welcome to the Document Manager",
        "resource": "Document Manager",
        "data": {
            "classification": "CONFIDENTIAL",
            "documents": datastore.list_documents(),
        },
    })


@resources_bp.route("/api/protected/documents/<name>", methods=["GET"])
@roles_required(ROLE_ADMIN, ROLE_USER, ROLE_VIEWER)
def read_document(name):
    content = datastore.read_document(name)
    if content is None:
        record_access(get_jwt_identity(), "ACCESS", f"Document:{name}", "DENIED")
        return jsonify({"error": "Document not found"}), 404
    record_access(get_jwt_identity(), "ACCESS", f"Document:{name}", "GRANTED")
    return jsonify({"resource": "Document Manager", "name": name, "content": content})
