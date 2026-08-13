"""
Patient Records CRUD blueprint.

RBAC (patient data is the most sensitive resource):
    - READ   (list / get) : Admin, User
    - CREATE / UPDATE / DELETE : Admin ONLY

Every write is audit-logged. Non-admin write attempts are blocked by the
roles_required guard, which logs a DENIED event so the attempt surfaces on the
security dashboard.
"""

from collections import Counter

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity

from extensions import db
from models import Patient, SEVERITIES, STATUSES, ROLE_ADMIN, ROLE_USER
from security import roles_required, record_access

patients_bp = Blueprint("patients", __name__)


def _summary():
    rows = Patient.query.all()
    by_sev = Counter(p.severity for p in rows)
    by_status = Counter(p.status for p in rows)
    return {
        "total_patients": len(rows),
        "critical": by_sev.get("Critical", 0),
        "serious": by_sev.get("Serious", 0),
        "in_icu": by_status.get("ICU", 0),
        "admitted": by_status.get("Admitted", 0),
    }


# --------------------------------------------------------------------------- #
# READ — Admin, User
# --------------------------------------------------------------------------- #
@patients_bp.route("/api/protected/patients", methods=["GET"])
@roles_required(ROLE_ADMIN, ROLE_USER)
def list_patients():
    record_access(get_jwt_identity(), "ACCESS", "Patient Records", "GRANTED")
    patients = Patient.query.order_by(Patient.patient_id).all()
    return jsonify({
        "message": "Welcome to Patient Records",
        "resource": "Patient Records",
        "classification": "CONFIDENTIAL - HEALTH RECORDS (PHI)",
        "summary": _summary(),
        "patients": [p.to_dict() for p in patients],
    })


@patients_bp.route("/api/protected/patients/<pid>", methods=["GET"])
@roles_required(ROLE_ADMIN, ROLE_USER)
def get_patient(pid):
    patient = Patient.query.filter_by(patient_id=pid).first()
    if not patient:
        return jsonify({"error": "Patient not found"}), 404
    return jsonify(patient.to_dict())


# --------------------------------------------------------------------------- #
# CREATE / UPDATE / DELETE — Admin ONLY
# --------------------------------------------------------------------------- #
def _validate(data, require_name=True):
    if require_name and not (data.get("name") or "").strip():
        return "Patient name is required"
    if data.get("severity") and data["severity"] not in SEVERITIES:
        return f"Severity must be one of {list(SEVERITIES)}"
    if data.get("status") and data["status"] not in STATUSES:
        return f"Status must be one of {list(STATUSES)}"
    age = data.get("age")
    if age is not None and str(age) != "":
        try:
            if not (0 <= int(age) <= 120):
                return "Age must be between 0 and 120"
        except (TypeError, ValueError):
            return "Age must be a number"
    return None


def _next_patient_id():
    last = Patient.query.order_by(Patient.id.desc()).first()
    n = 2001
    if last and last.patient_id.startswith("PT-"):
        try:
            n = int(last.patient_id.split("-")[1]) + 1
        except (IndexError, ValueError):
            n = (last.id or 0) + 2001
    return f"PT-{n}"


@patients_bp.route("/api/protected/patients", methods=["POST"])
@roles_required(ROLE_ADMIN)
def create_patient():
    data = request.get_json(silent=True) or {}
    err = _validate(data, require_name=True)
    if err:
        return jsonify({"error": err}), 400

    patient = Patient(patient_id=data.get("patient_id") or _next_patient_id())
    patient.apply(data)
    try:
        db.session.add(patient)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": f"Could not create patient: {exc}"}), 500

    record_access(get_jwt_identity(), "CREATE", f"Patient:{patient.patient_id}", "SUCCESS")
    return jsonify({"message": "Patient created", "patient": patient.to_dict()}), 201


@patients_bp.route("/api/protected/patients/<pid>", methods=["PUT"])
@roles_required(ROLE_ADMIN)
def update_patient(pid):
    patient = Patient.query.filter_by(patient_id=pid).first()
    if not patient:
        return jsonify({"error": "Patient not found"}), 404
    data = request.get_json(silent=True) or {}
    err = _validate(data, require_name=False)
    if err:
        return jsonify({"error": err}), 400

    patient.apply(data)
    db.session.commit()
    record_access(get_jwt_identity(), "UPDATE", f"Patient:{pid}", "SUCCESS")
    return jsonify({"message": "Patient updated", "patient": patient.to_dict()})


@patients_bp.route("/api/protected/patients/<pid>", methods=["DELETE"])
@roles_required(ROLE_ADMIN)
def delete_patient(pid):
    patient = Patient.query.filter_by(patient_id=pid).first()
    if not patient:
        return jsonify({"error": "Patient not found"}), 404
    db.session.delete(patient)
    db.session.commit()
    record_access(get_jwt_identity(), "DELETE", f"Patient:{pid}", "SUCCESS")
    return jsonify({"message": f"Patient {pid} deleted"})
