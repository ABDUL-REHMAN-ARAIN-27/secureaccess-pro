"""
Patient model (confidential health records / PHI).

Patient data is the most sensitive resource in the system: only Admin may
create, update or delete records. Read access is limited to Admin and User;
Viewer is denied. All write operations are audit-logged.
"""

from datetime import datetime

from extensions import db

SEVERITIES = ("Critical", "Serious", "Moderate", "Stable")
STATUSES = ("ICU", "Admitted", "Outpatient", "Discharged")


class Patient(db.Model):
    __tablename__ = "patients"

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    blood_group = db.Column(db.String(5))
    diagnosis = db.Column(db.String(120))
    severity = db.Column(db.String(20))
    department = db.Column(db.String(40))
    attending = db.Column(db.String(60))
    status = db.Column(db.String(20))
    admitted_on = db.Column(db.String(20))
    contact = db.Column(db.String(30))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "patient_id": self.patient_id,
            "name": self.name,
            "age": self.age,
            "gender": self.gender,
            "blood_group": self.blood_group,
            "diagnosis": self.diagnosis,
            "severity": self.severity,
            "department": self.department,
            "attending": self.attending,
            "status": self.status,
            "admitted_on": self.admitted_on,
            "contact": self.contact,
        }

    # Fields a client is allowed to set on create/update.
    WRITABLE = (
        "name", "age", "gender", "blood_group", "diagnosis",
        "severity", "department", "attending", "status", "admitted_on", "contact",
    )

    def apply(self, data):
        for field in self.WRITABLE:
            if field in data and data[field] is not None:
                setattr(self, field, data[field])
