"""
UEBA — per-user behaviour profile.

One row per user. It is the learned "normal" against which each new login is
compared. Aggregates are stored as small JSON blobs so the model stays
dependency-light and fully inspectable (no opaque binary model files).
"""

import json
from datetime import datetime

from extensions import db


class BehaviorProfile(db.Model):
    __tablename__ = "behavior_profiles"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, index=True, nullable=False)

    login_count = db.Column(db.Integer, default=0)
    hour_hist = db.Column(db.Text, default="[]")     # 24 ints: logins per hour
    intervals = db.Column(db.Text, default="[]")     # recent inter-login seconds
    known_ips = db.Column(db.Text, default="[]")
    known_devices = db.Column(db.Text, default="[]")
    vectors = db.Column(db.Text, default="[]")       # recent feature vectors (optional ML)

    last_login_at = db.Column(db.DateTime)
    last_anomaly = db.Column(db.Float, default=0.0)  # 0-100
    last_anomaly_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ---- JSON helpers -------------------------------------------------- #
    def _get(self, field, default):
        try:
            return json.loads(getattr(self, field) or "")
        except (ValueError, TypeError):
            return default

    def get_hist(self):
        h = self._get("hour_hist", [])
        return h if len(h) == 24 else [0] * 24

    def set_hist(self, h):
        self.hour_hist = json.dumps(h)

    def get_intervals(self):
        return self._get("intervals", [])

    def set_intervals(self, lst):
        self.intervals = json.dumps(lst[-50:])

    def get_known_ips(self):
        return self._get("known_ips", [])

    def set_known_ips(self, lst):
        self.known_ips = json.dumps(lst[-30:])

    def get_known_devices(self):
        return self._get("known_devices", [])

    def set_known_devices(self, lst):
        self.known_devices = json.dumps(lst[-30:])

    def get_vectors(self):
        return self._get("vectors", [])

    def set_vectors(self, lst):
        self.vectors = json.dumps(lst[-50:])

    def top_hours(self, n=3):
        hist = self.get_hist()
        ranked = sorted(range(24), key=lambda h: hist[h], reverse=True)
        return [f"{h:02d}:00" for h in ranked[:n] if hist[h] > 0]

    def to_dict(self):
        return {
            "username": self.username,
            "login_count": self.login_count,
            "typical_hours": self.top_hours(),
            "known_ips": len(self.get_known_ips()),
            "known_devices": len(self.get_known_devices()),
            "last_anomaly": round(self.last_anomaly or 0.0, 1),
            "last_anomaly_cvss": round((self.last_anomaly or 0.0) / 10.0, 1),
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "learning": self.login_count < 4,
        }
