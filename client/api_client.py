"""
Thin HTTP client shared by the user application and the admin dashboard.

Wraps the SecureAccess Pro REST API and carries the JWT bearer token for
authenticated requests.
"""

import os

import requests

API_URL = os.environ.get("SECUREACCESS_API", "http://127.0.0.1:5000")
TIMEOUT = 8


class ApiError(Exception):
    """Raised when the API returns a non-2xx response. Carries status + message."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class ApiClient:
    def __init__(self, base_url=API_URL):
        self.base_url = base_url.rstrip("/")
        self.token = None
        self.username = None
        self.role = None

    # ------------------------------------------------------------------ #
    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _request(self, method, path, **kwargs):
        url = f"{self.base_url}{path}"
        try:
            resp = requests.request(
                method, url, headers=self._headers(), timeout=TIMEOUT, **kwargs
            )
        except requests.RequestException as exc:
            raise ApiError(0, f"Cannot reach server at {self.base_url}.\n{exc}")

        try:
            body = resp.json()
        except ValueError:
            body = {}

        if not resp.ok:
            message = body.get("error") or body.get("detail") or resp.reason
            if resp.status_code == 423 and body.get("retry_after_minutes"):
                message += f" Try again in {body['retry_after_minutes']} min."
            raise ApiError(resp.status_code, message)
        return body

    # ------------------------------------------------------------------ #
    # Auth
    # ------------------------------------------------------------------ #
    def login(self, username, password, totp_code):
        data = self._request(
            "POST",
            "/api/login",
            json={"username": username, "password": password, "tfa_code": totp_code},
        )
        self.token = data["token"]
        self.username = data["username"]
        self.role = data["role"]
        return data

    def request_otp(self, username, password):
        """Ask the server to email a one-time login code."""
        return self._request(
            "POST", "/api/request-otp",
            json={"username": username, "password": password},
        )

    def register(self, username, email, password, confirm_password):
        return self._request(
            "POST",
            "/api/register",
            json={
                "username": username,
                "email": email,
                "password": password,
                "confirm_password": confirm_password,
            },
        )

    def logout(self):
        self.token = self.username = self.role = None

    # ------------------------------------------------------------------ #
    # Protected apps
    # ------------------------------------------------------------------ #
    def open_hr(self):
        return self._request("GET", "/api/protected/hr")

    def open_finance(self):
        return self._request("GET", "/api/protected/finance")

    def open_patients(self):
        return self._request("GET", "/api/protected/patients")

    # Patient CRUD (create/update/delete are Admin-only, enforced server-side)
    def create_patient(self, data):
        return self._request("POST", "/api/protected/patients", json=data)

    def update_patient(self, pid, data):
        return self._request("PUT", f"/api/protected/patients/{pid}", json=data)

    def delete_patient(self, pid):
        return self._request("DELETE", f"/api/protected/patients/{pid}")

    def open_documents(self):
        return self._request("GET", "/api/protected/documents")

    def read_document(self, name):
        return self._request("GET", f"/api/protected/documents/{name}")

    # ------------------------------------------------------------------ #
    # Admin / monitoring
    # ------------------------------------------------------------------ #
    def metrics(self):
        return self._request("GET", "/api/metrics")

    def access_logs(self, limit=100):
        return self._request("GET", f"/api/logs?limit={limit}")

    def login_history(self, limit=100):
        return self._request("GET", f"/api/login-history?limit={limit}")

    def site_access(self, limit=100):
        return self._request("GET", f"/api/site-access?limit={limit}")

    def users(self):
        return self._request("GET", "/api/users")

    def set_role(self, user_id, role):
        return self._request("PUT", f"/api/users/{user_id}/role", json={"role": role})

    def unlock(self, user_id):
        return self._request("POST", f"/api/users/{user_id}/unlock")

    def export_csv(self, dataset):
        """Return raw CSV text for an audit dataset (access-logs, login-history,
        site-access)."""
        url = f"{self.base_url}/api/export/{dataset}"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=TIMEOUT)
        except requests.RequestException as exc:
            raise ApiError(0, f"Cannot reach server: {exc}")
        if not resp.ok:
            raise ApiError(resp.status_code, "Export failed")
        return resp.text
