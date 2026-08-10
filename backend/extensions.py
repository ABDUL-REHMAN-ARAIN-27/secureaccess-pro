"""
Shared Flask extension instances.

Kept in a separate module so models and route blueprints can import `db`
without creating circular imports with the application factory in app.py.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

db = SQLAlchemy()
jwt = JWTManager()
