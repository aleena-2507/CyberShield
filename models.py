from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(256),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="Analyst"
    )

    def __repr__(self):
        return f"<User {self.email}>"
    from datetime import datetime


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    incident_id = db.Column(
        db.String(30),
        unique=True,
        nullable=True
    )

    title = db.Column(
        db.String(150),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    affected_asset = db.Column(
        db.String(150),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="Open"
    )

    created_by = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    creator = db.relationship(
        "User",
        backref="incidents"
    )

    def __repr__(self):
        return f"<Incident {self.incident_id}>"

class IncidentNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey("incident.id"),
        nullable=False
    )

    note = db.Column(
        db.Text,
        nullable=False
    )

    created_by = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    author = db.relationship("User")

    incident = db.relationship(
        "Incident",
        backref=db.backref(
            "notes",
            lazy=True,
            cascade="all, delete-orphan"
        )
    )
class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    vulnerability_id = db.Column(
        db.String(30),
        unique=True,
        nullable=True
    )

    title = db.Column(
        db.String(150),
        nullable=False
    )

    affected_asset = db.Column(
        db.String(150),
        nullable=False
    )

    cve_id = db.Column(
        db.String(30),
        nullable=True
    )

    cvss_score = db.Column(
        db.Float,
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    remediation = db.Column(
        db.Text,
        nullable=False
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="Open"
    )

    created_by = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    creator = db.relationship(
        "User",
        backref="vulnerabilities"
    )

    def __repr__(self):
        return f"<Vulnerability {self.vulnerability_id}>"