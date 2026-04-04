from datetime import datetime, timezone

from app.extensions import db


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(512), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    vulnerabilities = db.relationship(
        "Vulnerability",
        backref="asset",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    risk_history = db.relationship(
        "RiskHistory",
        backref="asset",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
