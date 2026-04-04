from datetime import datetime, timezone

from app.extensions import db


class ScanImport(db.Model):
    __tablename__ = "scan_imports"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(512), nullable=False)
    imported_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    finding_count = db.Column(db.Integer, nullable=False, default=0)

    vulnerabilities = db.relationship(
        "Vulnerability",
        backref="scan_import",
        lazy="dynamic",
    )
