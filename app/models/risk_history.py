from datetime import datetime, timezone

from app.extensions import db


class RiskHistory(db.Model):
    __tablename__ = "risk_history"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(
        db.Integer,
        db.ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    risk_score = db.Column(db.Integer, nullable=False)
    recorded_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
