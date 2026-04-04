"""Fixed severity weights per PRD."""

SEVERITY_WEIGHTS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 1,
    "info": 0,
    "informational": 0,
    "none": 0,
    "unknown": 0,
}


def severity_label_to_weight(label: str) -> int:
    if not label:
        return 0
    key = label.strip().lower()
    return SEVERITY_WEIGHTS.get(key, 0)


def aggregate_asset_risk_score(session, asset_id: int) -> int:
    from app.models import Vulnerability

    total = 0
    for row in session.query(Vulnerability.severity).filter_by(asset_id=asset_id).all():
        total += severity_label_to_weight(row[0])
    return total
