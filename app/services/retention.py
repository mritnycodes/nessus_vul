"""Data retention: purge by age, then orphan assets."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import exists
from sqlalchemy.orm import Session

from app.extensions import db
from app.models import Asset, RiskHistory, ScanImport, Vulnerability


def retention_cutoff(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def run_retention(
    days: int,
    *,
    session: Session | None = None,
    do_commit: bool = True,
) -> dict:
    """
    Order: risk_history → vulnerabilities (by first_observed_at) → scan_imports → orphan assets.
    When do_commit is False, caller owns the transaction (e.g. ingest).
    """
    cutoff = retention_cutoff(days)
    sess = session if session is not None else db.session

    deleted_risk_history = sess.query(RiskHistory).filter(
        RiskHistory.recorded_at < cutoff
    ).delete(synchronize_session=False)

    deleted_vulnerabilities = sess.query(Vulnerability).filter(
        Vulnerability.first_observed_at < cutoff
    ).delete(synchronize_session=False)

    deleted_scan_imports = sess.query(ScanImport).filter(
        ScanImport.imported_at < cutoff
    ).delete(synchronize_session=False)

    has_vuln = exists().where(Vulnerability.asset_id == Asset.id)
    orphan_q = sess.query(Asset).filter(~has_vuln)
    deleted_orphan_assets = orphan_q.count()
    orphan_q.delete(synchronize_session=False)

    if do_commit:
        sess.commit()
    return {
        "deleted_risk_history": deleted_risk_history,
        "deleted_vulnerabilities": deleted_vulnerabilities,
        "deleted_scan_imports": deleted_scan_imports,
        "deleted_orphan_assets": deleted_orphan_assets,
        "cutoff_utc": cutoff.isoformat(),
    }
