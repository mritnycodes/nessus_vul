"""Ingest Nessus XML: upsert assets/vulnerabilities, snapshot risk, retention."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import BinaryIO, Set

from sqlalchemy import and_
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.extensions import db
from app.models import Asset, RiskHistory, ScanImport, Vulnerability
from app.services.nessus_parser import parse_nessus_stream
from app.services.retention import run_retention
from app.services.risk import aggregate_asset_risk_score

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get_or_create_asset(session, ip_address: str, hostname: str | None) -> Asset:
    asset = session.query(Asset).filter_by(ip_address=ip_address).first()
    if asset is None:
        asset = Asset(ip_address=ip_address, hostname=hostname)
        session.add(asset)
        session.flush()
        return asset
    if hostname and (not asset.hostname or len(hostname) > len(asset.hostname or "")):
        asset.hostname = hostname
    return asset


def _upsert_vulnerability_pg(session, values: dict) -> None:
    stmt = pg_insert(Vulnerability).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["asset_id", "plugin_id", "port", "protocol"],
        set_={
            "last_observed_at": stmt.excluded.last_observed_at,
            "name": stmt.excluded.name,
            "severity": stmt.excluded.severity,
            "cvss_score": stmt.excluded.cvss_score,
            "scan_import_id": stmt.excluded.scan_import_id,
        },
    )
    session.execute(stmt)


def _upsert_vulnerability_generic(session, values: dict) -> None:
    existing = (
        session.query(Vulnerability)
        .filter(
            and_(
                Vulnerability.asset_id == values["asset_id"],
                Vulnerability.plugin_id == values["plugin_id"],
                Vulnerability.port == values["port"],
                Vulnerability.protocol == values["protocol"],
            )
        )
        .first()
    )
    if existing:
        existing.last_observed_at = values["last_observed_at"]
        existing.name = values["name"]
        existing.severity = values["severity"]
        existing.cvss_score = values["cvss_score"]
        existing.scan_import_id = values["scan_import_id"]
    else:
        session.add(Vulnerability(**values))


def ingest_nessus_stream(stream: BinaryIO, filename: str, retention_days: int) -> dict:
    findings = parse_nessus_stream(stream)
    session = db.session
    bind = session.get_bind()
    use_pg = bind is not None and bind.dialect.name == "postgresql"

    scan = ScanImport(filename=filename or "upload", finding_count=len(findings))
    session.add(scan)
    session.flush()

    affected: Set[int] = set()
    now = _now()

    try:
        for f in findings:
            asset = _get_or_create_asset(session, f.ip_address, f.hostname)
            affected.add(asset.id)
            values = {
                "asset_id": asset.id,
                "scan_import_id": scan.id,
                "plugin_id": f.plugin_id,
                "name": f.name,
                "port": f.port,
                "protocol": f.protocol,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "first_observed_at": now,
                "last_observed_at": now,
            }
            if use_pg:
                _upsert_vulnerability_pg(session, values)
            else:
                _upsert_vulnerability_generic(session, values)

        scan.finding_count = len(findings)
        session.flush()

        for aid in affected:
            score = aggregate_asset_risk_score(session, aid)
            session.add(RiskHistory(asset_id=aid, risk_score=score, recorded_at=now))

        retention_summary = run_retention(
            retention_days, session=session, do_commit=False
        )
        session.commit()
    except Exception:
        logger.exception("Ingest failed for filename=%s", filename)
        session.rollback()
        raise

    return {
        "scan_import_id": scan.id,
        "findings_parsed": len(findings),
        "assets_touched": len(affected),
        "retention": retention_summary,
    }
