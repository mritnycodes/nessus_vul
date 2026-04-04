"""REST API v1 per VulScan PRD."""
from __future__ import annotations

import logging
from io import BytesIO

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import case, func

from app.extensions import db
from app.models import Asset, RiskHistory, Vulnerability
from app.services.ingest import ingest_nessus_stream
from app.services.retention import run_retention
from app.services.risk import aggregate_asset_risk_score

logger = logging.getLogger(__name__)

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

ALLOWED_UPLOAD_EXT = frozenset({".nessus", ".xml"})
GRANULARITY_TO_TRUNC = {
    "weekly": "week",
    "monthly": "month",
    "quarterly": "quarter",
}


@bp.get("/health")
def health():
    return jsonify({"status": "ok"})


def _allowed_upload_filename(name: str) -> bool:
    if not name:
        return False
    lower = name.lower()
    return any(lower.endswith(ext) for ext in ALLOWED_UPLOAD_EXT)


@bp.post("/scans/upload")
def scans_upload():
    if "file" not in request.files:
        return jsonify({"error": "Missing multipart field 'file'"}), 400
    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"error": "Empty file upload"}), 400
    filename = f.filename
    if not _allowed_upload_filename(filename):
        return (
            jsonify(
                {"error": "Invalid file type; allowed extensions: .nessus, .xml"}
            ),
            400,
        )
    raw = f.read()
    if not raw:
        return jsonify({"error": "Empty file body"}), 400

    try:
        summary = ingest_nessus_stream(
            BytesIO(raw),
            filename=filename,
            retention_days=current_app.config["DATA_RETENTION_DAYS"],
        )
    except ValueError as e:
        logger.info("Upload parse/validation error: %s", e)
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Upload ingest failed")
        return jsonify({"error": "Ingest failed", "detail": str(e)}), 400

    return jsonify(summary), 201


@bp.post("/maintenance/retention")
def maintenance_retention():
    days = current_app.config["DATA_RETENTION_DAYS"]
    summary = run_retention(days)
    return jsonify(summary), 200


@bp.get("/vulnerabilities")
def list_vulnerabilities():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "Query parameter 'ip' is required"}), 400
    asset = db.session.query(Asset).filter_by(ip_address=ip).first()
    if not asset:
        return jsonify({"ip": ip, "vulnerabilities": []}), 200
    sev = Vulnerability.severity
    severity_rank = case(
        (sev == "critical", 0),
        (sev == "high", 1),
        (sev == "medium", 2),
        (sev == "low", 3),
        (sev == "info", 4),
        else_=5,
    )
    rows = (
        db.session.query(Vulnerability)
        .filter_by(asset_id=asset.id)
        .order_by(severity_rank, Vulnerability.plugin_id)
        .all()
    )
    out = []
    for v in rows:
        out.append(
            {
                "plugin_id": v.plugin_id,
                "name": v.name,
                "port": v.port,
                "protocol": v.protocol,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "first_observed_at": v.first_observed_at.isoformat()
                if v.first_observed_at
                else None,
                "last_observed_at": v.last_observed_at.isoformat()
                if v.last_observed_at
                else None,
            }
        )
    return jsonify({"ip": ip, "vulnerabilities": out}), 200


@bp.get("/assets")
def list_assets():
    finding_count = func.count(Vulnerability.id).label("finding_count")
    q = (
        db.session.query(Asset, finding_count)
        .outerjoin(Vulnerability, Vulnerability.asset_id == Asset.id)
        .group_by(Asset.id)
        .order_by(Asset.ip_address)
    )
    items = []
    for asset, cnt in q.all():
        items.append(
            {
                "ip_address": asset.ip_address,
                "hostname": asset.hostname,
                "finding_count": int(cnt or 0),
                "created_at": asset.created_at.isoformat()
                if asset.created_at
                else None,
            }
        )
    return jsonify({"assets": items}), 200


def _risk_payload(asset: Asset):
    score = aggregate_asset_risk_score(db.session, asset.id)
    vulns = db.session.query(Vulnerability).filter_by(asset_id=asset.id).all()
    breakdown: dict[str, int] = {}
    for v in vulns:
        breakdown[v.severity] = breakdown.get(v.severity, 0) + 1
    return {
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "risk_score": score,
        "finding_count": len(vulns),
        "severity_counts": breakdown,
    }


@bp.get("/risk")
def risk_by_query():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "Query parameter 'ip' is required"}), 400
    asset = db.session.query(Asset).filter_by(ip_address=ip).first()
    if not asset:
        return jsonify({"error": "Unknown asset IP"}), 404
    return jsonify(_risk_payload(asset)), 200


@bp.get("/risk/<path:ip_address>")
def risk_by_path(ip_address: str):
    ip = ip_address.strip()
    if not ip:
        return jsonify({"error": "Invalid IP path"}), 404
    asset = db.session.query(Asset).filter_by(ip_address=ip).first()
    if not asset:
        return jsonify({"error": "Unknown asset IP"}), 404
    return jsonify(_risk_payload(asset)), 200


@bp.get("/trends")
def trends():
    bind = db.session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return (
            jsonify(
                {
                    "error": "Trends require PostgreSQL (date_trunc); "
                    "this deployment uses a different database dialect."
                }
            ),
            501,
        )

    gran = (request.args.get("granularity") or "").strip().lower()
    if gran not in GRANULARITY_TO_TRUNC:
        return (
            jsonify(
                {
                    "error": "Invalid granularity; use weekly, monthly, or quarterly"
                }
            ),
            400,
        )
    try:
        limit = int(request.args.get("limit") or 52)
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    limit = max(1, min(limit, 500))

    trunc_unit = GRANULARITY_TO_TRUNC[gran]
    bucket = func.date_trunc(trunc_unit, RiskHistory.recorded_at).label("bucket")

    q = (
        db.session.query(
            bucket,
            func.avg(RiskHistory.risk_score).label("avg_risk"),
            func.count(RiskHistory.id).label("samples"),
        )
        .group_by(bucket)
        .order_by(bucket.desc())
        .limit(limit)
    )
    rows_desc = q.all()
    series = []
    for row in reversed(rows_desc):
        series.append(
            {
                "period_start": row.bucket.isoformat() if row.bucket else None,
                "avg_risk_score": float(row.avg_risk)
                if row.avg_risk is not None
                else 0.0,
                "sample_count": int(row.samples or 0),
            }
        )
    return jsonify({"granularity": gran, "buckets": series}), 200
