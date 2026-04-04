"""initial schema

Revision ID: 001_initial
Revises:
Create Date: 2026-04-04

"""
from alembic import op
import sqlalchemy as sa


revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("hostname", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_assets_ip_address"), "assets", ["ip_address"], unique=True)

    op.create_table(
        "scan_imports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_scan_imports_imported_at"), "scan_imports", ["imported_at"], unique=False
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("scan_import_id", sa.Integer(), nullable=True),
        sa.Column("plugin_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=2048), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_import_id"], ["scan_imports.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "asset_id",
            "plugin_id",
            "port",
            "protocol",
            name="uq_vuln_asset_plugin_port_proto",
        ),
    )
    op.create_index(
        op.f("ix_vulnerabilities_asset_id"), "vulnerabilities", ["asset_id"], unique=False
    )
    op.create_index(
        op.f("ix_vulnerabilities_scan_import_id"),
        "vulnerabilities",
        ["scan_import_id"],
        unique=False,
    )

    op.create_table(
        "risk_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_risk_history_asset_id"), "risk_history", ["asset_id"], unique=False
    )
    op.create_index(
        op.f("ix_risk_history_recorded_at"), "risk_history", ["recorded_at"], unique=False
    )


def downgrade():
    op.drop_index(op.f("ix_risk_history_recorded_at"), table_name="risk_history")
    op.drop_index(op.f("ix_risk_history_asset_id"), table_name="risk_history")
    op.drop_table("risk_history")
    op.drop_index(op.f("ix_vulnerabilities_scan_import_id"), table_name="vulnerabilities")
    op.drop_index(op.f("ix_vulnerabilities_asset_id"), table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_index(op.f("ix_scan_imports_imported_at"), table_name="scan_imports")
    op.drop_table("scan_imports")
    op.drop_index(op.f("ix_assets_ip_address"), table_name="assets")
    op.drop_table("assets")
