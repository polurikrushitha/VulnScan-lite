"""
VulnScan Lite — Alembic Initial Migration

Creates all tables:
  - users
  - scans
  - scan_results
  - security_checks
  - findings
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB
import sqlalchemy.dialects.postgresql as pg

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

GUID = sa.String(36).with_variant(UUID(as_uuid=False), "postgresql")
JSON_TYPE = sa.JSON().with_variant(JSONB, "postgresql")


def upgrade() -> None:
    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", GUID, primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ------------------------------------------------------------------
    # scans
    # ------------------------------------------------------------------
    op.create_table(
        "scans",
        sa.Column("id", GUID, primary_key=True),
        sa.Column("user_id", GUID, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column(
            "status",
            sa.Enum("queued", "running", "completed", "failed", name="scanstatus"),
            nullable=False,
            server_default="queued",
        ),
        sa.Column("score", sa.Float, nullable=True),
        sa.Column("grade", sa.String(10), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_scans_user_id", "scans", ["user_id"])

    # ------------------------------------------------------------------
    # scan_results
    # ------------------------------------------------------------------
    op.create_table(
        "scan_results",
        sa.Column("id", GUID, primary_key=True),
        sa.Column("scan_id", GUID, sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("ssl_data", JSON_TYPE, nullable=True),
        sa.Column("header_data", JSON_TYPE, nullable=True),
        sa.Column("cms_data", JSON_TYPE, nullable=True),
        sa.Column("html_data", JSON_TYPE, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_scan_results_scan_id", "scan_results", ["scan_id"], unique=True)

    # ------------------------------------------------------------------
    # security_checks
    # ------------------------------------------------------------------
    op.create_table(
        "security_checks",
        sa.Column("id", GUID, primary_key=True),
        sa.Column("scan_id", GUID, sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("check_name", sa.String(255), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column(
            "status",
            sa.Enum("passed", "failed", "warning", "info", name="checkstatus"),
            nullable=False,
        ),
        sa.Column("points", sa.Integer, nullable=False, server_default="0"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_security_checks_scan_id", "security_checks", ["scan_id"])

    # ------------------------------------------------------------------
    # findings
    # ------------------------------------------------------------------
    op.create_table(
        "findings",
        sa.Column("id", GUID, primary_key=True),
        sa.Column("scan_id", GUID, sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("check_name", sa.String(255), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("critical", "high", "medium", "low", "info", name="findingseverity"),
            nullable=False,
        ),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_security_checks_scan_id", table_name="security_checks")
    op.drop_table("security_checks")
    op.drop_index("ix_scan_results_scan_id", table_name="scan_results")
    op.drop_table("scan_results")
    op.drop_index("ix_scans_user_id", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

    # Drop enums
    sa.Enum(name="scanstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="checkstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="findingseverity").drop(op.get_bind(), checkfirst=True)
