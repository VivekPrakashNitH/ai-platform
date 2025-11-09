"""Allow multiple credentials per provider with only one active

Revision ID: a1b2c3d4e5f6
Revises: 219033c644de
Create Date: 2025-01-20 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "219033c644de"
branch_labels = None
depends_on = None


def upgrade():
    # Drop the existing unique constraint on (organization_id, project_id, provider)
    op.drop_constraint(
        "uq_credential_org_project_provider", "credential", type_="unique"
    )

    # Create a partial unique index that ensures only one active credential
    # per (organization_id, project_id, provider) combination
    # Using raw SQL for partial unique index with WHERE clause
    op.execute(
        """
        CREATE UNIQUE INDEX uq_credential_org_project_provider_active
        ON credential (organization_id, project_id, provider)
        WHERE is_active = true
        """
    )


def downgrade():
    # Drop the partial unique index
    op.execute("DROP INDEX IF EXISTS uq_credential_org_project_provider_active")

    # Restore the original unique constraint
    op.create_unique_constraint(
        "uq_credential_org_project_provider",
        "credential",
        ["organization_id", "project_id", "provider"],
    )

