"""auth2

Revision ID: 00f5a95ac83a
Revises: fa4a59aac643
Create Date: 2023-02-22 16:49:40.851115

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "00f5a95ac83a"
down_revision = "fa4a59aac643"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "auth_webauthn",
        sa.Column(
            "pk", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("user_id", postgresql.UUID(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("credential_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("credential_sign_count", sa.Integer(), nullable=False),
        sa.Column("created", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_used", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["auth_user.pk"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("pk"),
    )
    op.create_index(op.f("ix_auth_webauthn_user_id"), "auth_webauthn", ["user_id"], unique=False)
    op.add_column("auth_user", sa.Column("totp_secret", sa.String(), nullable=True))
    op.add_column("auth_user", sa.Column("totp_last_used", sa.String(), nullable=True))
    op.alter_column("auth_user", "active", existing_type=sa.BOOLEAN(), nullable=False)
    op.alter_column("auth_user", "override", existing_type=sa.BOOLEAN(), nullable=False)
    op.alter_column(
        "rpsl_database_journal",
        "serial_global",
        existing_type=sa.BIGINT(),
        nullable=False,
        existing_server_default=sa.text("nextval('rpsl_database_journal_serial_global_seq'::regclass)"),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column(
        "rpsl_database_journal",
        "serial_global",
        existing_type=sa.BIGINT(),
        nullable=True,
        existing_server_default=sa.text("nextval('rpsl_database_journal_serial_global_seq'::regclass)"),
    )
    op.alter_column("auth_user", "override", existing_type=sa.BOOLEAN(), nullable=True)
    op.alter_column("auth_user", "active", existing_type=sa.BOOLEAN(), nullable=True)
    op.drop_column("auth_user", "totp_last_used")
    op.drop_column("auth_user", "totp_secret")
    op.drop_index(op.f("ix_auth_webauthn_user_id"), table_name="auth_webauthn")
    op.drop_table("auth_webauthn")
    # ### end Alembic commands ###
