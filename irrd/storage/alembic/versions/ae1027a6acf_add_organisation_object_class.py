"""initial db

Revision ID: ae1027a6acf
Revises: 8744b4b906bb
Create Date: 2023-01-25 14:37:13.472465

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'ae1027a6acf'
down_revision = '8744b4b906bb'
branch_labels = None
depends_on = None


def upgrade():
    # Manually added
    op.create_index(op.f('ix_rpsl_objects_parsed_data_mnt_ref'), 'rpsl_objects', [sa.text("((parsed_data->'mnt-ref'))")],
                    unique=False, postgresql_using='gin')
    op.create_index(op.f('ix_rpsl_objects_parsed_data_org_name'), 'rpsl_objects', [sa.text("((parsed_data->'org-name'))")],
                    unique=False, postgresql_using='gin')
    op.create_index(op.f('ix_rpsl_objects_parsed_data_org'), 'rpsl_objects', [sa.text("((parsed_data->'org'))")],
                    unique=False, postgresql_using='gin')


def downgrade():
    # Manually added
    op.drop_index(op.f('ix_rpsl_objects_parsed_data_mnt_ref'), table_name='rpsl_objects')
    op.drop_index(op.f('ix_rpsl_objects_parsed_data_org_name'), table_name='rpsl_objects')
    op.drop_index(op.f('ix_rpsl_objects_parsed_data_org'), table_name='rpsl_objects')
