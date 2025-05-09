"""merge multiple heads

Revision ID: 923fb848e0ff
Revises: 2c1aa10e55eb, c0c22c84b56f
Create Date: 2025-05-09 17:26:05.335668

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '923fb848e0ff'
down_revision = ('2c1aa10e55eb', 'c0c22c84b56f')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
