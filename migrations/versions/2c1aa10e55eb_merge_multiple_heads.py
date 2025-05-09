"""merge multiple heads

Revision ID: 2c1aa10e55eb
Revises: 46844ec6ac20, 9628b126675a
Create Date: 2025-05-09 15:58:12.624154

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2c1aa10e55eb'
down_revision = ('46844ec6ac20', '9628b126675a')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
