"""first migration

Revision ID: 4d2200c6b37b
Revises: 
Create Date: 2024-03-25 21:09:41.488010

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from database import create_database, delete_database


# revision identifiers, used by Alembic.
revision: str = '4d2200c6b37b'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    create_database()

def downgrade() -> None:
    delete_database()
