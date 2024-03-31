"""creating roles and admin iuser

Revision ID: d053aeb9d82d
Revises: 4d2200c6b37b
Create Date: 2024-03-25 21:28:52.250207

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from repository import create_admin, create_roles
from database import Session, engine


# revision identifiers, used by Alembic.
revision: str = 'd053aeb9d82d'
down_revision: Union[str, None] = '4d2200c6b37b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

session = Session(engine)

def upgrade() -> None:
    create_roles(session)
    create_admin(session)


def downgrade() -> None:
    op.drop_table("users")
    op.drop_table("roles")
