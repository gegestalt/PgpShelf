"""empty message

Revision ID: 08713af524be
Revises: 5173f10ed5e5
Create Date: 2025-01-12 20:23:03.567336

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '08713af524be'
down_revision = '5173f10ed5e5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('encrypted_file',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=50), nullable=False),
    sa.Column('file_name', sa.String(length=255), nullable=False),
    sa.Column('encrypted_content', sa.LargeBinary(), nullable=False),
    sa.Column('upload_date', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=80), nullable=False),
    sa.Column('public_key', sa.Text(), nullable=False),
    sa.Column('private_key', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    op.drop_table('encrypted_file')
    # ### end Alembic commands ###
