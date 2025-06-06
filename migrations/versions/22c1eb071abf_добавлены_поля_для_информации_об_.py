"""Добавлены поля для информации об организаторе

Revision ID: 22c1eb071abf
Revises: bde7ce484156
Create Date: 2025-04-16 20:15:56.864613

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '22c1eb071abf'
down_revision = 'bde7ce484156'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('event_invitations', schema=None) as batch_op:
        batch_op.alter_column('inviter_id',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('invitee_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('organization_name', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('description', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('activity_field', sa.String(length=255), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('activity_field')
        batch_op.drop_column('description')
        batch_op.drop_column('organization_name')

    with op.batch_alter_table('event_invitations', schema=None) as batch_op:
        batch_op.alter_column('invitee_id',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('inviter_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###
