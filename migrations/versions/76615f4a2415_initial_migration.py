"""initial migration

Revision ID: 76615f4a2415
Revises: 
Create Date: 2022-09-08 16:23:08.282303

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '76615f4a2415'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('Groups',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('Pavadinimas', sa.String(length=100), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_Groups')),
    sa.UniqueConstraint('Pavadinimas', name=op.f('uq_Groups_Pavadinimas'))
    )
    op.create_table('Users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('Vardas ir pavardė', sa.String(length=30), nullable=False),
    sa.Column('El. pašto adresas', sa.String(length=120), nullable=False),
    sa.Column('Slaptažodis', sa.String(length=60), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_Users')),
    sa.UniqueConstraint('El. pašto adresas', name=op.f('uq_Users_El. pašto adresas')),
    sa.UniqueConstraint('Slaptažodis', name=op.f('uq_Users_Slaptažodis')),
    sa.UniqueConstraint('Vardas ir pavardė', name=op.f('uq_Users_Vardas ir pavardė'))
    )
    op.create_table('Bills',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('group_id', sa.String(), nullable=True),
    sa.Column('user_full_name', sa.String(), nullable=True),
    sa.Column('Apibūdinimas', sa.String(length=50), nullable=False),
    sa.Column('Suma', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['group_id'], ['Groups.id'], name=op.f('fk_Bills_group_id_Groups')),
    sa.ForeignKeyConstraint(['user_full_name'], ['Users.id'], name=op.f('fk_Bills_user_full_name_Users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_Bills'))
    )
    op.create_table('association',
    sa.Column('Groups_id', sa.Integer(), nullable=False),
    sa.Column('Users_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['Groups_id'], ['Groups.id'], name=op.f('fk_association_Groups_id_Groups')),
    sa.ForeignKeyConstraint(['Users_id'], ['Users.id'], name=op.f('fk_association_Users_id_Users')),
    sa.PrimaryKeyConstraint('Groups_id', 'Users_id', name=op.f('pk_association'))
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('association')
    op.drop_table('Bills')
    op.drop_table('Users')
    op.drop_table('Groups')
    # ### end Alembic commands ###