"""Initial database migration

Revision ID: 001
Revises: 
Create Date: 2024-01-01

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers, used by Alembic
revision = '001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Create threat_intelligence table
    op.create_table(
        'threat_intelligence',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('threat_type', sa.String(), nullable=False),
        sa.Column('source', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('indicators', JSON, nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.Column('mitre_techniques', JSON, nullable=True),
        sa.Column('geographic_location', JSON, nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('raw_data', JSON, nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_intelligence_threat_type'), 'threat_intelligence', ['threat_type'], unique=False)
    
    # Create threat_actors table
    op.create_table(
        'threat_actors',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('aliases', JSON, nullable=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('known_tools', JSON, nullable=True),
        sa.Column('ttps', JSON, nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_actors_name'), 'threat_actors', ['name'], unique=False)
    
    # Create iocs table
    op.create_table(
        'iocs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('type', sa.String(), nullable=False),
        sa.Column('value', sa.String(), nullable=False),
        sa.Column('threat_intel_id', sa.Integer(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('metadata', JSON, nullable=True),
        sa.ForeignKeyConstraint(['threat_intel_id'], ['threat_intelligence.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_iocs_type'), 'iocs', ['type'], unique=False)
    op.create_index(op.f('ix_iocs_value'), 'iocs', ['value'], unique=False)

def downgrade():
    op.drop_index(op.f('ix_iocs_value'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_type'), table_name='iocs')
    op.drop_table('iocs')
    
    op.drop_index(op.f('ix_threat_actors_name'), table_name='threat_actors')
    op.drop_table('threat_actors')
    
    op.drop_index(op.f('ix_threat_intelligence_threat_type'), table_name='threat_intelligence')
    op.drop_table('threat_intelligence') 