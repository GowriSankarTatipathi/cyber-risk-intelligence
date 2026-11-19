"""Ingestion runs and data quality (Issue 17.8).

Adds data_versions, ingestion_runs, ingestion_errors, validation_results and
ingestion_cursors.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-19 06:59:30.647715
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('data_versions',
    sa.Column('dataset_key', sa.Text(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('sha256', sa.Text(), nullable=False),
    sa.Column('evidence_version_id', sa.BigInteger(), nullable=False),
    sa.Column('row_count', sa.Integer(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name=op.f('ck_data_versions_sha256_format')),
    sa.CheckConstraint('version > 0', name=op.f('ck_data_versions_version_positive')),
    sa.ForeignKeyConstraint(['evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_data_versions_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_data_versions')),
    sa.UniqueConstraint('dataset_key', 'sha256', name='uq_data_versions_content'),
    sa.UniqueConstraint('dataset_key', 'version', name='uq_data_versions_version')
    )
    op.create_index(op.f('ix_data_versions_evidence_version_id'), 'data_versions', ['evidence_version_id'], unique=False)
    op.create_table('ingestion_runs',
    sa.Column('job_name', sa.Text(), nullable=False),
    sa.Column('source_id', sa.BigInteger(), nullable=False),
    sa.Column('status', sa.Text(), server_default='running', nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('input_evidence_version_id', sa.BigInteger(), nullable=True),
    sa.Column('data_version_id', sa.BigInteger(), nullable=True),
    sa.Column('retry_of_run_id', sa.BigInteger(), nullable=True),
    sa.Column('last_committed_row', sa.Integer(), server_default='0', nullable=False),
    sa.Column('resumed_from_row', sa.Integer(), server_default='0', nullable=False),
    sa.Column('rows_seen', sa.Integer(), server_default='0', nullable=False),
    sa.Column('rows_inserted', sa.Integer(), server_default='0', nullable=False),
    sa.Column('rows_updated', sa.Integer(), server_default='0', nullable=False),
    sa.Column('rows_unchanged', sa.Integer(), server_default='0', nullable=False),
    sa.Column('rows_rejected', sa.Integer(), server_default='0', nullable=False),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('parameters', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(status = 'running') = (finished_at IS NULL)", name=op.f('ck_ingestion_runs_finished_when_done')),
    sa.CheckConstraint("status IN ('running', 'succeeded', 'partial', 'failed')", name=op.f('ck_ingestion_runs_status')),
    sa.CheckConstraint('least(rows_seen, rows_inserted, rows_updated, rows_unchanged, rows_rejected, last_committed_row, resumed_from_row) >= 0', name=op.f('ck_ingestion_runs_counts_non_negative')),
    sa.ForeignKeyConstraint(['data_version_id'], ['data_versions.id'], name=op.f('fk_ingestion_runs_data_version_id_data_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['input_evidence_version_id'], ['evidence_versions.id'], name=op.f('fk_ingestion_runs_input_evidence_version_id_evidence_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['retry_of_run_id'], ['ingestion_runs.id'], name=op.f('fk_ingestion_runs_retry_of_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['source_id'], ['sources.id'], name=op.f('fk_ingestion_runs_source_id_sources'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ingestion_runs'))
    )
    op.create_index(op.f('ix_ingestion_runs_data_version_id'), 'ingestion_runs', ['data_version_id'], unique=False)
    op.create_index(op.f('ix_ingestion_runs_input_evidence_version_id'), 'ingestion_runs', ['input_evidence_version_id'], unique=False)
    op.create_index(op.f('ix_ingestion_runs_job_name'), 'ingestion_runs', ['job_name'], unique=False)
    op.create_index(op.f('ix_ingestion_runs_retry_of_run_id'), 'ingestion_runs', ['retry_of_run_id'], unique=False)
    op.create_index(op.f('ix_ingestion_runs_source_id'), 'ingestion_runs', ['source_id'], unique=False)
    op.create_table('ingestion_cursors',
    sa.Column('job_name', sa.Text(), nullable=False),
    sa.Column('source_id', sa.BigInteger(), nullable=False),
    sa.Column('cursor', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('last_run_id', sa.BigInteger(), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['last_run_id'], ['ingestion_runs.id'], name=op.f('fk_ingestion_cursors_last_run_id_ingestion_runs'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['source_id'], ['sources.id'], name=op.f('fk_ingestion_cursors_source_id_sources'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ingestion_cursors')),
    sa.UniqueConstraint('job_name', 'source_id', name='uq_ingestion_cursors_job')
    )
    op.create_table('ingestion_errors',
    sa.Column('run_id', sa.BigInteger(), nullable=False),
    sa.Column('stage', sa.Text(), nullable=False),
    sa.Column('code', sa.Text(), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('row_number', sa.Integer(), nullable=True),
    sa.Column('row_key', sa.Text(), nullable=True),
    sa.Column('field', sa.Text(), nullable=True),
    sa.Column('raw_row', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("stage IN ('parse', 'validate', 'write', 'run')", name=op.f('ck_ingestion_errors_stage')),
    sa.ForeignKeyConstraint(['run_id'], ['ingestion_runs.id'], name=op.f('fk_ingestion_errors_run_id_ingestion_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ingestion_errors'))
    )
    op.create_index(op.f('ix_ingestion_errors_run_id'), 'ingestion_errors', ['run_id'], unique=False)
    op.create_table('validation_results',
    sa.Column('run_id', sa.BigInteger(), nullable=False),
    sa.Column('rule', sa.Text(), nullable=False),
    sa.Column('severity', sa.Text(), nullable=False),
    sa.Column('rows_checked', sa.Integer(), nullable=False),
    sa.Column('rows_failed', sa.Integer(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("severity IN ('error', 'warning')", name=op.f('ck_validation_results_severity')),
    sa.CheckConstraint('rows_failed BETWEEN 0 AND rows_checked', name=op.f('ck_validation_results_failed_le_checked')),
    sa.ForeignKeyConstraint(['run_id'], ['ingestion_runs.id'], name=op.f('fk_validation_results_run_id_ingestion_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_validation_results')),
    sa.UniqueConstraint('run_id', 'rule', name='uq_validation_results_rule')
    )
    op.create_index(op.f('ix_validation_results_run_id'), 'validation_results', ['run_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_validation_results_run_id'), table_name='validation_results')
    op.drop_table('validation_results')
    op.drop_index(op.f('ix_ingestion_errors_run_id'), table_name='ingestion_errors')
    op.drop_table('ingestion_errors')
    op.drop_table('ingestion_cursors')
    op.drop_index(op.f('ix_ingestion_runs_source_id'), table_name='ingestion_runs')
    op.drop_index(op.f('ix_ingestion_runs_retry_of_run_id'), table_name='ingestion_runs')
    op.drop_index(op.f('ix_ingestion_runs_job_name'), table_name='ingestion_runs')
    op.drop_index(op.f('ix_ingestion_runs_input_evidence_version_id'), table_name='ingestion_runs')
    op.drop_index(op.f('ix_ingestion_runs_data_version_id'), table_name='ingestion_runs')
    op.drop_table('ingestion_runs')
    op.drop_index(op.f('ix_data_versions_evidence_version_id'), table_name='data_versions')
    op.drop_table('data_versions')
