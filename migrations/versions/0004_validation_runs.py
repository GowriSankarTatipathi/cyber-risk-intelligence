"""Validation runs (Issue 27.7).

Adds validation_runs and validation_findings. validation_results can now belong
to an ingestion run or a validation run (exactly one), and gains an "info" severity.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-19 07:25:47.709000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('validation_runs',
    sa.Column('status', sa.Text(), server_default='running', nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('checks_run', sa.Integer(), server_default='0', nullable=False),
    sa.Column('errors', sa.Integer(), server_default='0', nullable=False),
    sa.Column('warnings', sa.Integer(), server_default='0', nullable=False),
    sa.Column('scope', sa.Text(), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(status = 'running') = (finished_at IS NULL)", name=op.f('ck_validation_runs_finished_when_done')),
    sa.CheckConstraint("status IN ('running', 'passed', 'warnings', 'failed', 'error')", name=op.f('ck_validation_runs_status')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_validation_runs'))
    )
    op.create_table('validation_findings',
    sa.Column('validation_run_id', sa.BigInteger(), nullable=False),
    sa.Column('check_name', sa.Text(), nullable=False),
    sa.Column('severity', sa.Text(), nullable=False),
    sa.Column('table_name', sa.Text(), nullable=False),
    sa.Column('record_id', sa.BigInteger(), nullable=True),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("severity IN ('error', 'warning', 'info')", name=op.f('ck_validation_findings_severity')),
    sa.ForeignKeyConstraint(['validation_run_id'], ['validation_runs.id'], name=op.f('fk_validation_findings_validation_run_id_validation_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_validation_findings'))
    )
    op.create_index(op.f('ix_validation_findings_check_name'), 'validation_findings', ['check_name'], unique=False)
    op.create_index(op.f('ix_validation_findings_validation_run_id'), 'validation_findings', ['validation_run_id'], unique=False)
    op.add_column('validation_results', sa.Column('validation_run_id', sa.BigInteger(), nullable=True))
    op.add_column('validation_results', sa.Column('description', sa.Text(), nullable=True))
    op.alter_column('validation_results', 'run_id',
               existing_type=sa.BIGINT(),
               nullable=True)
    op.create_index(op.f('ix_validation_results_validation_run_id'), 'validation_results', ['validation_run_id'], unique=False)
    op.create_unique_constraint('uq_validation_results_validation_rule', 'validation_results', ['validation_run_id', 'rule'])
    op.create_foreign_key(op.f('fk_validation_results_validation_run_id_validation_runs'), 'validation_results', 'validation_runs', ['validation_run_id'], ['id'], ondelete='CASCADE')
    op.drop_constraint(op.f('ck_validation_results_severity'), 'validation_results', type_='check')
    op.create_check_constraint(op.f('ck_validation_results_severity'), 'validation_results',
                               "severity IN ('error', 'warning', 'info')")
    op.create_check_constraint(op.f('ck_validation_results_exactly_one_run'), 'validation_results',
                               'num_nonnulls(run_id, validation_run_id) = 1')


def downgrade() -> None:
    op.execute("DELETE FROM validation_results WHERE validation_run_id IS NOT NULL")
    op.drop_constraint(op.f('ck_validation_results_exactly_one_run'), 'validation_results', type_='check')
    op.drop_constraint(op.f('ck_validation_results_severity'), 'validation_results', type_='check')
    op.create_check_constraint(op.f('ck_validation_results_severity'), 'validation_results',
                               "severity IN ('error', 'warning')")
    op.drop_constraint(op.f('fk_validation_results_validation_run_id_validation_runs'), 'validation_results', type_='foreignkey')
    op.drop_constraint('uq_validation_results_validation_rule', 'validation_results', type_='unique')
    op.drop_index(op.f('ix_validation_results_validation_run_id'), table_name='validation_results')
    op.alter_column('validation_results', 'run_id',
               existing_type=sa.BIGINT(),
               nullable=False)
    op.drop_column('validation_results', 'description')
    op.drop_column('validation_results', 'validation_run_id')
    op.drop_index(op.f('ix_validation_findings_validation_run_id'), table_name='validation_findings')
    op.drop_index(op.f('ix_validation_findings_check_name'), table_name='validation_findings')
    op.drop_table('validation_findings')
    op.drop_table('validation_runs')
