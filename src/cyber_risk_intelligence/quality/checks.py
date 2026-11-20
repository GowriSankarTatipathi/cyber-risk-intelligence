"""The data-quality checks run by ``run_validation``.

Each check is a read-only query. ``failing_sql`` returns one row per affected
record as ``(table_name, record_id, message)``; ``checked_sql`` returns how many
rows the check looked at.

NULL means "unknown" throughout this database (see 17.1), so checks never fail
a record just because a value is unknown. Where a check depends on a value it
skips rows where that value is NULL, and the description says so.

Several checks repeat what a constraint already enforces. They are there to
catch data that slipped past one (a constraint added NOT VALID, or one that was
dropped and recreated) and to give a per-record report instead of a single error.
"""

from dataclasses import dataclass
from typing import Literal

Severity = Literal["error", "warning", "info"]

VALIDITY_TABLES = (
    "entity_identifiers", "entity_relationships", "company_aliases", "company_domains", "industry_classifications",
)
PROVENANCE_TABLES = {
    # table -> evidence_links column
    "legal_entities": "legal_entity_id",
    "entity_identifiers": "entity_identifier_id",
    "entity_relationships": "entity_relationship_id",
    "company_aliases": "company_alias_id",
    "company_domains": "company_domain_id",
    "industry_classifications": "industry_classification_id",
    "index_memberships": "index_membership_id",
}
LINK_TARGET_TABLES = {"company_id": "companies", **{v: k for k, v in PROVENANCE_TABLES.items()}}


@dataclass(frozen=True)
class Check:
    name: str
    severity: Severity
    description: str
    checked_sql: str
    failing_sql: str


def _period(alias: str) -> str:
    """The validity range, or an empty range when the dates are reversed (so overlap checks can't crash)."""
    return (f"CASE WHEN {alias}.valid_to <= {alias}.valid_from THEN 'empty'::daterange "
            f"ELSE daterange({alias}.valid_from, {alias}.valid_to, '[)') END")


def _union(parts: list[str]) -> str:
    return "\nUNION ALL\n".join(parts)


def _count(tables) -> str:
    return "SELECT " + " + ".join(f"(SELECT count(*) FROM {t})" for t in tables)


CHECKS: tuple[Check, ...] = (
    Check(
        "constraints_validated", "error",
        "Every constraint in the schema has been validated against existing rows (none left NOT VALID).",
        "SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace WHERE n.nspname = current_schema()",
        """SELECT c.conrelid::regclass::text, NULL::bigint, 'constraint ' || c.conname || ' is NOT VALID'
           FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
           WHERE n.nspname = current_schema() AND NOT c.convalidated""",
    ),
    Check(
        "valid_period_order", "error",
        "valid_to must be after valid_from. Open or unknown ends (NULL) are allowed.",
        _count(VALIDITY_TABLES),
        _union([f"""SELECT '{t}', id, 'valid_to ' || valid_to || ' is not after valid_from ' || valid_from
                    FROM {t} WHERE valid_from IS NOT NULL AND valid_to IS NOT NULL AND valid_to <= valid_from"""
                for t in VALIDITY_TABLES]),
    ),
    Check(
        "duplicate_active_identifier", "error",
        "The same normalized identifier (scheme + issuer scope + value) is active for two rows at once. "
        "Unknown dates count as unbounded.",
        "SELECT count(*) FROM entity_identifiers",
        """SELECT 'entity_identifiers', a.id,
                  a.scheme || ' ' || a.normalized_value || ' overlaps identifier ' || b.id
           FROM entity_identifiers a JOIN entity_identifiers b
             ON a.scheme = b.scheme AND a.issuer_scope = b.issuer_scope AND a.normalized_value = b.normalized_value
            AND a.id <> b.id
            AND """ + _period("a") + " && " + _period("b"),
    ),
    Check(
        "duplicate_active_relationship", "error",
        "The same child, parent and relationship type overlap in time.",
        "SELECT count(*) FROM entity_relationships",
        """SELECT 'entity_relationships', a.id, 'overlaps relationship ' || b.id
           FROM entity_relationships a JOIN entity_relationships b
             ON a.child_entity_id = b.child_entity_id AND a.parent_entity_id = b.parent_entity_id
            AND a.relationship_type = b.relationship_type AND a.id <> b.id
            AND """ + _period("a") + " && " + _period("b"),
    ),
    Check(
        "ownership_cycle", "error",
        "Two entities are each other's parent (subsidiary_of or acquired_by) during the same period.",
        "SELECT count(*) FROM entity_relationships WHERE relationship_type IN ('subsidiary_of', 'acquired_by')",
        """SELECT 'entity_relationships', a.id,
                  'entity ' || a.child_entity_id || ' and ' || a.parent_entity_id || ' are each other''s parent (with relationship ' || b.id || ')'
           FROM entity_relationships a JOIN entity_relationships b
             ON a.child_entity_id = b.parent_entity_id AND a.parent_entity_id = b.child_entity_id
            AND a.relationship_type IN ('subsidiary_of', 'acquired_by')
            AND b.relationship_type IN ('subsidiary_of', 'acquired_by')
            AND """ + _period("a") + " && " + _period("b"),
    ),
    Check(
        "date_in_future", "error",
        "Dates that describe the past (valid_from, observation, publication, archive capture, index check) "
        "are not later than today. Unknown dates are skipped.",
        _count((*VALIDITY_TABLES, "index_memberships", "evidence_versions")),
        _union(
            [f"SELECT '{t}', id, 'valid_from ' || valid_from || ' is in the future' FROM {t} WHERE valid_from > current_date"
             for t in VALIDITY_TABLES]
            + ["SELECT 'index_memberships', id, 'observed_on ' || observed_on || ' is in the future' "
               "FROM index_memberships WHERE observed_on > current_date"]
            + [f"SELECT 'evidence_versions', id, '{c} ' || {c} || ' is in the future' "
               f"FROM evidence_versions WHERE {c} > now() + interval '1 day'"
               for c in ("published_at", "observed_at", "archive_captured_at")]
        ),
    ),
    Check(
        "archive_capture_after_collection", "error",
        "An archive copy can't be captured after we collected it.",
        "SELECT count(*) FROM evidence_versions WHERE archive_captured_at IS NOT NULL",
        """SELECT 'evidence_versions', id, 'archive_captured_at ' || archive_captured_at || ' is after collected_at ' || collected_at
           FROM evidence_versions WHERE archive_captured_at > collected_at""",
    ),
    Check(
        "published_after_collection", "warning",
        "A document's publication date is after we collected it. Usually a wrong or 'last updated' date.",
        "SELECT count(*) FROM evidence_versions WHERE published_at IS NOT NULL",
        """SELECT 'evidence_versions', id, 'published_at ' || published_at || ' is after collected_at ' || collected_at
           FROM evidence_versions WHERE published_at > collected_at + interval '1 day'""",
    ),
    Check(
        "orphan_evidence_link", "error",
        "Every evidence link points at an existing record and capture.",
        "SELECT count(*) FROM evidence_links",
        _union(
            [f"""SELECT 'evidence_links', l.id, '{col} ' || l.{col} || ' does not exist in {tbl}'
                 FROM evidence_links l LEFT JOIN {tbl} t ON t.id = l.{col}
                 WHERE l.{col} IS NOT NULL AND t.id IS NULL"""
             for col, tbl in LINK_TARGET_TABLES.items()]
            + ["""SELECT 'evidence_links', l.id, 'evidence_version ' || l.evidence_version_id || ' does not exist'
                  FROM evidence_links l LEFT JOIN evidence_versions v ON v.id = l.evidence_version_id WHERE v.id IS NULL"""]
        ),
    ),
    Check(
        "verified_without_evidence", "error",
        "A value marked 'verified' must have at least one stored piece of evidence supporting it.",
        _count(PROVENANCE_TABLES),
        _union([f"""SELECT '{t}', t.id, 'verified but has no supporting evidence link'
                    FROM {t} t WHERE t.verification_status = 'verified'
                    AND NOT EXISTS (SELECT 1 FROM evidence_links l WHERE l.{col} = t.id AND l.relation = 'supports')"""
                for t, col in PROVENANCE_TABLES.items()]),
    ),
    Check(
        "missing_source_reference", "warning",
        "A collected value has neither a source_ref citation nor an evidence link, so we can't say where it came from.",
        _count(PROVENANCE_TABLES),
        _union([f"""SELECT '{t}', t.id, 'no source_ref and no evidence link'
                    FROM {t} t WHERE t.source_ref IS NULL
                    AND NOT EXISTS (SELECT 1 FROM evidence_links l WHERE l.{col} = t.id)"""
                for t, col in PROVENANCE_TABLES.items()]),
    ),
    Check(
        "company_without_legal_entity", "warning",
        "A company has no legal entity yet, so identifiers and filings can't be attached to it.",
        "SELECT count(*) FROM companies",
        """SELECT 'companies', c.id, c.company_key || ' has no legal entity'
           FROM companies c WHERE NOT EXISTS (SELECT 1 FROM legal_entities e WHERE e.company_id = c.id)""",
    ),
    Check(
        "possible_duplicate_company", "warning",
        "Companies share a normalized name. Review them; they are never merged automatically.",
        "SELECT count(*) FROM companies",
        """SELECT 'companies', a.id, a.company_key || ' has the same normalized name as ' || b.company_key
           FROM companies a JOIN companies b ON a.normalized_name = b.normalized_name AND a.id <> b.id""",
    ),
    Check(
        "unlinked_legal_entity", "info",
        "A legal entity is not linked to a company group yet. This is allowed: the group is unknown, not absent.",
        "SELECT count(*) FROM legal_entities",
        "SELECT 'legal_entities', id, legal_name || ' has no company yet' FROM legal_entities WHERE company_id IS NULL",
    ),
    Check(
        "unreferenced_evidence_object", "warning",
        "Stored evidence bytes that no capture refers to.",
        "SELECT count(*) FROM evidence_objects",
        """SELECT 'evidence_objects', o.id, 'no evidence_version refers to sha256 ' || o.sha256
           FROM evidence_objects o WHERE NOT EXISTS (SELECT 1 FROM evidence_versions v WHERE v.evidence_object_id = o.id)""",
    ),
    Check(
        "ingestion_run_stuck", "warning",
        "An import has been 'running' for more than 6 hours; it probably died without being marked failed.",
        "SELECT count(*) FROM ingestion_runs",
        """SELECT 'ingestion_runs', id, job_name || ' started ' || started_at || ' and is still running'
           FROM ingestion_runs WHERE status = 'running' AND started_at < now() - interval '6 hours'""",
    ),
    Check(
        "failed_ingestion_not_retried", "warning",
        "An import failed and nothing has retried it or run the same job successfully since.",
        "SELECT count(*) FROM ingestion_runs WHERE status = 'failed'",
        """SELECT 'ingestion_runs', f.id, f.job_name || ' failed: ' || coalesce(f.error_message, 'no message')
           FROM ingestion_runs f
           WHERE f.status = 'failed'
             AND NOT EXISTS (SELECT 1 FROM ingestion_runs r WHERE r.retry_of_run_id = f.id)
             AND NOT EXISTS (SELECT 1 FROM ingestion_runs r WHERE r.job_name = f.job_name
                             AND r.status IN ('succeeded', 'partial') AND r.started_at > f.started_at)""",
    ),
    Check(
        "spf_lookup_failed", "warning",
        "The latest SPF lookup for a company domain failed (timeout, SERVFAIL ...). Run it again; "
        "a failed lookup says nothing about whether the domain publishes SPF.",
        "SELECT count(*) FROM latest_spf_observations",
        """SELECT 'domains', o.domain_id, d.name || ' last SPF lookup failed: ' || coalesce(o.problems->>0, '')
           FROM latest_spf_observations o JOIN domains d ON d.id = o.domain_id WHERE o.status = 'lookup_failed'""",
    ),
    Check(
        "company_domain_without_spf_lookup", "info",
        "A current company domain has never had its SPF looked up, so its SPF is unknown.",
        "SELECT count(*) FROM company_domains WHERE valid_to IS NULL",
        """SELECT 'company_domains', cd.id, d.name || ' has no SPF lookup yet'
           FROM company_domains cd JOIN domains d ON d.id = cd.domain_id
           WHERE cd.valid_to IS NULL AND NOT EXISTS (
             SELECT 1 FROM email_security_observations o WHERE o.domain_id = cd.domain_id AND o.control = 'spf')""",
    ),
    Check(
        "dmarc_lookup_failed", "warning",
        "The latest DMARC lookup for a company domain failed. Run it again; "
        "a failed lookup says nothing about whether the domain publishes DMARC.",
        "SELECT count(*) FROM latest_dmarc_observations",
        """SELECT 'domains', o.domain_id, d.name || ' last DMARC lookup failed: ' || coalesce(o.problems->>0, '')
           FROM latest_dmarc_observations o JOIN domains d ON d.id = o.domain_id WHERE o.status = 'lookup_failed'""",
    ),
    Check(
        "company_domain_without_dmarc_lookup", "info",
        "A current company domain has never had its DMARC looked up, so its DMARC is unknown.",
        "SELECT count(*) FROM company_domains WHERE valid_to IS NULL",
        """SELECT 'company_domains', cd.id, d.name || ' has no DMARC lookup yet'
           FROM company_domains cd JOIN domains d ON d.id = cd.domain_id
           WHERE cd.valid_to IS NULL AND NOT EXISTS (
             SELECT 1 FROM email_security_observations o WHERE o.domain_id = cd.domain_id AND o.control = 'dmarc')""",
    ),
    Check(
        "assurance_verified_from_company_source", "error",
        "A certification is marked verified but its evidence comes from the company's own website. "
        "Only an independent register can verify one.",
        "SELECT count(*) FROM security_assurances WHERE verification_status = 'verified'",
        """SELECT 'security_assurances', a.id, a.framework || ' marked verified from company source ' || s.source_key
           FROM security_assurances a JOIN evidence_versions v ON v.id = a.evidence_version_id
           JOIN sources s ON s.id = v.source_id
           WHERE a.verification_status = 'verified' AND s.source_type = 'company_website'""",
    ),
    Check(
        "assurance_register_lapsed_but_claimed", "warning",
        "The company still claims a certification that its register entry shows as withdrawn, suspended or expired, "
        "and no register shows it active. Skipped when the register status is unknown.",
        "SELECT count(*) FROM company_assurance_summary WHERE company_claims + company_documents > 0",
        """SELECT 'companies', v.company_id, v.framework || coalesce(' ' || v.report_type, '')
                  || ' is claimed by the company but the register entry is no longer active'
           FROM company_assurance_summary v
           WHERE v.status = 'verified_lapsed' AND v.company_claims + v.company_documents > 0
             AND NOT EXISTS (SELECT 1 FROM security_assurances a WHERE a.company_id = v.company_id
                             AND a.framework = v.framework AND a.report_type IS NOT DISTINCT FROM v.report_type
                             AND a.basis = 'issuer_directory' AND a.directory_status = 'unknown')""",
    ),
    Check(
        "assurance_claim_expired", "info",
        "The latest certificate or report date we have for a claimed certification has passed. "
        "A newer one may exist that we have not seen; skipped when no date is known.",
        "SELECT count(*) FROM company_assurance_summary WHERE latest_valid_until IS NOT NULL",
        """SELECT 'companies', v.company_id, v.framework || coalesce(' ' || v.report_type, '')
                  || ' latest known validity ended ' || v.latest_valid_until
           FROM company_assurance_summary v WHERE v.status = 'claimed' AND v.validity = 'expired'""",
    ),
    Check(
        "backup_frequency_not_stated", "info",
        "The company says it backs up its own systems but none of its statements says how often. "
        "The frequency stays unknown; it is not assumed.",
        """SELECT count(DISTINCT company_id) FROM backup_policy_claims
           WHERE scope = 'own_practice' AND assertion = 'affirmed'""",
        """SELECT 'companies', b.company_id, 'backups mentioned in '
                  || count(DISTINCT b.claim_hash) || ' statement(s), frequency not stated'
           FROM backup_policy_claims b
           WHERE b.scope = 'own_practice' AND b.assertion = 'affirmed'
           GROUP BY b.company_id
           HAVING bool_and(b.frequency_class IS NULL)""",
    ),
)

EVIDENCE_BYTES_CHECK = Check(
    "evidence_bytes_integrity", "error",
    "Each stored evidence object can be read back and still matches its SHA-256 and size.",
    "SELECT count(*) FROM evidence_objects", "",
)
