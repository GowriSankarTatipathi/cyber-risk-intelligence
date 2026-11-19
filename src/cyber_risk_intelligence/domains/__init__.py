"""Company domains: load them from a sourced CSV (prerequisite for 23.x email and DNS checks)."""

from .job import CompanyDomainsJob, normalize_domain

__all__ = ["CompanyDomainsJob", "normalize_domain"]
