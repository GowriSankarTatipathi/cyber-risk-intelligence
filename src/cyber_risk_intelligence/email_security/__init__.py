"""Issue 23: email security and domain protection (23.1 SPF)."""

from .dns import DnsResolver, TxtLookup
from .job import SpfJob, targets_csv
from .spf import parse_spf, read_spf

__all__ = ["DnsResolver", "SpfJob", "TxtLookup", "parse_spf", "read_spf", "targets_csv"]
