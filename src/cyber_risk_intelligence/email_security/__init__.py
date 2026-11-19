"""Issue 23: email security and domain protection (23.1 SPF, 23.2 DMARC)."""

from .dmarc import organizational_domain, parse_dmarc, read_dmarc
from .dns import DnsResolver, TxtLookup
from .job import DmarcJob, SpfJob, targets_csv
from .spf import parse_spf, read_spf

__all__ = ["DmarcJob", "DnsResolver", "SpfJob", "TxtLookup", "organizational_domain", "parse_dmarc",
           "parse_spf", "read_dmarc", "read_spf", "targets_csv"]
