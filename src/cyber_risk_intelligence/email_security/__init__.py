"""Issue 23: email security and domain protection (23.1 SPF, 23.2 DMARC, 23.3 DKIM)."""

from .dkim import KnownSelector, read_dkim, selectors_from_spf
from .dmarc import organizational_domain, parse_dmarc, read_dmarc
from .dns import DnsResolver, TxtLookup
from .job import DkimJob, DmarcJob, SpfJob, targets_csv
from .spf import parse_spf, read_spf

__all__ = [
           "DkimJob",
           "DmarcJob",
           "DnsResolver",
           "KnownSelector",
           "SpfJob",
           "TxtLookup",
           "organizational_domain",
           "parse_dmarc",
           "parse_spf",
           "read_dkim",
           "read_dmarc",
           "read_spf",
           "selectors_from_spf",
           "targets_csv",
]
