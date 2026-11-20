"""Issue 23: email security and domain protection (23.1 SPF, 23.2 DMARC, 23.3 DKIM, 23.4 MTA-STS)."""

from .dkim import KnownSelector, read_dkim, selectors_from_spf
from .dmarc import organizational_domain, parse_dmarc, read_dmarc
from .dns import DnsResolver, TxtLookup
from .job import DkimJob, DmarcJob, MtaStsJob, SpfJob, targets_csv
from .mta_sts import PolicyFetcher, read_policy, read_sts_record, read_tlsrpt_record
from .spf import parse_spf, read_spf

__all__ = [
           "DkimJob",
           "DmarcJob",
           "DnsResolver",
           "KnownSelector",
           "MtaStsJob",
           "PolicyFetcher",
           "SpfJob",
           "TxtLookup",
           "organizational_domain",
           "parse_dmarc",
           "parse_spf",
           "read_dkim",
           "read_dmarc",
           "read_policy",
           "read_spf",
           "read_sts_record",
           "read_tlsrpt_record",
           "selectors_from_spf",
           "targets_csv",
]
