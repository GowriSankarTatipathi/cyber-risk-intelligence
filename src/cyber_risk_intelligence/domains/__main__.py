"""python -m cyber_risk_intelligence.domains wikidata companies-seed.csv > company_domains.csv"""

import argparse
import sys

from .wikidata import main as wikidata


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m cyber_risk_intelligence.domains")
    p.add_argument("command", choices=("wikidata",))
    p.add_argument("seed_csv")
    args = p.parse_args(argv)
    return wikidata(args.seed_csv)


if __name__ == "__main__":
    sys.exit(main())
