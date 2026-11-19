import pytest

from cyber_risk_intelligence.normalize import (
    lei_checksum_ok,
    normalize_cik,
    normalize_domain,
    normalize_identifier,
    normalize_lei,
    normalize_name,
    normalize_ticker,
)

# Microsoft Corporation's published LEI.
MSFT_LEI = "INR2EJN1ERAN0W5ZP974"


def test_cik_is_zero_padded():
    assert normalize_cik("789019") == "0000789019"
    assert normalize_cik(" 0000789019 ") == "0000789019"


@pytest.mark.parametrize("bad", ["", "abc", "12345678901", "78-9019"])
def test_cik_rejects_bad_values(bad):
    with pytest.raises(ValueError):
        normalize_cik(bad)


def test_lei_checksum():
    assert lei_checksum_ok(MSFT_LEI)
    assert normalize_lei(MSFT_LEI.lower()) == MSFT_LEI
    with pytest.raises(ValueError, match="checksum"):
        normalize_lei(MSFT_LEI[:-1] + "5")
    with pytest.raises(ValueError):
        normalize_lei("TOO-SHORT")


def test_ticker_and_generic_identifier():
    assert normalize_ticker(" brk.b ") == "BRK.B"
    assert normalize_identifier("ticker", "msft") == "MSFT"
    assert normalize_identifier("ein", " 91-1144442 ") == "91-1144442"
    with pytest.raises(ValueError):
        normalize_identifier("other", "   ")


def test_name_normalization_is_for_search_only():
    assert normalize_name("Microsoft Corporation") == "microsoft"
    assert normalize_name("AT&T Inc.") == "at and t"
    assert normalize_name("Nestlé S.A.") == "nestle"
    # Different companies stay different after normalization.
    assert normalize_name("Apple Inc.") != normalize_name("Apple Hospitality REIT, Inc.")


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Microsoft.com", "microsoft.com"),
        ("https://www.microsoft.com/en-us/trust-center?x=1", "www.microsoft.com"),
        ("http://user@Example.COM:8443/", "example.com"),
        ("bücher.de.", "xn--bcher-kva.de"),
    ],
)
def test_domain_normalization(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("bad", ["", "localhost", "not a domain", "https://"])
def test_domain_rejects_bad_values(bad):
    with pytest.raises(ValueError):
        normalize_domain(bad)
