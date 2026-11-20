"""The certificate a company website presents (issue 10.1 follow-up)."""

import csv
import datetime as dt
import io
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import select, text

from cyber_risk_intelligence.ct.website import (
    TlsResult,
    WebsiteCertificateJob,
    fetch_certificate,
    hosts_for,
)
from cyber_risk_intelligence.domains import CompanyDomainsJob
from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models.certificates import WebsiteCertificateCheck

from . import factories as f

NOW = dt.datetime.now(dt.UTC)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA Org"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name("Test Root")).issuer_name(_name("Test Root"))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_leaf(ca_key, ca_cert, names, days=(-1, 90), serial=0xABC123):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(serial)
            .not_valid_before(NOW + dt.timedelta(days=days[0])).not_valid_after(NOW + dt.timedelta(days=days[1]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


@pytest.fixture
def tls_server(tmp_path):
    """Serve TLS on 127.0.0.1 with a leaf for 'localhost'; returns (port, path of the CA file, leaf)."""
    servers = []

    def start(days=(-1, 90)):
        ca_key, ca = make_ca()
        key, leaf = make_leaf(ca_key, ca, ["localhost"], days)
        cert_file, key_file, ca_file = tmp_path / "leaf.pem", tmp_path / "leaf.key", tmp_path / "ca.pem"
        cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sock.settimeout(5)
        servers.append(sock)

        def serve():
            while True:
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1)
                except (OSError, ssl.SSLError):
                    pass

        threading.Thread(target=serve, daemon=True).start()
        return sock.getsockname()[1], str(ca_file), leaf

    yield start
    for s in servers:
        s.close()


def test_trusted_certificate(tls_server):
    port, ca_file, leaf = tls_server()
    r = fetch_certificate("localhost", port, timeout=5, cafile=ca_file)
    assert r.outcome == "trusted" and r.message is None and r.tls_version.startswith("TLS")
    assert x509.load_der_x509_certificate(r.der).serial_number == leaf.serial_number


def test_untrusted_certificate_is_still_read_with_the_reason(tls_server):
    port, _, leaf = tls_server()
    r = fetch_certificate("localhost", port, timeout=5)  # the test CA is not a system root
    assert r.outcome == "not_trusted" and "certificate" in r.message
    assert x509.load_der_x509_certificate(r.der).serial_number == leaf.serial_number


def test_expired_certificate_is_not_trusted(tls_server):
    port, ca_file, _ = tls_server(days=(-30, -1))
    r = fetch_certificate("localhost", port, timeout=5, cafile=ca_file)
    assert r.outcome == "not_trusted" and "expired" in r.message


def test_nothing_listening_is_unreachable_not_a_missing_certificate():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    r = fetch_certificate("127.0.0.1", port, timeout=2)
    assert r.outcome == "unreachable" and r.der is None


def test_only_the_domain_and_its_www_host_are_asked():
    assert hosts_for("acme.example") == ["acme.example", "www.acme.example"]
    assert hosts_for("www.acme.example") == ["www.acme.example"]
    assert hosts_for("corporate.acme.example") == ["corporate.acme.example"]
    assert hosts_for("acme.co.uk") == ["acme.co.uk", "www.acme.co.uk"]


# --- the job ---------------------------------------------------------------------------------------------

def csv_bytes(header, *rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().encode()


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path / "evidence")


@pytest.fixture
def acme(session_factory, store):
    with session_factory() as s:
        f.company(s, "acme", "Acme")
        s.commit()
    run = run_import(session_factory, store, CompanyDomainsJob(), csv_bytes(
        ["company_key", "domain", "role", "source_url"],
        ["acme", "acme.example", "primary_website", "https://www.wikidata.org/entity/Q1"]),
        source_url="file:///domains.csv")
    assert run.status == "succeeded"


def run_job(sf, store, answers):
    calls = []

    def fetch(host):
        calls.append(host)
        return answers[host]

    run = run_import(sf, store, WebsiteCertificateJob(store, fetch=fetch),
                     csv_bytes(["company_key", "domain"], ["acme", "acme.example"]), source_url="file:///t.csv")
    return run, calls


def test_job_records_each_host(session_factory, store, acme):
    ca_key, ca = make_ca()
    _, leaf = make_leaf(ca_key, ca, ["acme.example", "www.acme.example"])
    der = leaf.public_bytes(serialization.Encoding.DER)
    answers = {"acme.example": TlsResult("acme.example", 443, "unreachable", "ConnectionRefusedError: refused"),
               "www.acme.example": TlsResult("www.acme.example", 443, "trusted", None, "TLSv1.3", der)}
    run, calls = run_job(session_factory, store, answers)
    assert run.status == "succeeded" and run.rows_inserted == 1 and calls == ["acme.example", "www.acme.example"]
    with session_factory() as s:
        rows = {c.host: c for c in s.scalars(select(WebsiteCertificateCheck))}
        latest = s.execute(text("SELECT host, outcome FROM latest_website_certificates ORDER BY host")).all()
    bare, www = rows["acme.example"], rows["www.acme.example"]
    assert (bare.outcome, bare.cert_sha256, bare.evidence_version_id) == ("unreachable", None, None)
    assert www.outcome == "trusted" and www.serial_number == "abc123" and www.common_name == "acme.example"
    assert www.names == ["acme.example", "www.acme.example"] and "O=Test CA Org" in www.issuer_name
    assert www.not_after > NOW + dt.timedelta(days=89) and www.evidence_version_id is not None
    assert [tuple(r) for r in latest] == [("acme.example", "unreachable"), ("www.acme.example", "trusted")]

    run, _ = run_job(session_factory, store, answers)  # same certificate again: unchanged, still recorded
    assert run.rows_unchanged == 1
    with session_factory() as s:
        assert len(s.scalars(select(WebsiteCertificateCheck)).all()) == 4


def test_summary_leaves_out_hosts_no_longer_asked(session_factory, store, acme, capsys):
    from cyber_risk_intelligence.ct.__main__ import website_summary

    gone = TlsResult("www.acme.example", 443, "unreachable", "gaierror")
    run_job(session_factory, store, {"acme.example": TlsResult("acme.example", 443, "unreachable", "timeout"),
                                     "www.acme.example": gone})
    with session_factory() as s:  # a later run that asked only the domain itself
        s.execute(text("UPDATE website_certificate_checks SET ingestion_run_id = NULL WHERE host = 'www.acme.example'"))
        s.commit()
    website_summary(session_factory)
    out = capsys.readouterr().out
    assert "acme.example" in out and "www.acme.example" not in out
