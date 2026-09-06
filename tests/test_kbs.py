"""Key Broker tests, a credential must be unreachable without valid attestation."""

import time

import pytest

from sentinel.attestation import MockSilicon, sha384
from sentinel.enclave import Enclave
from sentinel.kbs import CredentialReleaseError, KeyBroker, ReleasePolicy

APPROVED = sha384(b"sentinel-miner-image-v0.1")
DSN = "postgres://user:secret@customer-db:5432/app"
RESOURCE = "customer-db"


def make_broker(policy: ReleasePolicy | None = None) -> KeyBroker:
    broker = KeyBroker(policy=policy or ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, DSN)
    return broker


def make_enclave(measurement: str = APPROVED, tcb: int = 7) -> Enclave:
    return Enclave(MockSilicon(), launch_measurement=measurement, tcb_level=tcb)


def trusted(broker: KeyBroker, enclave: Enclave) -> None:
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)


# --- the happy path -----------------------------------------------------------

def test_approved_enclave_receives_credential():
    broker, enclave = make_broker(), make_enclave()
    trusted(broker, enclave)
    creds = enclave.unlock(broker, RESOURCE)
    assert creds.dsn == DSN
    assert creds.resource == RESOURCE


# --- the refusals: each is a reason an operator cannot reach the secret --------

def test_tampered_image_gets_nothing():
    """Modified miner code fails the launch measurement, so no credential."""
    broker = make_broker()
    rogue = make_enclave(measurement=sha384(b"backdoored-image"))
    trusted(broker, rogue)  # even a genuine chip cannot save unapproved code
    with pytest.raises(CredentialReleaseError, match="launch measurement"):
        rogue.unlock(broker, RESOURCE)


def test_untrusted_chip_gets_nothing():
    """A chip the broker has never certified is refused before signature checks."""
    broker, enclave = make_broker(), make_enclave()
    # deliberately not registered
    with pytest.raises(CredentialReleaseError, match="not a trusted processor"):
        enclave.unlock(broker, RESOURCE)


def test_impersonated_chip_gets_nothing():
    """Registering a chip ID against someone else's key must not help."""
    broker, enclave = make_broker(), make_enclave()
    broker.trust_chip(enclave.chip_id, MockSilicon().public_key_hex)  # wrong key
    with pytest.raises(CredentialReleaseError, match="signature"):
        enclave.unlock(broker, RESOURCE)


def test_stale_tcb_gets_nothing():
    """Vulnerable firmware is refused even if everything else is right."""
    broker = make_broker()
    old = make_enclave(tcb=5)
    trusted(broker, old)
    with pytest.raises(CredentialReleaseError, match="TCB"):
        old.unlock(broker, RESOURCE)


def test_replayed_attestation_gets_nothing():
    """A spent nonce cannot unlock the secret twice."""
    broker, enclave = make_broker(), make_enclave()
    trusted(broker, enclave)

    nonce = broker.challenge()
    from sentinel.kbs import release_binding
    report = enclave.agent.attest(nonce, release_binding(RESOURCE))

    assert broker.release(RESOURCE, report).dsn == DSN  # first use succeeds
    with pytest.raises(CredentialReleaseError, match="nonce"):
        broker.release(RESOURCE, report)  # replay refused


def test_expired_nonce_gets_nothing():
    broker = make_broker(ReleasePolicy(approved_measurement=APPROVED, nonce_ttl_seconds=-1))
    enclave = make_enclave()
    trusted(broker, enclave)
    from sentinel.kbs import release_binding

    nonce = broker.challenge()
    time.sleep(0.01)
    report = enclave.agent.attest(nonce, release_binding(RESOURCE))
    with pytest.raises(CredentialReleaseError, match="nonce"):
        broker.release(RESOURCE, report)


def test_attestation_for_one_resource_cannot_unlock_another():
    """Cross-resource replay: proof for the analytics DB must not open payments."""
    broker, enclave = make_broker(), make_enclave()
    broker.store_secret("payments-db", "postgres://u:p@payments:5432/pay")
    trusted(broker, enclave)

    from sentinel.kbs import release_binding
    nonce = broker.challenge()
    report = enclave.agent.attest(nonce, release_binding(RESOURCE))  # bound to customer-db

    with pytest.raises(CredentialReleaseError, match="response binding"):
        broker.release("payments-db", report)


def test_unknown_resource_is_refused():
    broker, enclave = make_broker(), make_enclave()
    trusted(broker, enclave)
    with pytest.raises(CredentialReleaseError, match="no secret stored"):
        enclave.unlock(broker, "does-not-exist")


# --- hygiene ------------------------------------------------------------------

def test_credentials_are_not_exposed_in_repr():
    """A DSN must not leak through logs or tracebacks."""
    broker, enclave = make_broker(), make_enclave()
    trusted(broker, enclave)
    creds = enclave.unlock(broker, RESOURCE)
    assert "secret" not in repr(creds)
    assert "redacted" in repr(creds)


def test_failed_unlock_leaves_no_credential_in_enclave():
    broker = make_broker()
    rogue = make_enclave(measurement=sha384(b"backdoored-image"))
    trusted(broker, rogue)
    with pytest.raises(CredentialReleaseError):
        rogue.unlock(broker, RESOURCE)
    assert rogue.credential_for(RESOURCE) is None


# --- the hardware path: AMD's chain instead of a registered key ----------------

import pathlib as _pathlib

import pytest as _pytest

from sentinel.attestation import AttestationReport
from sentinel.kbs import looks_like_sevsnp, release_binding

_HOST = _pathlib.Path(__file__).parent / "fixtures" / "gcp-host-certs"
_REPORT = _HOST / "sevsnp-report-20260831T061928Z.bin"
needs_hw_fixtures = _pytest.mark.skipif(
    not _REPORT.exists(), reason="hardware fixtures not present"
)


def test_report_kind_is_read_from_its_shape():
    """A real report is the whole 1184-byte structure; a mock one is 64 bytes.

    Nothing else is near either length, so the broker can route without the
    report having to declare which kind it is, and without a caller being able
    to claim the cheaper check by lying about it.
    """
    assert looks_like_sevsnp("aa" * 1184)
    assert not looks_like_sevsnp("aa" * 64)
    assert not looks_like_sevsnp("")


def test_sevsnp_report_is_refused_when_no_verifier_is_configured():
    """A broker that cannot check a proof must not release a secret against it.

    The dangerous failure would be falling back to the chip registry, because
    then a real report from an unregistered chip would be judged by the weaker
    check and could be admitted by it.
    """
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement="whatever"))
    broker.store_secret("customer-db", "postgres://u:p@h/db")
    nonce = broker.challenge()
    report = AttestationReport(
        chip_id="F1CF2D6F", launch_measurement="whatever", tcb_level=9,
        nonce=nonce, report_data=release_binding("customer-db"),
        signature="ab" * 1184,
    )
    with pytest.raises(CredentialReleaseError, match="no verifier"):
        broker.release("customer-db", report)


@needs_hw_fixtures
def test_sevsnp_report_is_refused_when_the_host_supplied_no_certificates():
    """Without a VCEK there is nothing to check the signature against."""
    from sentinel.sevsnp import SevSnpPolicy, SevSnpVerifier
    from sentinel.sevsnp.certs import CertChain
    from cryptography import x509

    certs = {n: (_HOST / f"{n}.der").read_bytes() for n in ("ASK", "ARK")}
    chain = CertChain(product="Milan",
                      ask=x509.load_der_x509_certificate(certs["ASK"]),
                      ark=x509.load_der_x509_certificate(certs["ARK"]))
    verifier = SevSnpVerifier("Milan", SevSnpPolicy(approved_measurement=b"\x00" * 48),
                              chain=chain, offline=True)

    broker = KeyBroker(policy=ReleasePolicy(approved_measurement="x"), sevsnp=verifier)
    broker.store_secret("customer-db", "postgres://u:p@h/db")
    nonce = broker.challenge()
    report = AttestationReport(
        chip_id="F1CF2D6F", launch_measurement="x", tcb_level=9, nonce=nonce,
        report_data=release_binding("customer-db"), signature="ab" * 1184,
    )
    with pytest.raises(CredentialReleaseError, match="no VCEK"):
        broker.release("customer-db", report)


@needs_hw_fixtures
def test_a_forged_sevsnp_report_does_not_release_the_secret():
    """Bytes that are not a genuine report must be refused by the chain check.

    This is the case the registered-key path could never express: the report is
    the right shape and claims a real chip ID, and it still fails because no AMD
    key signed it.
    """
    from sentinel.sevsnp import SevSnpPolicy, SevSnpVerifier, parse_report
    from sentinel.sevsnp.certs import CertChain
    from cryptography import x509

    real = _REPORT.read_bytes()
    certs = {n: (_HOST / f"{n}.der").read_bytes() for n in ("VCEK", "ASK", "ARK")}
    chain = CertChain(product="Milan",
                      ask=x509.load_der_x509_certificate(certs["ASK"]),
                      ark=x509.load_der_x509_certificate(certs["ARK"]))
    verifier = SevSnpVerifier(
        "Milan",
        SevSnpPolicy(approved_measurement=parse_report(real).measurement),
        chain=chain, offline=True,
    )

    broker = KeyBroker(policy=ReleasePolicy(approved_measurement="x"),
                       sevsnp=verifier, sevsnp_certs=certs)
    broker.store_secret("customer-db", "postgres://u:p@h/db")

    # a genuine-looking report with one byte of the signed body altered
    forged = bytearray(real)
    forged[0x090] ^= 0xFF
    nonce = broker.challenge()
    report = AttestationReport(
        chip_id="F1CF2D6F", launch_measurement="x", tcb_level=9, nonce=nonce,
        report_data=release_binding("customer-db"), signature=bytes(forged).hex(),
    )
    with pytest.raises(CredentialReleaseError, match="attestation rejected"):
        broker.release("customer-db", report)


def test_mock_reports_still_take_the_registered_key_path():
    """The development path must keep working unchanged."""
    from sentinel.attestation import MockSilicon

    silicon = MockSilicon()
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement="img-v1"))
    broker.store_secret("customer-db", "postgres://u:p@h/db")
    broker.trust_chip(silicon.chip_id, silicon.public_verifier().public_key_hex)

    from sentinel.attestation import AttestationAgent

    agent = AttestationAgent(silicon, "img-v1", tcb_level=9)
    nonce = broker.challenge()
    report = agent.attest(nonce, release_binding("customer-db"))
    assert not looks_like_sevsnp(report.signature)
    assert broker.release("customer-db", report).dsn.startswith("postgres://")
