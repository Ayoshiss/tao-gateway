"""
Key Broker Service, credentials are released to *code*, not to people.

This is the piece that makes Sentinel's central claim true. A customer's database
password is never handed to a miner operator. It is held by the broker and
released only to an enclave that has just proved, cryptographically, three
things at once:

    * it is running on a chip the broker trusts        (signature + chip registry)
    * it booted the approved image                     (launch measurement)
    * the proof is fresh and for THIS resource         (broker-issued nonce + binding)

Fail any one and the credential is never emitted. An operator who swaps in
modified code does not get a degraded service; they get nothing.

Mirrors the real Confidential Containers flow, Trustee/KBS validating an
SEV-SNP report against a policy before releasing a secret from Vault. Here the
chip registry stands in for AMD's certificate directory, and `MockSilicon`
stands in for the processor. The interfaces are the same, so the real backend
drops in without changing callers.

Known limitation: once the decision to release is made, the credential is
returned in the clear, so it is only as private as the channel carrying it.
Production should encrypt it to the enclave's ephemeral public key (PK_TEE),
carried in the attestation report, so that nothing but that enclave can decrypt
it. That hardens what happens *after* the gate; the gating logic below is
unchanged either way. Tracked in ROADMAP.md under Milestone 2.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .attestation import (
    AttestationReport,
    VerificationError,
    bind_response,
    new_nonce,
    sha384,
    verify,
    verifier_from_public_key,
)
from .database import Credentials


class CredentialReleaseError(Exception):
    """Raised whenever a credential is withheld. Never leaks the secret."""


@dataclass
class ReleasePolicy:
    """What an enclave must prove before any secret is released."""

    approved_measurement: str
    min_tcb: int = 7
    nonce_ttl_seconds: float = 60.0


def release_binding(resource: str) -> str:
    """The value an enclave must bind into its report to request `resource`.

    Ties the proof to one specific secret, so an attestation obtained for the
    analytics database cannot be replayed to unlock the payments database.
    """
    return bind_response("kbs-release", sha384(resource.encode()))


#: A SEV-SNP report arrives as the whole 1184-byte structure, hex encoded, in the
#: `signature` field. A mock Ed25519 signature is 64 bytes. Nothing else is near
#: either length, so the shape identifies which verification path a report needs
#: without the report having to announce it.
SEVSNP_SIGNATURE_HEX_LEN = 1184 * 2


def looks_like_sevsnp(signature_hex: str) -> bool:
    """Whether this signature is a real SEV-SNP report rather than a mock one."""
    return len(signature_hex) >= SEVSNP_SIGNATURE_HEX_LEN


@dataclass
class KeyBroker:
    """Holds secrets; releases them only against a valid, fresh attestation.

    Two kinds of proof reach `release()`, and they are verified differently.

    A `MockSilicon` report is Ed25519 signed, so the broker checks it against a
    public key registered in advance with `trust_chip`. That models a directory
    of known-good chips and is what the development path uses.

    A real SEV-SNP report cannot work that way, because a processor has no bare
    public key to register. It is verified through AMD's certificate chain: the
    report is signed by the chip's VCEK, the VCEK by AMD's signing key, and that
    by AMD's root, which is pinned. Supply a `SevSnpVerifier` as `sevsnp` and the
    broker routes real reports to it, ignoring the chip registry entirely.

    Without a verifier configured, a real report is refused rather than falling
    back to the registry. A broker that cannot check a proof must not release a
    secret against it.
    """

    policy: ReleasePolicy
    #: Verifier for real hardware. `None` means this broker only accepts mocks.
    sevsnp: object | None = None
    #: Certificates the enclave supplied with its report, `{name: der}`. The
    #: extended report carries these so verification never has to reach AMD.
    sevsnp_certs: dict[str, bytes] = field(default_factory=dict, repr=False)
    _secrets: dict[str, Credentials] = field(default_factory=dict, repr=False)
    _trusted_chips: dict[str, str] = field(default_factory=dict, repr=False)
    _issued_nonces: dict[str, float] = field(default_factory=dict, repr=False)

    # -- setup -----------------------------------------------------------------

    def store_secret(self, resource: str, dsn: str) -> None:
        """Deposit a credential. This is the only place the DSN lives at rest."""
        self._secrets[resource] = Credentials(dsn=dsn, resource=resource)

    def trust_chip(self, chip_id: str, public_key_hex: str) -> None:
        """Register a chip as genuine.

        Stands in for AMD's VCEK certificate directory: in production the broker
        fetches the cert for a reported chip ID and checks it chains to AMD's
        root, rather than consulting a local map.
        """
        self._trusted_chips[chip_id] = public_key_hex

    # -- protocol --------------------------------------------------------------

    def challenge(self) -> str:
        """Issue a fresh nonce. The enclave must bind it into its report."""
        self._expire_nonces()
        nonce = new_nonce()
        self._issued_nonces[nonce] = time.monotonic() + self.policy.nonce_ttl_seconds
        return nonce

    def release(self, resource: str, report: AttestationReport) -> Credentials:
        """Verify the report and release the credential, or raise.

        Order matters: cheap structural checks first, signature last, and the
        secret is only read from storage after every check has passed.
        """
        if resource not in self._secrets:
            raise CredentialReleaseError(f"no secret stored for resource {resource!r}")

        # Freshness: the nonce must be one we issued and have not yet spent.
        self._expire_nonces()
        if report.nonce not in self._issued_nonces:
            raise CredentialReleaseError("unknown or expired nonce (replayed attestation)")

        # Real silicon and mock silicon prove themselves differently, so the
        # shape of the signature decides which check applies.
        if looks_like_sevsnp(report.signature):
            self._verify_sevsnp(report, resource)
        else:
            self._verify_registered_key(report, resource)

        # Spend the nonce so this proof cannot unlock anything twice.
        self._issued_nonces.pop(report.nonce, None)
        return self._secrets[resource]

    # -- internals -------------------------------------------------------------

    def _verify_registered_key(self, report: AttestationReport, resource: str) -> None:
        """The development path: an Ed25519 key registered in advance."""
        public_key = self._trusted_chips.get(report.chip_id)
        if public_key is None:
            raise CredentialReleaseError(
                f"chip {report.chip_id!r} is not a trusted processor"
            )
        try:
            verify(
                report,
                verifier_from_public_key(public_key),
                approved_measurement=self.policy.approved_measurement,
                expected_nonce=report.nonce,
                min_tcb=self.policy.min_tcb,
                expected_report_data=release_binding(resource),
            )
        except VerificationError as exc:
            raise CredentialReleaseError(f"attestation rejected: {exc}") from exc

    def _verify_sevsnp(self, report: AttestationReport, resource: str) -> None:
        """The hardware path: AMD's certificate chain, anchored to a pinned root.

        The chip registry is deliberately not consulted. A processor's identity
        comes from a VCEK that chains to AMD, not from a key someone remembered
        to add to a list, and consulting both would mean the weaker check could
        admit what the stronger one refuses.
        """
        if self.sevsnp is None:
            raise CredentialReleaseError(
                "a SEV-SNP report was presented but this broker has no verifier "
                "configured; refusing to release against a proof it cannot check"
            )

        leaf = self.sevsnp_certs.get("VCEK") or self.sevsnp_certs.get("VLEK")
        if leaf is None:
            raise CredentialReleaseError(
                "no VCEK available for this chip; the host provisioned no "
                "certificates and AMD's KDS was not consulted"
            )

        from cryptography import x509

        # The chip signs the canonical report, not the resource binding directly,
        # so REPORT_DATA holds SHA-512 of that JSON. `verify_signed_message`
        # recomputes it, which is what ties the signature to this exact nonce,
        # chip and binding rather than to any report the chip ever produced.
        try:
            self.sevsnp.verify_signed_message(
                report.canonical(),
                report.signature,
                vcek=x509.load_der_x509_certificate(leaf),
            )
        except VerificationError as exc:
            raise CredentialReleaseError(f"attestation rejected: {exc}") from exc

        # The signature proves the chip produced this report. It says nothing
        # about which secret the report was asking for, so check that separately:
        # otherwise a proof obtained for the analytics database would unlock the
        # payments one.
        if report.report_data != release_binding(resource):
            raise CredentialReleaseError(
                "attestation is bound to a different resource"
            )

    def _expire_nonces(self) -> None:
        now = time.monotonic()
        for nonce, expiry in list(self._issued_nonces.items()):
            if now > expiry:
                del self._issued_nonces[nonce]
