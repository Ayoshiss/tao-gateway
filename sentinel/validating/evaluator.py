"""
Challenge miners, verify their proofs, score them.

The validator trusts nothing a miner says about itself. It picks the nonce, so
the miner cannot answer before being asked; it checks the attestation against
the approved launch measurement, so modified code cannot pass; and it decides
correctness by agreement across miners rather than by asking any one of them.

Correctness by consensus is the important part. A validator cannot know the
right answer to a query against a customer's private database, that is the
whole point of the product. What it can do is send the same query to every
miner and notice who disagrees with the majority. A miner returning fabricated
rows is visible without the validator ever seeing the real data.

No chain access here. This module challenges over HTTP and produces weights;
submitting them is `weights.py`.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..attestation import (
    AttestationReport,
    VerificationError,
    bind_response,
    new_nonce,
    verify,
    verifier_from_public_key,
)
from ..serving.client import MinerClient, MinerClientError
from .scoring import (
    DEFAULT_LATENCY_CEILING_MS,
    DEFAULT_LATENCY_TARGET_MS,
    MinerScores,
    latency_score,
)

logger = logging.getLogger("sentinel.validating")

#: Deterministic probe sent to every miner in a round. Read-only by design,
#: a validator must never mutate a customer's data while measuring.
PROBE_TOOL = "postgres.query"
PROBE_ARGUMENTS: dict[str, Any] = {"sql": "SELECT id, email, plan FROM customers ORDER BY id"}


@dataclass
class MinerTarget:
    uid: int
    hotkey_ss58: str
    base_url: str


@dataclass
class ChallengeOutcome:
    uid: int
    hotkey_ss58: str
    scores: MinerScores = field(default_factory=MinerScores)
    verified: bool = False
    latency_ms: float = 0.0
    response_hash: str | None = None
    error: str | None = None

    @property
    def weight(self) -> float:
        return self.scores.weight()


class MinerEvaluator:
    """Runs one evaluation round against a set of miners."""

    def __init__(
        self,
        wallet: Any,
        approved_measurement: str,
        *,
        min_tcb: int = 7,
        latency_target_ms: float = DEFAULT_LATENCY_TARGET_MS,
        latency_ceiling_ms: float = DEFAULT_LATENCY_CEILING_MS,
        timeout: float = 30.0,
        product: str = "Milan",
        sevsnp_min_tcb: Mapping[str, int] | None = None,
    ) -> None:
        self.wallet = wallet
        self.approved_measurement = approved_measurement
        #: EPYC product line, which selects AMD's root. Wrong here means every
        #: real-silicon miner fails, so it is explicit rather than sniffed.
        self.product = product
        #: `min_tcb` is one integer and a real TCB is four components, so the
        #: hardware floor cannot be derived from it and is set separately.
        #: Empty means no floor: approved code on vulnerable firmware still
        #: passes, which is a gap and is tracked in ROADMAP.md. Populating it
        #: needs a decision about which firmware levels to require, and getting
        #: that wrong locks honest miners out of the subnet.
        self.sevsnp_min_tcb = dict(sevsnp_min_tcb or {})
        self.min_tcb = min_tcb
        self.latency_target_ms = latency_target_ms
        self.latency_ceiling_ms = latency_ceiling_ms
        self.timeout = timeout

    # -- one round ------------------------------------------------------------

    def evaluate_round(self, targets: Iterable[MinerTarget]) -> list[ChallengeOutcome]:
        """Probe every miner, then score correctness against the majority answer."""
        outcomes = [self._probe(t) for t in targets]

        # Consensus over miners that actually produced a verified answer. An
        # unverified miner does not get a vote on what the truth is, otherwise
        # a group of fakes could outvote the honest ones.
        votes = Counter(o.response_hash for o in outcomes if o.verified and o.response_hash)
        majority = votes.most_common(1)[0][0] if votes else None

        for outcome in outcomes:
            if majority is not None and outcome.verified:
                outcome.scores.correctness = 1.0 if outcome.response_hash == majority else 0.0
            logger.info(
                "uid=%s verified=%s weight=%.4f%s",
                outcome.uid, outcome.verified, outcome.weight,
                f" error={outcome.error}" if outcome.error else "",
            )
        return outcomes

    @staticmethod
    def weights_from(outcomes: Iterable[ChallengeOutcome]) -> dict[int, float]:
        """uid -> weight, normalised so the round sums to 1.0.

        Yuma expects a distribution. If every miner failed, an all-zero map is
        returned rather than a uniform one: rewarding everyone equally for
        failing is worse than rewarding no one.
        """
        raw = {o.uid: o.weight for o in outcomes}
        total = sum(raw.values())
        if total <= 0:
            return {uid: 0.0 for uid in raw}
        return {uid: w / total for uid, w in raw.items()}

    # -- per miner ------------------------------------------------------------

    def _probe(self, target: MinerTarget) -> ChallengeOutcome:
        outcome = ChallengeOutcome(uid=target.uid, hotkey_ss58=target.hotkey_ss58)
        client = MinerClient(target.base_url, self.wallet, target.hotkey_ss58, timeout=self.timeout)

        try:
            health = client.health()
            if health.get("attestation") != "sev-snp":
                public_key = health.get("public_key")
                if not public_key:
                    outcome.error = "health did not advertise a public key"
                    return outcome

            nonce = new_nonce()
            request_id = f"probe-{nonce[:12]}"
            response = client.call_full(PROBE_TOOL, PROBE_ARGUMENTS, nonce, request_id=request_id)
        except MinerClientError as exc:
            outcome.error = str(exc)
            return outcome

        outcome.latency_ms = response.latency_ms
        outcome.scores.latency = latency_score(
            response.latency_ms, self.latency_target_ms, self.latency_ceiling_ms
        )

        # An attested reply must not be cacheable: a cached body would be served
        # to someone else without the proof that belongs to it.
        cache_control = response.header("Cache-Control").lower()
        outcome.scores.cache_hygiene = 1.0 if "no-store" in cache_control else 0.0

        payload = response.payload
        outcome.response_hash = payload.get("response_hash")

        try:
            report = AttestationReport(**payload["attestation"])
        except (KeyError, TypeError) as exc:
            outcome.error = f"malformed attestation: {exc}"
            return outcome

        # Nonce discipline is scored separately from attestation validity so a
        # miner replaying an old report is distinguishable from one with no
        # valid report at all.
        outcome.scores.nonce_discipline = 1.0 if report.nonce == nonce else 0.0

        binding = bind_response(request_id, outcome.response_hash or "")
        try:
            if health.get("attestation") == "sev-snp":
                self._verify_sevsnp(report, health, binding, expected_nonce=nonce)
            else:
                verify(
                    report,
                    verifier_from_public_key(public_key),
                    approved_measurement=self.approved_measurement,
                    expected_nonce=nonce,
                    min_tcb=self.min_tcb,
                    expected_report_data=binding,
                )
        except VerificationError as exc:
            outcome.error = f"attestation rejected: {exc}"
            return outcome

        outcome.verified = True
        outcome.scores.attestation = 1.0
        return outcome

    def _verify_sevsnp(
        self, report, health: dict[str, Any], binding: str, *, expected_nonce: str
    ) -> None:
        """Verify a real chip's report against AMD's chain, using the miner's certs.

        The certificates come from the miner, which is the party being judged.
        That is safe only because of what is not taken from it: the root is
        pinned in `CertChain.verify_self`, so a miner that mints its own chain
        fails here rather than passing with its own signature. What it buys is
        that scoring never depends on AMD's KDS being up, and a KDS outage
        cannot zero an honest miner's score.
        """
        import base64

        from cryptography import x509

        from ..sevsnp import SevSnpPolicy, SevSnpVerifier
        from ..sevsnp.certs import CertChain

        certificates = health.get("certificates") or {}
        try:
            certs = {n: base64.b64decode(v) for n, v in certificates.items()}
        except Exception as exc:  # noqa: BLE001 - miner-supplied, treat as hostile
            raise VerificationError(f"unreadable certificates: {exc}") from exc

        missing = {"ASK", "ARK"} - set(certs)
        leaf = certs.get("VCEK") or certs.get("VLEK")
        if missing or leaf is None:
            raise VerificationError(
                "miner advertised SEV-SNP but not a full certificate chain"
            )

        try:
            chain = CertChain(
                product=self.product,
                ask=x509.load_der_x509_certificate(certs["ASK"]),
                ark=x509.load_der_x509_certificate(certs["ARK"]),
            )
            vcek = x509.load_der_x509_certificate(leaf)
        except Exception as exc:  # noqa: BLE001 - malformed DER is a rejection
            raise VerificationError(f"malformed certificate: {exc}") from exc

        verifier = SevSnpVerifier(
            self.product,
            SevSnpPolicy(
                approved_measurement=bytes.fromhex(self.approved_measurement),
                **self.sevsnp_min_tcb,
            ),
            chain=chain,
            offline=True,
        )
        # Proves the chip produced exactly this report. The report's own fields
        # are checked separately below, because a genuine signature over the
        # wrong claims is still the wrong claims.
        verifier.verify_signed_message(report.canonical(), report.signature, vcek=vcek)

        # The signature covers the nonce, but covering it and being the one we
        # asked for are different claims. Checked explicitly rather than left to
        # the binding: today request_id is derived from the nonce so a stale
        # report fails anyway, and a validator should not depend on that holding.
        if report.nonce != expected_nonce:
            raise VerificationError("report answers a different nonce (replay)")

        if report.report_data != binding:
            raise VerificationError(
                "response binding mismatch (proof is for a different response)"
            )
