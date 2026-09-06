"""The miner daemon, scored by a real validator round.

Every other test builds a miner out of the pieces the way the test wants them.
This one builds it the way `scripts/run_miner.py` does, from parsed arguments,
and then has an actual `MinerEvaluator` challenge it. That is the difference
between the components working and the deployed thing working, and it is the
gap the seeded-database bug lived in: the daemon started cleanly, served
cleanly, and scored zero, because nothing had ever asked it the question the
validator asks.
"""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import threading

import pytest
from bittensor.sp_core import Keypair

from sentinel.attestation import sha384
from sentinel.validating import MinerEvaluator, MinerTarget

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent / "scripts"
APPROVED = sha384(b"sentinel-miner-image-v0.1")


def load_daemon():
    """Import run_miner.py by path; scripts/ is not a package."""
    spec = importlib.util.spec_from_file_location("run_miner", SCRIPTS / "run_miner.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def daemon():
    return load_daemon()


def daemon_args(daemon, **overrides):
    """The defaults the CLI would produce, minus the chain and the hardware."""
    args = argparse.Namespace(
        allow_mock=True,
        measurement=APPROVED,
        product="Milan",
        dsn="sqlite:///",
        seed=daemon.DEFAULT_SEED,
        bind="127.0.0.1",
        port=0,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


@pytest.fixture
def running_miner(daemon):
    """The daemon's own `build_miner`, serving on a free port."""
    hotkey = Keypair.create_from_uri("//DaemonMiner")
    server, enclave = daemon.build_miner(daemon_args(daemon), hotkey.ss58_address)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield hotkey, f"http://127.0.0.1:{server.server_port}", enclave
    finally:
        server.shutdown()
        server.server_close()


def test_the_daemon_as_configured_passes_a_validator_round(running_miner):
    """The assembled miner answers the real probe and scores as an honest one.

    Not "it returns 200". The evaluator verifies the attestation, checks the
    response binding, and scores; a miner that served the wrong rows, or served
    them without a valid proof, fails here.
    """
    hotkey, base_url, _ = running_miner
    evaluator = MinerEvaluator(
        Keypair.create_from_uri("//Validator"), APPROVED, latency_ceiling_ms=60_000
    )

    outcomes = evaluator.evaluate_round(
        [MinerTarget(uid=0, hotkey_ss58=hotkey.ss58_address, base_url=base_url)]
    )

    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.error is None, outcome.error
    assert outcome.verified, "attestation was not verified"
    assert outcome.scores.attestation == 1.0
    assert outcome.response_hash is not None


def test_an_unseeded_daemon_fails_the_probe_rather_than_serving_nothing(daemon):
    """Without the seed the table is missing, and that must show up as a failure.

    Worth pinning because the failure is silent from the miner's side: it starts,
    it serves, its attestations are perfectly valid. Only the answer is missing.
    """
    hotkey = Keypair.create_from_uri("//UnseededMiner")
    server, _ = daemon.build_miner(
        daemon_args(daemon, seed=None), hotkey.ss58_address
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        evaluator = MinerEvaluator(
            Keypair.create_from_uri("//Validator"), APPROVED, latency_ceiling_ms=60_000
        )
        outcome = evaluator.evaluate_round(
            [MinerTarget(uid=0, hotkey_ss58=hotkey.ss58_address, base_url=base_url_of(server))]
        )[0]
        assert outcome.scores.correctness == 0.0
        assert outcome.weight < 1.0
    finally:
        server.shutdown()
        server.server_close()


def base_url_of(server) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def test_real_silicon_is_the_default_and_mock_must_be_asked_for(daemon, monkeypatch):
    """On a machine with no SEV-SNP, refusing to start is the correct behaviour.

    A miner that quietly degrades to software signing would advertise a hardware
    guarantee it is not providing, which is worse than not running.
    """
    from sentinel.sevsnp import guest

    monkeypatch.setattr(guest, "available", lambda: False)
    with pytest.raises(SystemExit, match="not a SEV-SNP guest"):
        daemon.open_silicon(allow_mock=False)

    silicon, real = daemon.open_silicon(allow_mock=True)
    assert not real
    assert silicon.chip_id.startswith("MOCK")


def test_an_image_that_is_not_the_approved_one_refuses_to_serve(daemon, monkeypatch):
    """The measurement gate, which is the reason any of this exists.

    The chip reports what actually booted. If that is not the pinned value the
    miner stops, rather than serving while claiming to be the approved image.
    """
    from sentinel.sevsnp import guest

    class WrongImage:
        chip_id = "F1CF2D6F"
        measurement = "de" * 48

    monkeypatch.setattr(guest, "available", lambda: True)
    monkeypatch.setattr(guest, "SevSnpSilicon", lambda *a, **k: WrongImage())

    with pytest.raises(SystemExit, match="launch measurement mismatch"):
        daemon.build_miner(daemon_args(daemon, measurement="ab" * 48), "hotkey")
