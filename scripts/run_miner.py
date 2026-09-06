"""
A Sentinel miner, long running, on real silicon.

    python scripts/run_miner.py --netuid 554 --wallet sentinel \
        --advertise-ip 34.x.x.x --measurement <hex>

Everything before this ran a miner and a validator together for the length of
one demonstration. This runs only the miner, and it runs until something stops
it, which is the difference between showing the mechanism works and taking a
position on a live subnet.

The chip is the point. On a SEV-SNP guest the enclave signs with the processor
and the broker checks AMD's certificate chain; the credential is released to a
measured image, not to whoever is holding the wallet. `--allow-mock` exists so
the wiring can be exercised on a laptop, and says so loudly, because a mock
miner on a real subnet is claiming a guarantee it is not providing.

First boot on a new image, before there is a measurement to pin:

    python scripts/run_miner.py --print-measurement

That prints what the firmware measured and exits. Pin the value, redeploy with
it, and from then on the miner refuses to serve if the image is not the one
that was approved.
"""

import argparse
import logging
import pathlib
import signal
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sentinel.database import Credentials, PostgresDatabase, SqliteDatabase
from sentinel.enclave import Enclave
from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer
from sentinel.mcp.tools import PostgresQueryTool
from sentinel.serving import MinerHandler
from sentinel.serving.server import make_server

logger = logging.getLogger("sentinel.miner")

RESOURCE = "customer-db"

#: ServeAxon is rate limited per neuron (50 blocks by default), and a published
#: endpoint does not expire. Re-publishing hourly is enough to recover from a
#: chain-side loss without ever tripping the limit.
REPUBLISH_SECONDS = 3600


# --- silicon ------------------------------------------------------------------

def open_silicon(allow_mock: bool):
    """The real chip if there is one, a mock only when explicitly permitted."""
    from sentinel.sevsnp import guest

    if guest.available():
        silicon = guest.SevSnpSilicon()
        logger.info("SEV-SNP guest detected, chip %s", silicon.chip_id)
        return silicon, True

    if not allow_mock:
        raise SystemExit(
            "no /dev/sev-guest: this host is not a SEV-SNP guest.\n"
            "Run on a confidential VM, or pass --allow-mock to exercise the "
            "wiring without the hardware guarantee."
        )

    from sentinel.attestation import MockSilicon

    logger.warning(
        "MOCK SILICON: signing in software. Attestations from this miner prove "
        "the protocol works and nothing about the hardware."
    )
    return MockSilicon(), False


def build_verifier(silicon, product: str, measurement_hex: str):
    """A verifier anchored to AMD's pinned root, using the host's certificates.

    The certificates arrive from the host alongside the report, which sounds
    like trusting the attacker to supply the evidence. It is not: the chain is
    checked against a root whose SPKI hash is compiled in, so a substituted root
    fails before any field of the report is read. The benefit is that
    verification never depends on AMD's KDS being reachable, which it was not on
    the day this path was written.
    """
    from cryptography import x509

    from sentinel.sevsnp import SevSnpPolicy, SevSnpVerifier
    from sentinel.sevsnp.certs import CertChain

    certs = silicon.certificates
    missing = {"VCEK", "ASK", "ARK"} - set(certs)
    if missing:
        raise SystemExit(
            f"host provisioned no {', '.join(sorted(missing))}; cannot verify "
            "offline. This is a host configuration problem, not a guest one."
        )

    chain = CertChain(
        product=product,
        ask=x509.load_der_x509_certificate(certs["ASK"]),
        ark=x509.load_der_x509_certificate(certs["ARK"]),
    )
    verifier = SevSnpVerifier(
        product,
        SevSnpPolicy(approved_measurement=bytes.fromhex(measurement_hex)),
        chain=chain,
        offline=True,
    )
    return verifier, certs


# --- assembly -----------------------------------------------------------------

def build_miner(args, hotkey_ss58: str):
    """Wire chip to broker to enclave to MCP, and return a server ready to run."""
    silicon, real = open_silicon(args.allow_mock)

    if real:
        actual = silicon.measurement
        if actual != args.measurement:
            # The whole point. An image that is not the approved one does not
            # get to serve while quietly claiming it is.
            raise SystemExit(
                f"launch measurement mismatch.\n"
                f"  approved: {args.measurement}\n"
                f"  running:  {actual}\n"
                "Either this is not the approved image, or the image changed "
                "and the pinned value needs updating deliberately."
            )
        verifier, certs = build_verifier(silicon, args.product, args.measurement)
        broker = KeyBroker(
            policy=ReleasePolicy(approved_measurement=args.measurement),
            sevsnp=verifier,
            sevsnp_certs=certs,
        )
    else:
        broker = KeyBroker(policy=ReleasePolicy(approved_measurement=args.measurement))
        broker.trust_chip(silicon.chip_id, silicon.public_verifier().public_key_hex)

    broker.store_secret(RESOURCE, args.dsn)

    enclave = Enclave(silicon, launch_measurement=args.measurement)
    credentials = enclave.unlock(broker, RESOURCE)
    logger.info("credential released to the enclave for %r", RESOURCE)

    mcp = MCPServer()
    mcp.register(PostgresQueryTool(open_database(credentials, args.seed)))

    handler = MinerHandler(enclave, mcp, hotkey_ss58=hotkey_ss58)
    return make_server(handler, args.bind, args.port), enclave


DEFAULT_SEED = pathlib.Path(__file__).parent / "miner-seed.sql"


def open_database(credentials: Credentials, seed: pathlib.Path | None):
    """Postgres when the credential points at one, SQLite otherwise.

    The DSN read here is the one the broker released, not the one the operator
    typed. They are the same string today because this miner brokers to itself,
    but reading the released copy is what keeps that an implementation detail
    rather than a dependency.
    """
    dsn = credentials.dsn
    if dsn.startswith(("postgres://", "postgresql://")):
        return PostgresDatabase(credentials)

    # sqlite:///relative.db and sqlite:////absolute.db, as SQLAlchemy spells it.
    rest = dsn.removeprefix("sqlite://")
    path = rest[1:] if rest.startswith("//") else rest.lstrip("/")
    # Unseeded, the validator's probe hits a missing table and the miner scores
    # zero for correctness however good its attestation was.
    seed_sql = seed.read_text() if seed else None
    return SqliteDatabase(credentials, path=path or ":memory:", seed_sql=seed_sql)


# --- chain --------------------------------------------------------------------

async def publish_forever(args, wallet, stop: threading.Event) -> None:
    """Keep the endpoint published, re-asserting it periodically."""
    import bittensor as bt

    from sentinel.chain import publish_axon

    signer = bt.resolve_signer(wallet, "hotkey")
    while not stop.is_set():
        try:
            async with bt.Subtensor(args.endpoint) as st:
                result = await publish_axon(
                    st, signer, args.netuid, args.advertise_ip, args.port
                )
                logger.info("ServeAxon success=%s", getattr(result, "success", result))
        except Exception as exc:  # noqa: BLE001 - a miner must survive chain trouble
            # Serving continues regardless. An unreachable chain costs discovery
            # by new validators; it does not stop answering the ones that
            # already know the endpoint.
            logger.warning("could not publish endpoint: %s", exc)
        stop.wait(REPUBLISH_SECONDS)


# --- entry point --------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--netuid", type=int, default=554)
    p.add_argument("--wallet", default="sentinel")
    p.add_argument("--hotkey", default="miner")
    p.add_argument("--endpoint", default="finney")
    p.add_argument("--advertise-ip", help="the address validators can reach")
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8091)
    p.add_argument("--product", default="Milan", help="EPYC product line")
    p.add_argument("--measurement", help="the approved launch measurement, hex")
    p.add_argument("--dsn", default="sqlite:///")
    p.add_argument("--seed", type=pathlib.Path, default=DEFAULT_SEED,
                   help="SQL to seed a fresh SQLite database with")
    p.add_argument("--no-seed", action="store_true",
                   help="do not seed; the database already has the data")
    p.add_argument("--allow-mock", action="store_true",
                   help="run without SEV-SNP, for wiring tests only")
    p.add_argument("--print-measurement", action="store_true",
                   help="print this VM's launch measurement and exit")
    p.add_argument("--no-chain", action="store_true",
                   help="serve without publishing on-chain")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    )

    if args.print_measurement:
        from sentinel.sevsnp import guest

        if not guest.available():
            print("not a SEV-SNP guest: there is no launch measurement to read.")
            return 1
        print(guest.SevSnpSilicon().measurement)
        return 0

    if not args.measurement:
        p.error("--measurement is required (or --print-measurement to read it)")
    if args.no_seed:
        args.seed = None
    if not args.no_chain and not args.advertise_ip:
        p.error("--advertise-ip is required (or --no-chain to serve without publishing)")

    hotkey_ss58 = "mock-hotkey"
    wallet = None
    if not args.no_chain:
        import bittensor as bt

        wallet = bt.Wallet(name=args.wallet, hotkey=args.hotkey)
        hotkey_ss58 = wallet.hotkey.ss58_address

    server, enclave = build_miner(args, hotkey_ss58)
    stop = threading.Event()

    threading.Thread(target=server.serve_forever, daemon=True).start()
    logger.info(
        "miner serving on %s:%d  chip=%s  hotkey=%s",
        args.bind, server.server_port, enclave.chip_id, hotkey_ss58,
    )

    if not args.no_chain:
        import asyncio

        threading.Thread(
            target=lambda: asyncio.run(publish_forever(args, wallet, stop)),
            daemon=True,
        ).start()

    # Shut down on a signal rather than on an exception, so a restart is a
    # deliberate event and systemd can tell the difference between the two.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    try:
        while not stop.is_set():
            time.sleep(1)
    finally:
        logger.info("shutting down")
        stop.set()
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
