"""
Publish a miner's endpoint on-chain, from wherever the hotkey actually lives.

    python scripts/publish_axon.py --netuid 554 --ip 34.44.81.184 --port 8091

Separate from the miner on purpose. A miner never signs with its hotkey: it
verifies its callers' signatures, and its own answers are signed by the chip.
The only thing the private hotkey is needed for is this one chain call, so
there is no reason for it to sit on a cloud VM for the life of the deployment.

Run this from the machine holding the wallet. The miner runs elsewhere with
`--hotkey-ss58 <address> --no-chain`, serving under an identity whose key it
does not have. If that VM is compromised, the attacker gets a miner that
answers queries; they do not get the ability to move the endpoint, sign as the
neuron, or touch anything the coldkey controls.

The published address does not expire, so this is a one-off per address change.
"""

import argparse
import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


async def main(args) -> int:
    import bittensor as bt

    from sentinel.chain import publish_axon

    kwargs = {"path": args.wallet_path} if args.wallet_path else {}
    wallet = bt.Wallet(name=args.wallet, hotkey=args.hotkey, **kwargs)
    hotkey_ss58 = wallet.hotkey.ss58_address
    print(f"publishing {args.ip}:{args.port} for {hotkey_ss58} on netuid {args.netuid}")

    async with bt.Subtensor(args.endpoint) as st:
        signer = bt.resolve_signer(wallet, "hotkey")
        try:
            result = await publish_axon(st, signer, args.netuid, args.ip, args.port)
        except ValueError as exc:
            print(f"refused: {exc}")
            return 1
        print(f"ServeAxon success={getattr(result, 'success', result)}")
        print(f"  {str(getattr(result, 'message', ''))[:120]}")

    print(f"\nRun the miner with:\n  --hotkey-ss58 {hotkey_ss58} --no-chain")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--netuid", type=int, default=554)
    # 554 is a testnet subnet. Publishing to finney would succeed against the
    # wrong chain and leave the miner undiscoverable with no error to show for it.
    # --network is the spelling btcli uses, and operators type it by reflex.
    p.add_argument("--endpoint", "--network", dest="endpoint", default="test")
    p.add_argument("--wallet", default="sentinel")
    p.add_argument("--hotkey", default="miner")
    p.add_argument("--wallet-path", default=None)
    p.add_argument("--ip", required=True, help="address validators can reach")
    p.add_argument("--port", type=int, default=8091)
    raise SystemExit(asyncio.run(main(p.parse_args())))
