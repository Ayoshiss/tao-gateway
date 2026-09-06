# Run a Sentinel miner

About an hour, most of it waiting for a VM to install packages.

Read the two paragraphs below before you spend anything. They are the parts
that are different from every other subnet you have mined.

---

## What you are signing up for

**Netuid 554 is on Bittensor testnet. There are no emissions.** Nothing here
earns. If you are here to mine for reward, stop now, and thanks for reading this
far. What this is worth doing for is telling us where it breaks.

**A Sentinel miner needs a confidential VM, not spare capacity.** Most subnets
let you point hardware you already own at the problem. This one cannot: the
whole design rests on an AMD SEV-SNP processor proving which code is running
before a credential is released to it. That means a specific machine type, and
it costs roughly $30 a month on GCP spot pricing. If you are doing this as a
favour, we should be paying for it. Ask.

**Every miner must run a byte-identical image.** The validator pins one approved
launch measurement. A different image measures differently and scores zero. This
is a real operational burden and we know it; it is one of the things we want your
opinion on.

---

## What is not yet true

Say this plainly rather than have you find it.

The SEV-SNP launch measurement covers the boot state of the VM, not the Python
application on top of it. We tested this on our own live miner: modifying the
miner's code and the data it serves left the measurement byte-identical, and the
validator still scored it 1.0. So today the chip proves what *booted*, not what
is *running*.

Fixing that means binding the root filesystem into the measurement. It is the
open problem, it is tracked, and it is not solved. You are looking at an
incentive mechanism and a deployment path, not a finished security guarantee.

---

## Prerequisites

- A GCP project with billing enabled, and `gcloud` logged in to it.
- Python 3.11+ locally.
- A Bittensor wallet with a little testnet TAO. Registration burn is about
  τ0.0005, so a faucet drip is plenty.

Confidential VMs are available in most regions. These instructions use
`us-central1-a`.

---

## 1. Get the code

```bash
git clone https://github.com/Ayoshiss/sentinel-subnet.git
cd sentinel-subnet
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 2. Create a hotkey and register it on 554

The hotkey is the miner's identity. It never needs your coldkey on the server.

```bash
.venv/bin/btcli wallet new-hotkey --wallet <your-wallet> --wallet-hotkey sentinel-miner
```

```bash
.venv/bin/btcli subnet register --netuid 554 --network test --wallet <your-wallet> --hotkey sentinel-miner
```

Note the ss58 address it prints. You need it twice below.

## 3. Provision the confidential VM

```bash
PROJECT=<your-gcp-project> ZONE=us-central1-a NAME=sentinel-miner-1 ./deploy/provision-gcp.sh
```

This creates an `n2d-standard-2` with SEV-SNP enabled, opens tcp:8091 to
validators, and installs the miner without starting it. It prints the external
IP. Keep it.

Confidential instances cannot live migrate, so the maintenance policy is
TERMINATE and the instance is set to restart on failure. Expect it to bounce
occasionally. That is normal and the miner comes back on its own.

Confirm the hardware is genuinely what it claims before trusting any of it:

```bash
gcloud compute ssh sentinel-miner-1 --zone=us-central1-a --command 'ls -l /dev/sev-guest && sudo dmesg | grep -i sev-snp'
```

You want to see `Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP`.

## 4. Read the launch measurement

The image has to tell you what it measures as; you cannot decide it.

```bash
gcloud compute ssh sentinel-miner-1 --zone=us-central1-a --command \
  'cd /opt/sentinel && sudo .venv/bin/python scripts/run_miner.py --print-measurement'
```

If this does not match the measurement the validator has pinned, your miner will
serve happily and score zero. Compare it against the value in TESTNET.md and
tell us if it differs, because that is exactly the coordination problem we want
to understand.

## 5. Configure and start

```bash
gcloud compute ssh sentinel-miner-1 --zone=us-central1-a
sudo tee /etc/sentinel/miner.env <<EOF
HOTKEY_SS58=<the ss58 from step 2>
MEASUREMENT=<the measurement from step 4>
EOF
sudo systemctl enable --now sentinel-miner
journalctl -u sentinel-miner -f
```

You should see the chip detected, then a credential released to the enclave,
then the miner serving on 0.0.0.0:8091.

**No wallet key goes on this machine.** The miner serves under an address it
holds no private key for. It never signs with the hotkey: it verifies its
callers' signatures, and its own answers are signed by the chip. If the VM is
compromised, the attacker gets a miner that answers queries, not your identity.

## 6. Publish the endpoint

From your laptop, where the wallet actually lives:

```bash
.venv/bin/python scripts/publish_axon.py --netuid 554 --network test \
  --wallet <your-wallet> --hotkey sentinel-miner --ip <the external IP> --port 8091
```

ServeAxon is rate limited per neuron, roughly 50 blocks, so this belongs at
setup and on address changes, not in a loop.

## 7. Check you are discoverable

```bash
.venv/bin/btcli subnets metagraph 554 --network test
```

And that the miner answers from outside:

```bash
curl http://<the external IP>:8091/health
```

That returns the chip id, the launch measurement, and AMD's certificate chain.
Handing out the certificates is deliberate: they are public, and the chain is
checked against a root pinned in the verifier, so verification never has to
reach AMD's key service.

---

## When it goes wrong

**Miner exits with "launch measurement mismatch".** The image is not the one
pinned. That is the gate doing its job. Read the running value and talk to us.

**`no /dev/sev-guest`.** The VM was not created as confidential. Check the
instance was made with `--confidential-compute-type=SEV_SNP`.

**Scores zero on correctness with a valid attestation.** The database is not
seeded, so the validator's probe hits a missing table. `scripts/miner-seed.sql`
is applied automatically on a fresh SQLite database.

**Nothing discovers you.** Almost always the wrong network. 554 is testnet, so
every command needs `--network test`. Publishing to finney succeeds against the
wrong chain and leaves you invisible with no error anywhere.

---

## What we want back

Not endorsements. The useful thing is what annoyed you.

- Where did this break, and how long did it actually take?
- Would you run a paid confidential VM for a subnet? At what emission level?
- The single-pinned-image requirement. Dealbreaker, or manageable?
- What would make you not bother?
