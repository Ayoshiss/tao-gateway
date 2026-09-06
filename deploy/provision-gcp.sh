#!/usr/bin/env bash
#
# Provision a SEV-SNP confidential VM on GCP and install the Sentinel miner.
#
#   ./deploy/provision-gcp.sh
#
# Two things about this machine are not defaults and are not optional.
#
# SEV-SNP requires an N2D on AMD Milan or later, and GCP will not schedule a
# confidential instance for live migration, so the maintenance policy has to be
# TERMINATE. That means Google can stop this VM during host maintenance, which
# is why --restart-on-failure is paired with it: the miner comes back on its
# own, and a miner that is down is a miner scoring zero.
#
# Restarting is safe precisely because it is not trusted. The measurement is
# read from the chip at every start and checked against the pinned value, so a
# VM that comes back as something other than the approved image refuses to
# serve rather than quietly rejoining the subnet.

set -euo pipefail

PROJECT="${PROJECT:-project-46c1af1b-86e0-4b9b-a77}"
ZONE="${ZONE:-us-central1-a}"
NAME="${NAME:-sentinel-miner-1}"
MACHINE="${MACHINE:-n2d-standard-2}"
NETUID="${NETUID:-554}"
PORT="${PORT:-8091}"

echo "project  $PROJECT"
echo "zone     $ZONE"
echo "instance $NAME ($MACHINE, SEV-SNP)"
echo

# Validators reach the miner over HTTP on one port. Nothing else is open, and
# SSH stays on Google's own IAP range rather than the whole internet.
if ! gcloud compute firewall-rules describe sentinel-miner --project="$PROJECT" >/dev/null 2>&1; then
    echo "creating firewall rule"
    gcloud compute firewall-rules create sentinel-miner \
        --project="$PROJECT" \
        --allow="tcp:${PORT}" \
        --target-tags=sentinel-miner \
        --description="Validator challenges to Sentinel miners"
fi

echo "creating instance"
gcloud compute instances create "$NAME" \
    --project="$PROJECT" \
    --zone="$ZONE" \
    --machine-type="$MACHINE" \
    --confidential-compute-type=SEV_SNP \
    --min-cpu-platform="AMD Milan" \
    --maintenance-policy=TERMINATE \
    --restart-on-failure \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=20GB \
    --boot-disk-type=pd-balanced \
    --tags=sentinel-miner \
    --metadata-from-file=startup-script="$(dirname "$0")/startup.sh"

IP=$(gcloud compute instances describe "$NAME" --project="$PROJECT" --zone="$ZONE" \
     --format='value(networkInterfaces[0].accessConfigs[0].natIP)')

cat <<EOF

instance up, external IP $IP

The startup script installed the code but did NOT start the miner, because two
things cannot be decided from here.

1. The measurement. Read it from the chip itself, once:

     gcloud compute ssh $NAME --project=$PROJECT --zone=$ZONE --command \\
       'cd /opt/sentinel && sudo .venv/bin/python scripts/run_miner.py --print-measurement'

   That value identifies this exact image. Pin it in /etc/sentinel/miner.env.

2. The wallet. The hotkey has to be created or copied onto the box by you.
   Never paste a coldkey onto a miner; ServeAxon is signed by the hotkey and
   the hotkey is all this machine needs.

Then:

     gcloud compute ssh $NAME --project=$PROJECT --zone=$ZONE
     sudo systemctl enable --now sentinel-miner
     journalctl -u sentinel-miner -f

Confirm SEV-SNP is genuinely on before trusting any of it:

     ls -l /dev/sev-guest && dmesg | grep -i sev
EOF
