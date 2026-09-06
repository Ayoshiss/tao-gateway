#!/usr/bin/env bash
#
# GCP startup script. Runs as root on first boot.
#
# Installs the miner and leaves it stopped. Starting it needs the launch
# measurement, which cannot be known until this image has booted once, and a
# wallet hotkey, which should never be baked into an image.

set -euo pipefail

exec > >(tee /var/log/sentinel-startup.log) 2>&1
echo "sentinel startup $(date -Is)"

# The whole premise. If this device is missing, the VM is not confidential and
# nothing installed below would be telling the truth, so stop loudly.
if [ ! -e /dev/sev-guest ]; then
    echo "FATAL: /dev/sev-guest absent, this is not a SEV-SNP guest"
    exit 1
fi

apt-get update -qq
apt-get install -y -qq python3-venv python3-dev git build-essential pkg-config

id -u sentinel >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin sentinel

# The guest owns the device; the miner runs unprivileged and still needs it.
cat >/etc/udev/rules.d/90-sev-guest.rules <<'EOF'
KERNEL=="sev-guest", OWNER="sentinel", GROUP="sentinel", MODE="0600"
EOF
udevadm control --reload-rules && udevadm trigger

git clone --depth 1 https://github.com/Ayoshiss/sentinel-subnet.git /opt/sentinel
cd /opt/sentinel
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

install -d -m 0750 -o sentinel -g sentinel /etc/sentinel
cat >/etc/sentinel/miner.env <<'EOF'
# The miner's public address. No private key belongs on this machine: the
# endpoint is published from wherever the wallet lives, with
# scripts/publish_axon.py.
HOTKEY_SS58=
# Read once from this VM's own chip:
#   sudo .venv/bin/python scripts/run_miner.py --print-measurement
MEASUREMENT=
EOF
chmod 0640 /etc/sentinel/miner.env
chown root:sentinel /etc/sentinel/miner.env

chown -R sentinel:sentinel /opt/sentinel
install -m 0644 /opt/sentinel/deploy/sentinel-miner.service /etc/systemd/system/
systemctl daemon-reload

echo "installed. Not started: /etc/sentinel/miner.env still needs HOTKEY_SS58 and MEASUREMENT."
