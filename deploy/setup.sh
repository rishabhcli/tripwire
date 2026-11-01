#!/usr/bin/env bash
# Provision a fresh Ubuntu 24.04 Vultr VM. Run as a sudo user. Never put keys in this file.
set -euo pipefail
sudo apt-get update -y && sudo apt-get install -y docker.io caddy python3-venv git
sudo systemctl enable --now docker
git clone https://github.com/rishabhcli/tripwire.git ~/tripwire 2>/dev/null || (cd ~/tripwire && git pull)
cd ~/tripwire
sudo docker build -t tripwire-sandbox:latest -f deploy/sandbox.Dockerfile .
python3 -m venv .venv && .venv/bin/pip install -q -e .
echo "Next: create /etc/tripwire.env with VULTR_INFERENCE_API_KEY and TRIPWIRE_MODEL, then install deploy/tripwire.service"
