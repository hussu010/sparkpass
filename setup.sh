#!/usr/bin/env bash
# One command for the pair: the steps of "Set up the pair" in README.md, on the head unit, as the user of
# sparkrun (not root; it uses sudo, and ssh -t to the worker, where a step needs root).
# Idempotent: each step checks first and skips what is done, so a second run changes nothing except
# install.sh, which runs again with no lease (it picks up an update of this repository).
set -euo pipefail

usage() {
	cat <<'EOF'
usage: ./setup.sh <worker-address> [--binary <path>]

  <worker-address>  the ConnectX-7 address of the worker, for example 10.100.0.2
  --binary <path>   the sparkpass binary for install.sh
                    (default: build target/release/sparkpass of this repository in Docker)
EOF
}

die() {
	printf 'setup.sh: error: %s\n' "$*" >&2
	exit 1
}

step() {
	printf '\n== %s\n' "$*"
}

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
worker=
binary=
while (($# > 0)); do
	case $1 in
	--binary)
		(($# >= 2)) || { usage >&2; exit 2; }
		binary=$2
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		usage >&2
		exit 2
		;;
	*)
		[[ -z $worker ]] || { usage >&2; exit 2; }
		worker=$1
		shift
		;;
	esac
done
[[ -n $worker ]] || { usage >&2; exit 2; }
((EUID != 0)) || die "run it as the user of sparkrun, not as root"

# The ConnectX-7 link: the interface and the head address that reach the worker with no router.
route=$(ip -o route get "$worker") || die "no route to $worker"
[[ $route != *" via "* ]] || die "$worker is behind a router; give the ConnectX-7 address of the worker"
iface=$(awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' <<<"$route")
head=$(awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}' <<<"$route")
# The serve port of templates/pair.yaml (defaults.port).
port=8000
export PATH=$HOME/.local/bin:$PATH SPARKRUN_MGMT_IFACE=$iface SPARKRUN_NO_TELEMETRY=1
echo "head $head, worker $worker, link $iface"

step "1. Tailscale admin settings (checks only: the admin console changes them)"
command -v tailscale >/dev/null || die "install Tailscale (https://tailscale.com/download/linux), then: sudo tailscale up"
name=$(tailscale status --json | python3 -c '
import json, sys
s = json.load(sys.stdin); me = s["Self"]; missing = []
if not s.get("CertDomains"): missing.append("DNS page: MagicDNS on, then HTTPS Certificates, Enable HTTPS")
if "funnel" not in (me.get("CapMap") or {}): missing.append("Access controls: the funnel node attribute for your login (README, step 1)")
if me.get("KeyExpiry"): missing.append("Machines page: this unit, Disable key expiry")
if missing: sys.exit("set these in https://login.tailscale.com/admin, then run ./setup.sh again:\n  - " + "\n  - ".join(missing))
print(me["DNSName"].rstrip("."))')
echo "ok: $name"

step "2. sparkrun, the cluster, and the settings of both units"
if ! command -v sparkrun >/dev/null; then
	command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh
	uv tool install sparkrun==0.3.10
fi
sparkrun setup telemetry --disable >/dev/null
sparkrun cluster show pair >/dev/null 2>&1 ||
	sparkrun cluster create pair --hosts "$head,$worker" --transfer-mode push --transfer-interface cx7 \
		--mgmt-interface "$iface"
sparkrun cluster set-default pair >/dev/null
# The head connects to itself too: it is the first host of the cluster. setup ssh asks for passwords.
for h in "$head" "$worker"; do
	ssh -n -o BatchMode=yes -o ConnectTimeout=5 "$h" true 2>/dev/null || { sparkrun setup ssh --cluster pair; break; }
done
need_docker=
need_earlyoom=
for h in "$head" "$worker"; do
	ssh -n -o BatchMode=yes "$h" '[[ $(uname -r) != 7.0.0-1019-nvidia ]] || grep -qw kho=off /proc/cmdline' ||
		die "$h: kernel 7.0.0-1019-nvidia breaks NCCL over RoCE without kho=off (README, Before you start)"
	ssh -n -o BatchMode=yes "$h" 'id -nG | grep -qw docker' || need_docker=yes
	ssh -n -o BatchMode=yes "$h" 'systemctl is-active --quiet earlyoom' || need_earlyoom=yes
	# Linger keeps the shared memory of vLLM with no login. SPARKRUN_MGMT_IFACE keeps the control ports of vLLM
	# on the link (README, step 2). nodivert: the firewall rules refuse to load without it. ssh -t: sudo asks
	# for the password of that unit, only when a setting is missing.
	ssh -t "$h" "set -e
loginctl show-user \$USER -p Linger --value | grep -qx yes || sudo loginctl enable-linger \$USER
grep -qx 'SPARKRUN_MGMT_IFACE=$iface' /etc/environment || echo 'SPARKRUN_MGMT_IFACE=$iface' | sudo tee -a /etc/environment >/dev/null
! command -v tailscale >/dev/null || tailscale debug prefs | grep -q '\"NetfilterMode\": 1' || sudo tailscale set --netfilter-mode=nodivert"
done
[[ -z $need_docker ]] || sparkrun setup docker-group --cluster pair
[[ -z $need_earlyoom ]] || sparkrun setup earlyoom --cluster pair

step "3. The firewall on the worker"
tar -C "$repo" --exclude=.git --exclude=target -cf - . | ssh -o BatchMode=yes "$worker" 'mkdir -p sparkpass && tar -xf - -C sparkpass'
ssh -t "$worker" 'systemctl is-active --quiet sparkpass-firewall.service && cmp -s sparkpass/firewall/rules.sh /usr/local/lib/sparkpass/rules.sh ||
(cd sparkpass && sudo ./install.sh --second-unit)'

step "4. The gateway (install.sh)"
[[ -x /usr/bin/caddy ]] || sudo apt-get install -y caddy
if [[ -z $binary ]]; then
	binary=$repo/target/release/sparkpass
	docker=(docker)
	# A docker group added in step 2 counts only from the next login.
	docker info >/dev/null 2>&1 || docker=(sudo docker)
	"${docker[@]}" run --rm --user "$(id -u):$(id -g)" -e CARGO_HOME=/work/target/cargo-home -v "$repo":/work -w /work \
		rust:1-slim-bookworm cargo build --locked --release
fi
if [[ ! -x /usr/local/bin/sparkpass || $(sudo /usr/local/bin/sparkpass list) == "no lease" ]]; then
	# Its next steps are steps 5 and 7 here.
	sudo "$repo/install.sh" --binary "$binary" | sed '/^Next steps/,$d'
else
	echo "a lease is active: install.sh skipped (it runs only with no lease)"
fi

step "5. Funnel and the settings"
sudo tailscale set --accept-dns=false --auto-update=false --netfilter-mode=nodivert
sudo tailscale serve status --json | grep -qE '"TCPForward": *"127\.0\.0\.1:443"' ||
	sudo tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443
sudo tailscale cert --cert-file - "$name" >/dev/null
# Only empty values: a value of the owner stays.
sudo sed -i -e "s|^PUBLIC_URL=\$|PUBLIC_URL=https://$name|" -e "s|^MODEL_PORT=\$|MODEL_PORT=$port|" /etc/sparkpass/config
sudo sed -i -e "s|^SPARKPASS_SITE=\$|SPARKPASS_SITE=$name|" -e "s|^SPARKPASS_MODEL_PORT=\$|SPARKPASS_MODEL_PORT=$port|" /etc/sparkpass/caddy.env
if ! grep -qE '^TS_PERMIT_CERT_UID=.?caddy' /etc/default/tailscaled; then
	echo TS_PERMIT_CERT_UID=caddy | sudo tee -a /etc/default/tailscaled >/dev/null
	echo "restarting tailscaled: an SSH session over the tailnet can drop; then run ./setup.sh again"
	sudo systemctl restart tailscaled
fi
sudo systemctl start pass-reconcile.timer
sudo sparkpass reconcile

step "6. The model"
echo "The weights are under the Qwen Community License 1.0: clause 2 needs a licence from Qwen before a paid pass."
# Shard 35 (the MXFP8 prefill weights of the checkpoint in templates/pair.yaml): the serve command fetches it at
# start when it is missing, and sparkrun stops a head that is not ready after about 2 minutes.
image=$(awk '$1 == "container:" {print $2}' "$repo/templates/pair.yaml")
checkpoint=$(awk -F'"' '$1 ~ /VLLM_B12X_NVFP4_MXFP8_CHECKPOINT:/ {print $2}' "$repo/templates/pair.yaml")
checkpoint=${checkpoint#/cache/huggingface/hub/}
[[ $checkpoint == models--*/snapshots/* ]] || die "no VLLM_B12X_NVFP4_MXFP8_CHECKPOINT in templates/pair.yaml"
model_repo=${checkpoint#models--}
model_repo=${model_repo%%/*}
model_repo=${model_repo/--//}
revision=${checkpoint##*/}
shard="model-00035-of-00036.safetensors"
for h in "$head" "$worker"; do
	ssh -n -o BatchMode=yes "$h" "test -f .cache/huggingface/hub/$checkpoint/$shard" && continue
	ssh -n -o BatchMode=yes "$h" "docker pull -q $image >/dev/null && docker run --rm --user \$(id -u):\$(id -g) \
-e HF_HOME=/cache/huggingface -v \$HOME/.cache/huggingface:/cache/huggingface --entrypoint python3 $image -c \
\"from huggingface_hub import snapshot_download as d; d('$model_repo', revision='$revision', \
allow_patterns=['$shard', 'model.safetensors.index.json'])\""
done
health() { curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$port/health" || true; }
if [[ $(health) != 200 ]]; then
	# Old containers of a failed start hold GPU memory (systemd/sparkpass-model.service). The first run downloads
	# the image and the model (about 140 GB), then copies them to the worker.
	(cd "$repo" && { sparkrun stop --all --cluster pair || true; } && sparkrun run templates/pair.yaml --cluster pair --no-follow)
	for _ in $(seq 1 90); do
		[[ $(health) == 200 ]] && break
		sleep 10
	done
fi

step "7. Checks"
[[ $(health) == 200 ]] || die "the model does not answer on 127.0.0.1:$port; see: sparkrun logs --cluster pair"
model=$(curl -s "http://127.0.0.1:$port/v1/models" | python3 -c 'import json, sys; print(json.load(sys.stdin)["data"][0]["id"])')
echo "ok: model $model"
systemctl is-active --quiet caddy || die "Caddy is stopped; see: journalctl -u pass-reconcile.service"
# Through Funnel: no key gets 401. Each new connection through a relay can take seconds.
code=$(curl -sS -o /dev/null -w '%{http_code}' --retry 4 --retry-all-errors -m 20 "https://$name/v1/models") || true
[[ $code == 401 ]] || die "https://$name/v1/models gave $code with no key, expected 401"
echo "ok: https://$name/v1/models gives 401 with no key"
cat <<EOF

The pair is ready. Model: $model
- Your editor: on your computer (on the tailnet), keep this running:
    ssh -N -o ServerAliveInterval=30 -L 127.0.0.1:$port:127.0.0.1:$port $USER@$name
  then use the OpenAI-compatible base URL http://localhost:$port/v1, model $model, any API key text.
- A guest: sudo sparkpass grant <name> --ttl 2h prints the base URL https://$name/v1 and a key.
EOF
