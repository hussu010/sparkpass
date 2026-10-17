#!/usr/bin/env bash
# Run by sparkpass-model.service before each start of the model, as the user of sparkrun (no root): each other host of
# the sparkrun cluster must have sparkpass-firewall.service active (install.sh --second-unit). The control ports of
# vLLM permit code execution, and on a worker with no rules they accept connections from the LAN and the tailnet.
# The hosts come from the cluster that sparkrun starts the containers on. Exit 1 stops the start; the unit tries again.
set -euo pipefail
export PATH=$HOME/.local/bin:$PATH
cluster=${1:-pair}
die() {
	printf 'check-workers: %s; the model does not start\n' "$*" >&2
	exit 1
}
hosts=$(sparkrun cluster show "$cluster" --json | python3 -c 'import json, sys; print("\n".join(json.load(sys.stdin)["hosts"]))' 2>/dev/null) ||
	die "cannot read the hosts of the sparkrun cluster $cluster"
local_addresses=$(ip -o addr show | awk '{print $4}' | cut -d/ -f1)
workers=0
while read -r host; do
	[[ -n $host ]] || continue
	grep -qxF -- "$host" <<<"$local_addresses" && continue
	ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$host" systemctl is-active --quiet sparkpass-firewall.service ||
		die "$host: sparkpass-firewall.service is not active (or $host does not answer)"
	workers=$((workers + 1))
done <<<"$hosts"
((workers > 0)) || die "the sparkrun cluster $cluster has no host other than this unit"
echo "check-workers: the firewall is active on $workers worker(s)"
