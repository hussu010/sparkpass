#!/usr/bin/env bash
# Tests firewall/check-workers.sh with fake sparkrun, ssh and ip commands (no network, no units).
# Value: protects=the model does not start while a worker of the cluster has no active firewall unit;
# fails_when=the script skips a worker, accepts an inactive or silent one, accepts a cluster with no worker, or
# ignores a sparkrun failure; why_new=the check is new (TODOS, "The worker starts vLLM even when its firewall rules
# did not load"); seam=PATH ($HOME/.local/bin comes first in the script).
set -uo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bin=$tmp/.local/bin
mkdir -p "$bin"
# Fakes. FAKE_HOSTS: the JSON host list; FAKE_ACTIVE: the hosts whose firewall unit is active.
cat >"$bin/sparkrun" <<'EOF'
#!/usr/bin/env bash
[[ $* == "cluster show pair --json" ]] || exit 9
[[ ${FAKE_SPARKRUN_FAILS:-} ]] && exit 1
printf '{"name": "pair", "hosts": %s}\n' "$FAKE_HOSTS"
EOF
cat >"$bin/ip" <<'EOF'
#!/usr/bin/env bash
echo "1: lo    inet 127.0.0.1/8 scope host lo"
echo "2: cx7    inet 10.100.0.1/24 scope global cx7"
EOF
cat >"$bin/ssh" <<'EOF'
#!/usr/bin/env bash
host=${*: -5:1}
[[ ${*: -4} == "systemctl is-active --quiet sparkpass-firewall.service" ]] || exit 9
echo "$host" >>"$HOME/ssh.log"
[[ " $FAKE_ACTIVE " == *" $host "* ]]
EOF
chmod +x "$bin"/*
fails=0
check() {
	local name=$1 want=$2 hosts=$3 active=$4 sparkrun_fails=${5:-}
	rm -f "$tmp/ssh.log"
	HOME=$tmp FAKE_HOSTS=$hosts FAKE_ACTIVE=$active FAKE_SPARKRUN_FAILS=$sparkrun_fails \
		bash "$repo/firewall/check-workers.sh" >/dev/null 2>"$tmp/err"
	local got=$?
	if [[ $got == "$want" ]]; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $got, want $want: $(cat "$tmp/err")"
		fails=$((fails + 1))
	fi
}
check "worker active" 0 '["10.100.0.1", "10.100.0.2"]' "10.100.0.2"
grep -qx 10.100.0.1 "$tmp/ssh.log" && { echo "FAIL the head (a local address) was checked over SSH"; fails=$((fails + 1)); }
check "worker inactive or silent" 1 '["10.100.0.1", "10.100.0.2"]' ""
check "second worker inactive" 1 '["10.100.0.1", "10.100.0.2", "10.100.0.3"]' "10.100.0.2"
check "no worker in the cluster" 1 '["10.100.0.1"]' ""
check "sparkrun fails" 1 '["10.100.0.1", "10.100.0.2"]' "10.100.0.2" yes
if ((fails > 0)); then
	echo "FAIL: $fails case(s)"
	exit 1
fi
echo "PASS: tests/check-workers.sh"
