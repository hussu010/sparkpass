#!/usr/bin/env bash
# Tests firewall/rules.sh with a real iptables (nf_tables, as on the units) in a privileged Docker container.
# Network namespaces stand in for the head unit and its peers: the LAN (enP7s7), the tailnet (tailscale0)
# and the other unit on the two ConnectX-7 interfaces. Runs on a developer machine with docker; it needs no
# hardware. It does not prove the units: tailscaled (Funnel, nodivert), the chains of the real Docker and the
# real interfaces are for the check on the units (TODOS.md, "Firewall rules with Tailscale on the units").
# It prints one line for each case and stops at the first mismatch with exit code 1.
set -euo pipefail

if [[ ${1:-} != --inside ]]; then
	repo=$(cd "$(dirname "$0")/.." && pwd)
	exec docker run --rm --init --privileged -v "$repo":/repo:ro "${FIREWALL_TEST_IMAGE:-debian:bookworm-slim}" bash /repo/tests/firewall.sh --inside
fi

if ! command -v iptables >/dev/null; then
	apt-get -qq update >/dev/null
	DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends iptables iproute2 netcat-openbsd procps >/dev/null
fi

rules=/repo/firewall/rules.sh
fail() {
	echo "FAIL $*"
	exit 1
}
ns() { ip netns exec "$@"; }

for n in unit lan tail peer; do
	ip netns add "$n"
	ns "$n" ip link set lo up
done
# <unit interface> <namespace> <its interface> <unit address> <its address> <IPv6 /64 prefix>
wire() {
	ip link add "$1" netns unit type veth peer name "$3" netns "$2"
	ns unit ip addr add "$4/24" dev "$1"
	ns unit ip addr add "$6::1/64" dev "$1" nodad
	ns "$2" ip addr add "$5/24" dev "$3"
	ns "$2" ip addr add "$6::2/64" dev "$3" nodad
	ns unit ip link set "$1" up
	ns "$2" ip link set "$3" up
}
wire enP7s7 lan eth0 192.168.1.125 192.168.1.50 fd00:1
wire tailscale0 tail eth0 100.64.0.1 100.64.0.2 fd00:3
wire enp1s0f0np0 peer eth0 10.100.0.1 10.100.0.2 fd00:2
wire enP2p1s0f0np0 peer eth1 10.100.1.1 10.100.1.2 fd00:4
# A LAN device with a manual route to the link, and a unit that forwards: the path through one unit to the
# other. FORWARD keeps the kernel's ACCEPT policy (Docker sets DROP for IPv4 only in some boot orders).
ns lan ip route add 10.100.0.0/24 via 192.168.1.125
ns peer ip route add 192.168.1.0/24 via 10.100.0.1
ns unit sysctl -qw net.ipv4.ip_forward=1
for cmd in iptables ip6tables; do
	ns unit "$cmd" -N DOCKER-USER
	ns unit "$cmd" -A FORWARD -j DOCKER-USER
done

# A control port on all addresses, SSH, a port of the other unit, and a LAN service that the unit uses.
ns unit sysctl -qw net.ipv6.bindv6only=1
for port in 25000 22; do
	ns unit nc -4 -lk "$port" >/dev/null 2>&1 &
	ns unit nc -6 -lk "$port" >/dev/null 2>&1 &
done
ns peer nc -4 -lk 25000 >/dev/null 2>&1 &
ns lan nc -4 -lk 7000 >/dev/null 2>&1 &
sleep 1

cases=(
	"lan 192.168.1.125 25000 deny LAN to a control port"
	"lan fd00:1::1 25000 deny LAN to a control port, IPv6"
	"lan 10.100.0.1 25000 deny LAN to the link address of the unit"
	"tail 100.64.0.1 25000 deny tailnet to a control port"
	"tail fd00:3::1 25000 deny tailnet to a control port, IPv6"
	"lan 10.100.0.2 25000 deny LAN through the unit to the other unit"
	"peer 10.100.0.1 25000 allow other unit to a control port, first link interface"
	"peer 10.100.1.1 25000 allow other unit to a control port, second link interface"
	"peer fd00:2::1 25000 allow other unit to a control port, IPv6"
	"unit 127.0.0.1 25000 allow loopback"
	"unit ::1 25000 allow loopback, IPv6"
	"lan 192.168.1.125 22 allow SSH from the LAN"
	"tail 100.64.0.1 22 allow SSH from the tailnet"
	"tail fd00:3::1 22 allow SSH from the tailnet, IPv6"
	"unit 192.168.1.50 7000 allow the reply to a connection that the unit opens"
)
# <namespace> <address> <port>: a TCP connect within 1 s.
connects() { ns "$1" timeout 1 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null; }
# <label>: each case gets its expected result; with "no rules", each case connects.
check() {
	local c from addr port want label got
	for c in "${cases[@]}"; do
		read -r from addr port want label <<<"$c"
		[[ $1 == "no rules" ]] && want=allow
		got=deny
		connects "$from" "$addr" "$port" && got=allow
		[[ $got == "$want" ]] || fail "$1: $label ($from -> $addr:$port) got $got, want $want"
	done
	echo "ok   $1: ${#cases[@]} paths"
}
# <command> <chain> <jump>: the jump is the first rule of the chain, and the only jump to that target.
first() {
	[[ $(ns unit "$1" -S "$2" | sed -n 2p) == "-A $2 -j $3" ]] || fail "$case: $1 $2 does not start with the jump to $3"
	[[ $(ns unit "$1" -S "$2" | grep -c -e "-j $3\$") == 1 ]] || fail "$case: $1 $2 has more than one jump to $3"
}

check "no rules"

case="first load"
ns unit "$rules" || fail "$case: rules.sh failed"
check "$case"
for cmd in iptables ip6tables; do
	first "$cmd" INPUT SPARKPASS-INPUT
	first "$cmd" DOCKER-USER SPARKPASS-FORWARD
done
echo "ok   $case: the jumps are first in INPUT and DOCKER-USER, for IPv4 and IPv6"

case="second load"
before=$(ns unit iptables-save -t filter | grep -v '^#')
# Another tool puts an accept rule first; the next load puts the jump back in front of it.
ns unit iptables -I INPUT 1 -i tailscale0 -j ACCEPT
ns unit "$rules" || fail "$case: rules.sh failed"
ns unit iptables -D INPUT -i tailscale0 -j ACCEPT
[[ $(ns unit iptables-save -t filter | grep -v '^#') == "$before" ]] || fail "$case: the rules differ from the first load"
first iptables INPUT SPARKPASS-INPUT
echo "ok   $case: the same rules as the first load, and the jump first again over a later accept rule"

case="tailscaled in netfilter mode on"
for cmd in iptables ip6tables; do
	ns unit "$cmd" -N ts-input
	ns unit "$cmd" -A ts-input -i tailscale0 -j ACCEPT
	ns unit "$cmd" -I INPUT 1 -j ts-input
done
if ns unit "$rules" 2>"/tmp/err"; then fail "$case: rules.sh exited 0"; fi
grep -q 'tailscale set --netfilter-mode=nodivert' /tmp/err || fail "$case: no nodivert hint: $(cat /tmp/err)"
connects tail 100.64.0.1 25000 && fail "$case: the tailnet reaches a control port"
first iptables INPUT SPARKPASS-INPUT
echo "ok   $case: exit 1 with the nodivert hint, and the tailnet still gets no control port"

case="no Docker"
ip netns add bare
if ns bare "$rules" 2>"/tmp/err"; then fail "$case: rules.sh exited 0"; fi
grep -q 'no DOCKER-USER chain' /tmp/err || fail "$case: no Docker hint: $(cat /tmp/err)"
echo "ok   $case: exit 1 with the Docker hint"

echo "PASS"
