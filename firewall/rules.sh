#!/usr/bin/env bash
# The sparkpass firewall rules, for both units (docs/designs/guest-pass-mvp.md, "Constraints").
# vLLM, Ray and NCCL open control ports with random numbers, some on all addresses (25000), and these ports
# permit code execution. So the rules decide by interface, not by port: a new inbound connection reaches
# this unit only on loopback and on the ConnectX-7 link to the other unit. From the LAN, the tailnet and the
# Docker bridges, only SSH and the host services below get through. Replies to connections that this unit
# opened always get through. Tailscale Funnel needs no rule: tailscaled takes the connections to its peer
# API and serve ports in its own network stack, before the kernel (shouldProcessInbound in
# wgengine/netstack, tailscale 1.104.1; checked on spark-3, 2026-10-15).
# The chains only drop: allowed traffic goes on to the rest of INPUT and FORWARD. Each run replaces the
# chains and puts the jump to them first in INPUT and DOCKER-USER, in one iptables-restore transaction for
# each family, so no run removes a rule while a workspace runs.
# Callers, as root: sparkpass grant and reconcile on the head unit, sparkpass-firewall.service on the
# second unit. A non-zero exit makes grant refuse and reconcile stop the gateway.
set -euo pipefail

# The two interfaces of the ConnectX-7 port that links the units: the same names on each DGX Spark.
link=(enp1s0f0np0 enP2p1s0f0np0)

die() {
	printf 'rules.sh: error: %s\n' "$*" >&2
	exit 1
}

# <command> <ICMP protocol> <DHCP server port> <DHCP client port> <mDNS group>
load() {
	local cmd=$1 i pair from to jumps n
	"$cmd" -w 5 -S DOCKER-USER >/dev/null 2>&1 || die "$cmd has no DOCKER-USER chain: start Docker first"
	{
		echo '*filter'
		echo ':SPARKPASS-INPUT - [0:0]'
		echo ':SPARKPASS-FORWARD - [0:0]'
		echo '-A SPARKPASS-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN'
		echo '-A SPARKPASS-INPUT -i lo -j RETURN'
		for i in "${link[@]}"; do echo "-A SPARKPASS-INPUT -i $i -j RETURN"; done
		echo "-A SPARKPASS-INPUT -p $2 -j RETURN"
		echo '-A SPARKPASS-INPUT -p tcp --dport 22 -j RETURN'
		# WireGuard of tailscaled (PORT in /etc/default/tailscaled): direct paths, not only the relays.
		echo '-A SPARKPASS-INPUT -p udp --dport 41641 -j RETURN'
		echo "-A SPARKPASS-INPUT -p udp --sport $3 --dport $4 -j RETURN"
		# mDNS: NVIDIA Sync and <host>.local find the unit by name.
		echo "-A SPARKPASS-INPUT -d $5 -p udp --dport 5353 -j RETURN"
		echo '-A SPARKPASS-INPUT -j DROP'
		# No routed path through one unit (LAN, tailnet, a container) to the link and the other unit.
		for i in "${link[@]}"; do echo "-A SPARKPASS-FORWARD -o $i -j DROP"; done
		# Each old jump goes and one new jump goes first, in the same transaction.
		for pair in INPUT:SPARKPASS-INPUT DOCKER-USER:SPARKPASS-FORWARD; do
			from=${pair%:*} to=${pair#*:}
			jumps=$("$cmd" -w 5 -S "$from" | grep -c -x -e "-A $from -j $to") || true
			for ((n = 0; n < jumps; n++)); do echo "-D $from -j $to"; done
			echo "-I $from 1 -j $to"
		done
		echo 'COMMIT'
	} | "$cmd-restore" -w 5 --noflush
}

load iptables icmp 67 68 224.0.0.251
load ip6tables ipv6-icmp 547 546 ff02::fb

# In its default netfilter mode, tailscaled puts its jumps first again at each start, and ts-input accepts
# all of tailscale0. The rules above stay loaded; this exit makes the owner fix the mode.
for cmd in iptables ip6tables; do
	if "$cmd" -w 5 -S | grep -q -E '^-A (INPUT|FORWARD) -j ts-(input|forward)$'; then
		die "tailscaled adds its own rules to INPUT and FORWARD (netfilter mode on). Run: tailscale set --netfilter-mode=nodivert"
	fi
done
