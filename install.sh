#!/usr/bin/env bash
# Installs sparkpass on the head unit, or with --second-unit only the firewall rules and their boot unit
# on the second unit. Design: docs/designs/guest-pass-mvp.md ("Layout", "The gateway", "Locking, start
# order, and the boot gate", "Distribution Plan").
# Idempotent: run it again after each update of the repository. It refuses to run while a lease exists
# (upgrade order: install with no active lease). It never overwrites the token file or a settings file.
set -euo pipefail

usage() {
	cat <<'EOF'
usage: sudo ./install.sh [--binary <path>]
       sudo ./install.sh --second-unit

  --binary <path>  the sparkpass binary to install
                   (default: target/release/sparkpass of this repository)
  --second-unit    install only firewall/rules.sh and sparkpass-firewall.service (the second Spark)
  --help           show this text
EOF
}

die() {
	printf 'install.sh: error: %s\n' "$*" >&2
	exit 1
}

warn() {
	printf '\n*** WARNING: %s\n\n' "$*" >&2
}

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
binary=$repo/target/release/sparkpass
second_unit=false
while (($# > 0)); do
	case $1 in
	--binary)
		if (($# < 2)); then
			usage >&2
			exit 2
		fi
		binary=$2
		shift 2
		;;
	--second-unit)
		second_unit=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 2
		;;
	esac
done

((EUID == 0)) || die "run it as root: sudo $0"

rules_source=$repo/firewall/rules.sh
rules=/usr/local/lib/sparkpass/rules.sh
units=/etc/systemd/system

install_rules() {
	mkdir -p "${rules%/*}"
	install -m 0755 "$rules_source" "$rules"
}

# Update rule (eng review D4): automatic updates are off on both units. This value is the switch of the
# daily unattended upgrade (apt-daily-upgrade.timer); apt-config gives the value after all config files.
warn_on_automatic_updates() {
	local periodic=0
	eval "$(apt-config shell periodic APT::Periodic::Unattended-Upgrade 2>/dev/null)"
	if [[ $periodic != 0 ]]; then
		warn "automatic updates are on (APT::Periodic::Unattended-Upgrade \"$periodic\").
An update during a lease can stop the model or restart the unit. Turn them off on both units:
  dpkg-reconfigure -plow unattended-upgrades   (answer No)
Then update by hand only when no lease is active, and repeat the milestone 1 check before the next grant."
	fi
}

# Second unit: the firewall rules and their boot unit only.
if [[ $second_unit == true ]]; then
	[[ -f $rules_source ]] || die "$rules_source does not exist; milestone 1 writes it, and the second unit needs it"
	install_rules
	install -m 0644 "$repo/systemd/sparkpass-firewall.service" "$units/"
	systemctl daemon-reload
	systemctl enable sparkpass-firewall.service
	# Load the rules now, not only at the next boot. A failed load stops this script.
	systemctl restart sparkpass-firewall.service
	warn_on_automatic_updates
	echo "installed $rules and sparkpass-firewall.service; the rules are loaded and load again at each boot."
	echo "Check after a reboot: systemctl status sparkpass-firewall.service"
	exit 0
fi

# Head unit. All checks come before the first change, except the unit checks after daemon-reload.

# With no arguments, sparkpass prints its usage and exits with 2. Another code: a file that does not
# run here (another architecture, for example), or no file. A name with no "/" would run from PATH.
[[ $binary == */* ]] || binary=./$binary
code=0
"$binary" >/dev/null 2>&1 || code=$?
if ((code != 2)); then
	hint=
	# 126: the file exists but does not run. Bash gives 126 also for a binary of another architecture.
	((code == 126)) && hint=" For exit code 126: chmod +x it (a CI artifact has no exec bit), or use the build for this architecture."
	die "$binary is not a sparkpass build that runs on this host (exit code $code with no arguments, expected 2).$hint Build it with 'cargo build --locked --release', or pass --binary <path>."
fi

for file in gateway/Caddyfile systemd/caddy-sparkpass.conf systemd/pass-reconcile.service \
	systemd/pass-reconcile.timer etc/config.example etc/caddy.env.example; do
	[[ -f $repo/$file ]] || die "$repo/$file does not exist"
done

# The drop-in names /usr/bin/caddy: the Ubuntu package and the official Caddy apt repository both put it there.
caddy_hint="install Caddy 2.6 or newer from the Ubuntu package (apt install caddy) or the official Caddy apt repository"
[[ -x /usr/bin/caddy ]] || die "/usr/bin/caddy does not exist: $caddy_hint"
systemctl cat caddy.service >/dev/null 2>&1 || die "caddy.service does not exist: $caddy_hint"
getent group caddy >/dev/null || die "the group caddy does not exist: $caddy_hint"

# Upgrade order: install with no active lease. A missing binary is a first install.
if [[ -x /usr/local/bin/sparkpass ]]; then
	leases=$(/usr/local/bin/sparkpass list) || die "'sparkpass list' failed; install only when it shows no lease"
	[[ $leases == "no lease" ]] || die "install only with no lease; 'sparkpass list' shows:
$leases
End each lease first with 'sparkpass revoke <name>'."
fi

# time-sync.target waits for a real clock only with the wait service of the time daemon.
if systemctl is-enabled --quiet chrony.service 2>/dev/null; then
	wait_unit=chrony-wait.service
elif systemctl is-enabled --quiet systemd-timesyncd.service 2>/dev/null; then
	wait_unit=systemd-time-wait-sync.service
else
	die "neither chrony nor systemd-timesyncd is enabled; reconcile needs a real clock before it starts the gateway"
fi
systemctl cat "$wait_unit" >/dev/null 2>&1 || die "$wait_unit does not exist; it makes time-sync.target wait for a real clock"

# Changes.

# caddy-api.service of the official Caddy package runs `caddy run --environ --resume`: it loads the last
# autosaved config (an old live rule, for example), not the Caddyfile (rule 2). Stop it and mask it first.
caddy_api=$(systemctl show -p LoadState --value caddy-api.service)
if [[ $caddy_api == loaded ]]; then
	systemctl disable --now caddy-api.service
fi
if [[ $caddy_api != not-found ]]; then
	systemctl mask --now caddy-api.service ||
		die "cannot mask caddy-api.service; remove its unit file from /etc/systemd/system and run this script again"
fi

install -m 0755 "$binary" /usr/local/bin/sparkpass

missing_rules=false
if [[ -f $rules_source ]]; then
	install_rules
elif [[ ! -x $rules ]]; then
	missing_rules=true
fi

mkdir -p /var/lib/sparkpass /etc/sparkpass
chown root:root /var/lib/sparkpass /etc/sparkpass
chmod 0700 /var/lib/sparkpass
chmod 0755 /etc/sparkpass

# Only when missing: an existing token file can hold a live rule, and sparkpass writes it in place and
# never creates it. Its group lets Caddy read it.
token=/etc/sparkpass/token.caddy
if [[ ! -e $token ]]; then
	printf '# sparkpass: deny-all\nrespond 401\n' >"$token"
fi
chown root:caddy "$token"
chmod 0640 "$token"

# <template> <target> <mode> <group>: copy only when missing, and set the owner and the mode always.
install_once() {
	[[ -e $2 ]] || install -m "$3" "$1" "$2"
	chown "root:$4" "$2"
	chmod "$3" "$2"
}
install_once "$repo/etc/config.example" /etc/sparkpass/config 0600 root
install_once "$repo/etc/caddy.env.example" /etc/sparkpass/caddy.env 0640 caddy

# One backup: the last installed file that differs from gateway/Caddyfile (a repair in place, or the
# file of the caddy package).
caddyfile=/etc/caddy/Caddyfile
mkdir -p /etc/caddy
if [[ -f $caddyfile ]] && ! cmp -s "$repo/gateway/Caddyfile" "$caddyfile"; then
	cp -p "$caddyfile" "$caddyfile.before-sparkpass"
	echo "kept the old $caddyfile as $caddyfile.before-sparkpass"
fi
install -m 0644 "$repo/gateway/Caddyfile" "$caddyfile"

mkdir -p "$units/caddy.service.d"
install -m 0644 "$repo/systemd/caddy-sparkpass.conf" "$units/caddy.service.d/sparkpass.conf"
install -m 0644 "$repo/systemd/pass-reconcile.service" "$repo/systemd/pass-reconcile.timer" "$units/"
if [[ $wait_unit == chrony-wait.service ]]; then
	mkdir -p "$units/chrony-wait.service.d"
	cat >"$units/chrony-wait.service.d/sparkpass.conf" <<'EOF'
# Installed by sparkpass install.sh. chrony-wait.service of the Ubuntu chrony package stops its wait
# after 180 s (TimeoutStartSec=180), and time-sync.target is then reached with a clock that is not
# synchronized. pass-reconcile.service starts after time-sync.target and compares lease end times with
# the clock, so the wait has no limit: with no network at boot, the gateway stays closed. Side effect:
# multi-user.target waits for chrony-wait.service, so with no network the boot does not reach it until the
# clock syncs (ssh and getty do not wait). Check: systemctl show -p After multi-user.target
[Service]
TimeoutStartSec=infinity
EOF
fi
systemctl daemon-reload

# Another drop-in can override this one, so check the result before any unit is enabled. Rule 2: the
# exact Caddyfile command, never --resume. A stop must end within the 10 s limit of each sparkpass
# command. On a failed check, no unit starts Caddy: reconcile is disabled and Caddy is stopped.
refuse_caddy_unit() {
	systemctl disable --now pass-reconcile.timer pass-reconcile.service || true
	# Stopped and disabled at boot: only reconcile starts Caddy, and this unit failed its check.
	systemctl disable --now caddy.service || true
	die "$* Look for another drop-in: systemctl cat caddy.service"
}
exec_start=$(systemctl show -p ExecStart --value caddy.service) || true
if [[ $exec_start != *"argv[]=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile ;"* || $exec_start == *--resume* ]]; then
	refuse_caddy_unit "caddy.service does not start with exactly '/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile' after the drop-in: $exec_start."
fi
stop_timeout=$(systemctl show -p TimeoutStopUSec --value caddy.service) || true
[[ $stop_timeout == 5s ]] || refuse_caddy_unit "caddy.service has TimeoutStopSec=$stop_timeout after the drop-in, expected 5s."

# Only reconcile starts Caddy. No lease is active (checked above), so the stop affects no guest, and the
# next reconcile starts Caddy with the new files and proves that it refuses a wrong key.
systemctl disable caddy.service
systemctl stop caddy.service
systemctl enable pass-reconcile.service pass-reconcile.timer "$wait_unit"

warn_on_automatic_updates

# The last value of the key $1 in the KEY=VALUE lines on stdin, with no spaces around it.
value_of() {
	sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" | tail -n 1 | sed 's/[[:space:]]*$//'
}
# sparkpass ends a value at "#"; systemd (EnvironmentFile=) keeps a "#" in the value.
check_address=$(sed 's/#.*//' /etc/sparkpass/config | value_of GATEWAY_CHECK_ADDRESS)
model_port=$(sed 's/#.*//' /etc/sparkpass/config | value_of MODEL_PORT)
caddy_port=$(value_of SPARKPASS_MODEL_PORT </etc/sparkpass/caddy.env)
# Loopback only (read_settings in src/config.rs decides; this test knows the usual forms).
if ! [[ $check_address =~ ^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ || $check_address == ::1 ]]; then
	warn "GATEWAY_CHECK_ADDRESS in /etc/sparkpass/config is \"$check_address\", and it must be a loopback
address of THIS host, for example 127.0.0.1 (never the other Spark). Until it is one, sparkpass
reconcile keeps Caddy stopped and sparkpass grant refuses (see $repo/etc/config.example)."
fi
if [[ -n $model_port && $caddy_port != "$model_port" ]] || [[ -n $caddy_port && ! $caddy_port =~ ^[0-9]+$ ]]; then
	warn "SPARKPASS_MODEL_PORT in /etc/sparkpass/caddy.env is \"$caddy_port\", and MODEL_PORT in
/etc/sparkpass/config is \"$model_port\". Give both the same port number. With an empty
SPARKPASS_MODEL_PORT, Caddy proxies to 127.0.0.1:80, not to the model server."
fi
# SPARKPASS_BIND is for tests/gateway.sh only. An empty value makes Caddy 2.6.2 listen on all addresses.
if grep -qE '^[[:space:]]*SPARKPASS_BIND[[:space:]]*=' /etc/sparkpass/caddy.env; then
	warn "/etc/sparkpass/caddy.env sets SPARKPASS_BIND. Remove that line: on the unit, Caddy listens on
127.0.0.1 only (tailscaled forwards the TCP of Tailscale Funnel there), and an empty value makes
Caddy 2.6.2 listen on all addresses. Only tests/gateway.sh sets it."
fi
if [[ $missing_rules == true ]]; then
	warn "$rules does not exist, and the repository has no firewall/rules.sh (milestone 1 writes it).
Until it exists, sparkpass grant refuses and sparkpass reconcile keeps Caddy stopped.
Add firewall/rules.sh, then run this script again."
fi
# The inbound route is Tailscale Funnel. Warnings only: the owner sets it up after this script (step 1 below).
if ! command -v tailscale >/dev/null; then
	warn "tailscale is not installed. The inbound route is Tailscale Funnel: see step 1 below."
fi
cert_uid=
if [[ -r /etc/default/tailscaled ]]; then
	cert_uid=$(value_of TS_PERMIT_CERT_UID </etc/default/tailscaled | tr -d "\"'")
fi
if [[ $cert_uid != caddy ]]; then
	warn "/etc/default/tailscaled has no TS_PERMIT_CERT_UID=caddy. Without it, tailscaled gives Caddy
no certificate for the ts.net name, and each TLS handshake fails. See step 1 below."
fi

cat <<EOF
sparkpass is installed: /usr/local/bin/sparkpass, $caddyfile, the caddy.service drop-in,
pass-reconcile.service and pass-reconcile.timer (enabled), $wait_unit (enabled).
Caddy is stopped and disabled at boot: only 'sparkpass reconcile' starts it.

Next steps, as root. The inbound route is Tailscale Funnel with raw TCP passthrough: TLS ends at Caddy
(docs/designs/guest-pass-mvp.md, "The gateway"). <name> is the ts.net name of this unit, for example
spark.tail1234.ts.net.
  1. Tailscale on this unit:
       install Tailscale (https://tailscale.com/download/linux), then: tailscale up
       In the admin console: MagicDNS and HTTPS certificates on, and the funnel node attribute in the
       tailnet policy ('tailscale funnel' prints the link when it is missing).
       Add the line TS_PERMIT_CERT_UID=caddy to /etc/default/tailscaled (Caddy gets the certificate of
       <name> from tailscaled), then: systemctl restart tailscaled
       tailscale set --accept-dns=false
         (this unit then resolves <name> through public DNS, to a relay of Funnel, so that the self-check
         of grant and tests/expiry.sh --via-public take the public route; MagicDNS gives the tailnet
         address of this unit, where Caddy does not listen)
       tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443
       tailscale cert --cert-file - <name> >/dev/null
         (tailscaled gets the certificate before the first start of Caddy, so that the first check of
         reconcile does not wait for it; do it again after the unit was off for a long time)
  2. Fill /etc/sparkpass/config: PUBLIC_URL=https://<name>, MODEL_PORT, GATEWAY_CHECK_ADDRESS=127.0.0.1
     (a loopback address), and the optional NOTIFY_URL.
  3. Fill /etc/sparkpass/caddy.env: SPARKPASS_SITE=<name> and SPARKPASS_MODEL_PORT (the same value as
     MODEL_PORT).
  4. If /var/lib/sparkpass/gateway-open exists, a check proved that the gateway is open. While it
     exists, reconcile keeps Caddy stopped and grant refuses. Repair gateway/Caddyfile in the
     repository, run this script again, then remove /var/lib/sparkpass/gateway-open.
  5. Start the gateway: sparkpass reconcile. Then 'sparkpass list' shows "no lease", and
     'systemctl is-active caddy' shows "active".
  6. From a network outside the tailnet (for example a phone with no Tailscale):
       curl -sS -o /dev/null -w '%{http_code}\n' https://<name>/v1/models
     gives 401. Then run tests/expiry.sh (TODOS.md, "Prove the gateway step on the units").
EOF
