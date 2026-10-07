#!/usr/bin/env bash
# Tests gateway/Caddyfile with a real Caddy (the official Docker image) and tests/stub-model.py.
# Runs on a developer machine with docker, python3 and curl; it needs no hardware.
#   tests/gateway.sh                      caddy:2
#   CADDY_IMAGE=caddy:2.6.2 tests/gateway.sh  (the Ubuntu 24.04 package)
# It prints one line for each case and stops at the first mismatch with exit code 1.
# It does not prove the units: the systemd unit, the ACME certificate and the real
# inbound path are for tests/expiry.sh.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
image=${CADDY_IMAGE:-caddy:2}
work=$(mktemp -d)
box=sparkpass-gateway-test-$$
stub_pid=""

cleanup() {
	docker rm -f "$box" >/dev/null 2>&1 || true
	if [[ -n $stub_pid ]]; then
		kill "$stub_pid" 2>/dev/null || true
		wait "$stub_pid" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

fail() {
	echo "FAIL $*"
	exit 1
}

# The token file formats. They must stay the same as `rule` in src/gateway.rs.
deny_all() { printf '# sparkpass: deny-all\nrespond 401\n'; }
lease_rule() { # <name> <token>
	printf '# sparkpass: lease %s\n@sparkpass_pass header Authorization "Bearer %s"\nvars @sparkpass_pass sparkpass_pass yes\n' "$1" "$2"
}

# Writes the token file in place and loads it, as grant does with `systemctl reload caddy`.
# No bind mount: Docker Desktop can keep the old size of a changed file, and Caddy then reads a cut file.
load() { # <token file text>
	printf '%s' "$1" | docker exec -i "$box" sh -c 'cat >/etc/sparkpass/token.caddy'
	docker exec "$box" caddy reload --config /etc/caddy/Caddyfile --force >"$work/reload.log" 2>&1 ||
		fail "caddy reload: $(cat "$work/reload.log")"
}

status() { # <method> <path> [curl arguments]
	local method=$1 path=$2
	shift 2
	if [[ $method == POST ]]; then set -- "$@" -H 'Content-Type: application/json' -d '{}'; fi
	# The site name and port in the URL, as a real client sends them (Caddy 2.6.2 maps the access log by
	# them), and --connect-to to the published port of the container.
	curl -q --noproxy '*' -sk --connect-to "localhost:8443:127.0.0.1:$published" -o "$work/body" -m 10 -w '%{http_code}' \
		-X "$method" "$@" "https://localhost:8443$path" || true
}

expect() { # <want> <method> <path> [curl arguments]
	local want=$1 got
	got=$(status "${@:2}")
	[[ $got == "$want" ]] || fail "$case: $2 $3 ${*:4} got $got, want $want"
}

# Each path of the model server that a guest can try, with the method that it takes.
paths=("GET /v1/models" "POST /v1/chat/completions" "POST /v1/completions" "POST /invocations"
	"POST /tokenize" "GET /metrics" "GET /" "GET /other")

on_each_path() { # <want> [curl arguments]
	local p
	for p in "${paths[@]}"; do expect "$1" "${p% *}" "${p#* }" "${@:2}"; done
}

token=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
wrong=$(printf '0%.0s' {1..64}) # the wrong key of the grant and reconcile checks
key="Authorization: Bearer $token"
refused_cases() { # on each path: no header, a wrong key, an empty bearer, lower case, a suffix
	on_each_path 401
	on_each_path 401 -H "Authorization: Bearer $wrong"
	on_each_path 401 -H "Authorization: Bearer"
	on_each_path 401 -H "Authorization: bearer $token"
	on_each_path 401 -H "Authorization: Bearer ${token}0"
}

python3 "$repo/tests/stub-model.py" --bind 0.0.0.0 --port 0 >"$work/stub.out" 2>&1 &
stub_pid=$!
mkdir "$work/etc"
deny_all >"$work/etc/token.caddy"
for _ in {1..50}; do
	stub_port=$(sed -n 's|^stub-model: http://.*:\([0-9]*\)/v1$|\1|p' "$work/stub.out")
	[[ -n $stub_port ]] && break
	sleep 0.1
done
[[ -n $stub_port ]] || fail "the stub did not start: $(cat "$work/stub.out")"

docker create --name "$box" --add-host host.docker.internal:host-gateway -p 127.0.0.1::8443 \
	-e SPARKPASS_SITE=localhost:8443 -e SPARKPASS_MODEL_HOST=host.docker.internal \
	-e SPARKPASS_MODEL_PORT="$stub_port" \
	"$image" caddy run --environ --config /etc/caddy/Caddyfile >/dev/null
docker cp -q "$repo/gateway/Caddyfile" "$box:/etc/caddy/Caddyfile"
docker cp -q "$work/etc" "$box:/etc/sparkpass"
docker start "$box" >/dev/null
published=$(docker port "$box" 8443/tcp | sed -n '1s/.*://p')
for _ in {1..100}; do
	[[ $(status GET /) == 401 ]] && break
	sleep 0.2
done
[[ $(status GET /) == 401 ]] || fail "start: no 401 from Caddy: $(docker logs "$box" 2>&1 | tail -5)"
echo "ok   start: $(docker exec "$box" caddy version | cut -d' ' -f1), stub on port $stub_port"

case="config"
config=$(docker exec "$box" caddy adapt --config /etc/caddy/Caddyfile 2>/dev/null)
for want in '"grace_period":2000000000' '"response_header_timeout":300000000000' '"max_size":4000000'; do
	[[ $config == *"$want"* ]] || fail "$case: the adapted config has no $want"
done
echo "ok   $case: grace period 2 s, response header timeout 300 s, body limit 4 MB"

case="deny-all"
on_each_path 401
on_each_path 401 -H "Authorization: Bearer"
on_each_path 401 -H "Authorization: Bearer $wrong"
on_each_path 401 -H "$key"
echo "ok   $case: 401 on each path with no header, an empty bearer, a wrong key, a key of no lease"

case="active rule"
# The exact text of gateway::rule, with its final newline (a command substitution would drop it).
rule=$(lease_rule bob "$token")$'\n'
load "$rule"
expect 200 GET /v1/models -H "$key"
expect 200 POST /v1/chat/completions -H "$key"
expect 200 POST /v1/completions -H "$key"
for p in "POST /invocations" "POST /tokenize" "GET /metrics" "GET /" "GET /other"; do
	expect 404 "${p% *}" "${p#* }" -H "$key"
	# Only the gateway's own 404 has no body: a 404 of the model server means the path reached it.
	[[ ! -s $work/body ]] || fail "$case: $p reached the model server: $(cat "$work/body")"
done
# Raw paths with a dot or empty segment (curl --path-as-is): the proxy would send them as they are, so
# the gateway refuses them with its own 400 (no body) before the proxy. With no key, 401 comes first.
for p in /metrics/../v1/models /metrics/%2e%2e/v1/models /tokenize/../v1/models /x/..%2f..%2fv1/models \
	/v1/../metrics /v1/./models /v1//models; do
	expect 400 GET "$p" -H "$key" --path-as-is
	[[ ! -s $work/body ]] || fail "$case: $p reached the model server: $(cat "$work/body")"
	expect 401 GET "$p" --path-as-is
done
# A request with a query string, for the access log case below (the stub answers it with its own 404).
status GET "/v1/models?q=sparkpass-query-text" -H "$key" >/dev/null
refused_cases
echo "ok   $case: the key gets 200 on /v1/*, 404 elsewhere, 400 for a dot or empty segment; each other header gets 401 on each path"

case="body limit"
head -c 5000000 /dev/zero >"$work/big"
got=$(curl -q --noproxy '*' -sk --connect-to "localhost:8443:127.0.0.1:$published" -o /dev/null -m 30 -w '%{http_code}' \
	-H "$key" -H 'Content-Type: application/json' --data-binary @"$work/big" https://localhost:8443/v1/chat/completions || true)
[[ $got == 413 ]] || fail "$case: a 5 MB body got $got, want 413"
echo "ok   $case: a 5 MB body with the key gets 413"

# A power cut in the in-place write of the token file can leave an empty file or any first part of the rule.
# Such a file matters after a restart (revoke's try-restart, or a boot), never after grant's reload, which
# writes a complete rule. Pass: Caddy loads the file and refuses each request, or Caddy refuses the file, so
# that a restart cannot start the gateway (Caddy 2.6.2 refuses an empty import; Caddy 2.11 loads it).
refused_file() { # <token file text>: 401 on each path, or a config that Caddy cannot load
	printf '%s' "$1" | docker exec -i "$box" sh -c 'cat >/etc/sparkpass/token.caddy'
	if docker exec "$box" caddy reload --config /etc/caddy/Caddyfile --force >"$work/reload.log" 2>&1; then
		on_each_path 401 -H "$key"
		on_each_path 401
		echo "ok   $case: 401 on each path, also with the key"
	else
		docker exec "$box" caddy adapt --config /etc/caddy/Caddyfile >/dev/null 2>&1 &&
			fail "$case: the reload failed, but the config adapts: $(cat "$work/reload.log")"
		echo "ok   $case: Caddy refuses the file, so a restart cannot start the gateway"
	fi
}

case="empty token file"
refused_file ""
cuts=("line 1" "${rule%%@*}" "lines 1 and 2" "${rule%%vars*}"
	"inside the key" "${rule%%Bearer*}Bearer ${token:0:32}" "inside the last word" "${rule%??}")
for ((i = 0; i < ${#cuts[@]}; i += 2)); do
	case="cut rule, ${cuts[i]}"
	refused_file "${cuts[i + 1]}"
done

case="stub stopped"
load "$rule"
expect 200 GET /v1/models -H "$key"
kill "$stub_pid"
wait "$stub_pid" 2>/dev/null || true
stub_pid=""
expect 503 GET /v1/models -H "$key"
echo "ok   $case: the key gets 503 on /v1/models"

case="access log"
docker logs "$box" >"$work/caddy.log" 2>&1
access=$(grep -F '"logger":"http.log.access' "$work/caddy.log" || true)
[[ -n $access ]] || fail "$case: no access log line"
grep -qF '"uri":"/v1/models"' <<<"$access" || fail "$case: no path in the access log"
grep -qF '"status":401' <<<"$access" || fail "$case: no status in the access log"
# Only time, client IP address, method, path, status and size, plus the log metadata.
python3 -c 'import json, sys
keep = {"level", "ts", "logger", "msg", "remote_ip", "client_ip", "method", "uri", "status", "size"}
for line in sys.stdin:
    d = json.loads(line)
    d.update(d.pop("request"))
    if set(d) - keep:
        sys.exit("FAIL access log: a line has more fields: " + line)' <<<"$access" || exit 1
if line=$(grep -m1 -iE "bearer|$token" "$work/caddy.log"); then fail "$case: the log has a key: $line"; fi
if line=$(grep -m1 -F "sparkpass-query-text" <<<"$access"); then fail "$case: the log has a query string: $line"; fi
echo "ok   $case: $(wc -l <<<"$access" | tr -d ' ') lines, no headers, no query, no Bearer, no key"
echo "PASS"
