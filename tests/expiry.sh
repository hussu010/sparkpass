#!/usr/bin/env bash
# Forced-end, deny-all and re-grant test of the guest pass, build phase 1 (API only).
# Design: docs/designs/guest-pass-mvp.md, "Success Criteria" and "Next Steps" 6; TODOS.md, item "Prove
# the gateway step on the units", and completed item "Fail closed when the gateway does not enforce the
# token file", acceptance rule 5.
# The owner runs it by hand as root on the head unit, after install.sh. It uses the real
# sparkpass binary, systemd, Caddy and curl, so it does not run in CI.
set -Eeuo pipefail

BIN=/usr/local/bin/sparkpass
CONFIG=/etc/sparkpass/config
TOKEN_FILE=/etc/sparkpass/token.caddy
FIREWALL=/usr/local/lib/sparkpass/rules.sh
STATE=/var/lib/sparkpass
MARKER=$STATE/gateway-open
LOCK=$STATE/lock
NAME=expiry-test
BOUND=15     # seconds after the end time: the stream ends and the key gets 401
LOCK_HOLD=40 # seconds: in step 3 a different process holds the lock across the end time (eng review D8)
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Each "every path" check. The first three are the routes of the pass. On each other route the key gets
# the 404 of the gateway (the route allowlist of gateway/Caddyfile): other routes of the model server can
# change state that the next guest sees.
EVERY=("GET /v1/models" "POST /v1/chat/completions" "POST /v1/completions"
  "GET /v1/chat/completions" "POST /v1/models" "POST /v1/embeddings" "POST /v1/responses"
  "POST /v1/load_lora_adapter" "POST /invocations" "POST /tokenize" "GET /metrics" "GET /health")
DENIED=("${EVERY[@]:3}")

usage() {
  cat <<'EOF'
Usage: sudo tests/expiry.sh [--stub] [--ttl <n>s|<n>m] [--via-public] [--skip-reboot-note]

Forced-end test of the sparkpass guest pass, build phase 1 (API only). Run it as root on
the head unit after install.sh, with no lease, no end timer and no guest traffic. It uses
the lease name "expiry-test", and it revokes that lease after each failure.

Steps:
  1  sparkpass reconcile. With the deny-all rule, each request gets 401.
  2  grant: the key gets 200 on GET /v1/models, and on each route outside the pass the
     404 of the gateway (a 404 with no body: the model server sends a body); no header,
     an empty bearer value, a wrong key, and the key with one more character get 401.
  3  a stream with the key runs past the end time, and a different process holds the
     sparkpass lock from 5 s before the end time for 40 s (eng review D8). Not later than
     15 s after the end time, the stream ends and the key gets 401; within 30 s after the
     lock hold, sparkpass list shows no lease and the end timer is gone. The model server
     shows zero running requests.
  4  grant and an early revoke: the key gets 401, and the end timer is gone.
  5  a new grant of the same name, with the TTL of step 3: the new key works, and the
     earlier keys get 401. The new lease ends at its own end time: the new key gets 401
     on every path within 15 s, and within 30 s no lease and no end timer stay.
  6  a summary.
"Every path": the routes of the pass (GET /v1/models, POST /v1/chat/completions,
POST /v1/completions), then GET /v1/chat/completions, POST /v1/models,
POST /v1/embeddings, POST /v1/responses, POST /v1/load_lora_adapter,
POST /invocations, POST /tokenize, GET /metrics, GET /health.

Options:
  --stub              run against tests/stub-model.py on MODEL_PORT (stop the real model
                      first). Step 4 also checks 503 when the stub is stopped, and 504 (not
                      a hang) when the stub is frozen. The frozen check waits for the 300 s
                      header timeout of the gateway: about 5 minutes.
  --ttl <n>s|<n>m     TTL of the leases in steps 3 and 5 (default 5m, at least 60s).
  --via-public        send each request through PUBLIC_URL: public DNS and a relay of
                      Tailscale Funnel (the inbound-path run of the Success Criteria). It
                      needs 'tailscale set --accept-dns=false' on this unit, so that the
                      ts.net name resolves to a relay and not to the tailnet address of
                      this unit. Without this option, each request goes to
                      GATEWAY_CHECK_ADDRESS (loopback) with curl --connect-to.
  --skip-reboot-note  do not print the reboot procedures at the end.
  -h, --help          print this text and the manual procedures.

Environment:
  EXPIRY_MAX_TOKENS   max_tokens of the stream to the real model (default 32768). The
                      stream also sends "ignore_eos": true (vLLM, SGLang). The stream must
                      run past the end time: if the context limit refuses the request,
                      set a lower value.

Settings, from /etc/sparkpass/config: PUBLIC_URL, MODEL_PORT, GATEWAY_CHECK_ADDRESS.
Exit codes: 0 pass, 1 failure, 2 usage error. A failure with a proven open gateway (an
answer other than 401 where 401 is the rule) writes /var/lib/sparkpass/gateway-open and
stops Caddy.

EOF
  manual all
}

# manual all|certificate: the procedures that this script does not automate.
manual() {
  local check="curl -q --noproxy '*' -sS -o /dev/null -w '%{http_code}\\n' --connect-to ::<GATEWAY_CHECK_ADDRESS>: -H 'Authorization: Bearer <key>' <PUBLIC_URL>/v1/models"
  if [[ $1 == all ]]; then
    cat <<EOF
Manual: reboot across the end time
  1. sparkpass grant $NAME --ttl 5m. Keep the API key.
  2. Before the end time: poweroff. Start the unit again after the end time.
  3. systemctl is-enabled caddy prints "disabled".
  4. After the boot run of pass-reconcile.service: the old key gets 401, sparkpass list
     prints "no lease", and systemctl list-timers --all 'sparkpass-end-*' lists no timer.
Manual: reboot inside an active lease
  1. sparkpass grant $NAME --ttl 30m. Keep the API key.
  2. reboot. After the boot run of pass-reconcile.service: systemctl list-timers
     'sparkpass-end-*' lists the end timer again, and the key gets 200 (503 until the
     model runs).
  3. sparkpass revoke $NAME. The key gets 401.
  Build phase 2 adds: the home data stays, and SSH connects with no host key warning.

EOF
  fi
  cat <<EOF
Manual: the certificate from tailscaled and the route of Tailscale Funnel (step 1 of the
procedure that install.sh prints). Also after the unit was off for a long time. <name> is
the host of PUBLIC_URL:
  1. grep TS_PERMIT_CERT_UID /etc/default/tailscaled prints TS_PERMIT_CERT_UID=caddy.
  2. tailscale cert --cert-file - <name> >/dev/null succeeds: tailscaled has the certificate.
  3. After sparkpass reconcile, journalctl -u caddy shows no TLS handshake error for <name>.
     This command shows <name> and a public CA (Let's Encrypt); Caddy 2.6.2 logs no line for
     a certificate from tailscaled:
       openssl s_client -connect 127.0.0.1:443 -servername <name> </dev/null | openssl x509 -noout -subject -issuer
  4. tailscale funnel status shows TCP 443 of this node, forwarded to 127.0.0.1:443.
  5. getent hosts <name> gives a public address (a relay of Funnel), not a 100.x tailnet
     address: 'tailscale set --accept-dns=false' is on, so --via-public takes the public route.
  6. tests/expiry.sh, then tests/expiry.sh --via-public. Each check uses TLS with the name
     of PUBLIC_URL and a normal certificate check, so a pass also proves the certificate.
Check a key with the command below. Put an IPv6 GATEWAY_CHECK_ADDRESS in brackets, for
example --connect-to ::[::1]:
  $check
Manual: no network at boot (one time, design task T13)
  1. With no lease, disconnect the network of the head unit, and reboot.
  2. timedatectl prints "System clock synchronized: no", systemctl is-active caddy prints
     "inactive", and curl -q -sS https://127.0.0.1/ fails with "Connection refused".
  3. Connect the network. After the clock sync and the reconcile run, caddy is active,
     and tests/expiry.sh passes.
EOF
}

usage_error() { printf 'expiry.sh: %s (see --help)\n' "$1" >&2; exit 2; }
die() { printf 'expiry.sh: %s\n' "$*" >&2; exit 1; } # before the test changes the host

STUB=no VIA_PUBLIC=no REBOOT_NOTE=yes TTL=5m
while (($#)); do
  case $1 in
    --stub) STUB=yes ;;
    --ttl)
      (($# >= 2)) || usage_error "--ttl needs a value"
      TTL=$2
      shift
      ;;
    --via-public) VIA_PUBLIC=yes ;;
    --skip-reboot-note) REBOOT_NOTE=no ;;
    -h | --help) usage; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
[[ $TTL =~ ^([0-9]{1,6})([sm])$ ]] || usage_error "--ttl must be <n>s or <n>m, for example 5m"
TTL_S=$((10#${BASH_REMATCH[1]}))
if [[ ${BASH_REMATCH[2]} == m ]]; then TTL_S=$((TTL_S * 60)); fi
((TTL_S >= 60)) || usage_error "--ttl must be at least 60s"
MAX_TOKENS=${EXPIRY_MAX_TOKENS:-32768}
[[ $MAX_TOKENS =~ ^[1-9][0-9]{0,6}$ ]] || usage_error "EXPIRY_MAX_TOKENS must be a positive number"

end_timers() { systemctl list-timers --all --no-legend 'sparkpass-end-*' 2>/dev/null || true; }

# Refuse to start: nothing on the host changes before these checks pass.
((EUID == 0)) || die "run it as root: sudo tests/expiry.sh"
[[ -x $BIN ]] || die "$BIN is missing: run install.sh first"
[[ -x $FIREWALL ]] || die "$FIREWALL is not executable: milestone 1 writes firewall/rules.sh, and install.sh copies it"
command -v flock >/dev/null || die "flock (util-linux) is missing: step 3 holds the lock with it"
[[ ! -e $MARKER ]] || die "$MARKER exists: the gateway answered a wrong key. Repair the Caddyfile, remove the file, then run this test"
lease_list=$("$BIN" list) || die "sparkpass list failed"
[[ $lease_list == "no lease" ]] || die "a lease exists, so the test does not start: $lease_list"
timers=$(end_timers)
[[ -z $timers ]] || die "an end timer exists, so the test does not start: $timers"
[[ -r $CONFIG ]] || die "cannot read $CONFIG"
if [[ $STUB == yes ]]; then
  command -v python3 >/dev/null || die "--stub needs python3"
  [[ -f $HERE/stub-model.py ]] || die "$HERE/stub-model.py is missing"
fi

# setting KEY: the value from the settings file, parsed as read_settings parses it (the file is not sourced):
# "#" starts a comment, the last KEY=VALUE line wins, and the key and the value are trimmed.
setting() { sed -n "s/#.*//; s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONFIG" | tail -n 1 | sed 's/[[:space:]]*$//'; }
PUBLIC_URL=$(setting PUBLIC_URL)
while [[ $PUBLIC_URL == */ ]]; do PUBLIC_URL=${PUBLIC_URL%/}; done
MODEL_PORT=$(setting MODEL_PORT)
ADDRESS=$(setting GATEWAY_CHECK_ADDRESS)
[[ $PUBLIC_URL == https://?* ]] || die "$CONFIG: PUBLIC_URL must start with https://"
if ! [[ $MODEL_PORT =~ ^[0-9]{1,5}$ ]] || ((10#$MODEL_PORT < 1 || 10#$MODEL_PORT > 65535)); then
  die "$CONFIG: MODEL_PORT must be a port number"
fi
MODEL_PORT=$((10#$MODEL_PORT))
[[ -n $ADDRESS ]] || die "$CONFIG: GATEWAY_CHECK_ADDRESS is missing"
if [[ $ADDRESS == *:* ]]; then ADDRESS="[$ADDRESS]"; fi # IPv6
# Without --via-public, each connection goes to GATEWAY_CHECK_ADDRESS on the port of PUBLIC_URL, as
# the reconcile check does. TLS still checks the name of PUBLIC_URL.
VIA=(--connect-to "::$ADDRESS:")
ROUTE="--connect-to $ADDRESS"
if [[ $VIA_PUBLIC == yes ]]; then
  VIA=()
  ROUTE="the public name (public DNS and Tailscale Funnel)"
fi
WRONG=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
CHUNKS=$(((TTL_S + 300) * 2)) # stub stream at 0.5 s per chunk: it runs 5 minutes past the end time

STEP=start ARMED=no STUB_PID="" STREAM_PID="" BAD="" OPEN="" KEY="" MODEL="" DEADLINE=0 TIMER=""
TMP=$(mktemp -d) # mode 0700: $TMP/auth holds a key

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '\nFAIL in step %s: %s\n' "$STEP" "$*" >&2; exit 1; }

cleanup() {
  local rc=$?
  # PIPE too: a closed output pipe (tee, an SSH drop) must not stop the revoke and the marker below.
  trap '' INT TERM HUP PIPE
  trap - EXIT ERR
  set +e
  # The stream, the lock hold (flock -o: the kill frees the lock), a sleep, the stub (stop_stub waits for it).
  # shellcheck disable=SC2046 # one word for each pid
  kill $(jobs -p) 2>/dev/null
  # A gateway proven open: the marker and the stop come first, because a revoke cannot close it.
  if ((rc != 0)) && [[ -n $OPEN ]]; then close_open_gateway; fi
  if ((rc != 0)) && [[ $ARMED == yes ]]; then
    printf 'expiry.sh: the test failed (exit %s); running: sparkpass revoke %s\n' "$rc" "$NAME" >&2
    "$BIN" revoke "$NAME" || printf 'expiry.sh: the revoke failed too: check sparkpass list\n' >&2
    # After the revoke the last key must get 401 on every path. An HTTP answer other than 401 (not a curl
    # failure, 000) proves an open gateway, also when the failed step was a wait (until_by) and not expect().
    if [[ -z $OPEN && -n $KEY ]] && ! answers 401 "$KEY" "${EVERY[@]}" && [[ $BAD == *=[1-9]* ]]; then
      OPEN="the last key still passed the gateway after the revoke:$BAD"
      close_open_gateway
    fi
  fi
  stop_stub
  rm -rf "$TMP"
  exit "$rc"
}

# A revoke cannot close a gateway that does not enforce the token file. The marker keeps Caddy stopped:
# reconcile does not start it, and grant refuses.
close_open_gateway() {
  if ! printf '%s\n' "$OPEN" >"$MARKER"; then
    if [[ -e $MARKER ]]; then
      printf 'expiry.sh: THE MARKER %s MAY NOT BE COMPLETE: while it exists, each reconcile run stops the gateway\n' "$MARKER" >&2
    else
      printf 'expiry.sh: THE MARKER %s WAS NOT WRITTEN: the next reconcile can start the gateway again\n' "$MARKER" >&2
    fi
  fi
  if systemctl stop caddy; then
    printf 'expiry.sh: the gateway is open, and Caddy is stopped. Repair gateway/Caddyfile, run install.sh, then remove %s.\n' "$MARKER" >&2
  else
    printf 'expiry.sh: the gateway is open, and THE STOP OF CADDY FAILED: stop it by hand, then repair gateway/Caddyfile and remove %s.\n' "$MARKER" >&2
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
# The command text, not its expansion: no key gets into this message.
trap 'printf "expiry.sh: line %s: the command \"%s\" failed\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

# status METHOD PATH [CURL_ARG...]: the HTTP status of one request through the gateway; 000 when curl fails.
# The body goes to $TMP/body. -q first: root's ~/.curlrc cannot add --insecure, a proxy, or -L.
# --noproxy: a proxy would skip --connect-to.
status() {
  local method=$1 path=$2 body=()
  shift 2
  if [[ $method == POST ]]; then body=(-H 'Content-Type: application/json' -d '{}'); fi
  rm -f "$TMP/body"
  curl -q --noproxy '*' -sS -o "$TMP/body" -w '%{http_code}' -m 10 "${VIA[@]}" "${body[@]}" "$@" "$PUBLIC_URL$path" || true
}

# answers WANT WHO ROUTE...: true when each route answers WANT to WHO: "none" (no Authorization header),
# "empty" (an empty bearer value), or a bearer key. BAD gets the other answers, as "route=code".
# A 404 with a body is "404+body": only the 404 of the gateway has no body (the stub and vLLM send JSON).
answers() {
  local want=$1 who=$2 route code auth=()
  shift 2
  case $who in
    none) auth=() ;;
    empty) auth=(-H 'Authorization: Bearer ') ;;
    *) auth=(-H "Authorization: Bearer $who") ;;
  esac
  BAD=""
  for route in "$@"; do
    code=$(status "${route%% *}" "${route#* }" "${auth[@]}")
    if [[ $code == 404 && -s $TMP/body ]]; then code=404+body; fi
    [[ $code == "$want" ]] || BAD+=" $route=$code"
  done
  [[ -z $BAD ]]
}

hint() {
  if [[ $BAD == *=000* ]]; then
    printf '\n  000: curl failed (see its error above). For a TLS error: see "the certificate from tailscaled" in --help.'
  fi
  if [[ $BAD == *=404+body* ]]; then
    printf '\n  404+body: the request passed the gateway, and the model server answered it.'
  fi
}

# expect WANT WHO LABEL ROUTE...: answers, or fail. LABEL names WHO; the message never holds a key.
expect() {
  local want=$1 who=$2 label=$3
  shift 3
  answers "$want" "$who" "$@" && return 0
  # An HTTP answer other than 401 (000 is a curl failure, not an answer) proves the gateway open.
  if [[ $want == 401 && $BAD == *=[1-9][0-9][0-9]* ]]; then
    OPEN="tests/expiry.sh step $STEP, $(date -u '+%F %T UTC'): the gateway answered$BAD to $label through $ROUTE, and each answer must be 401: the gateway does not enforce the token file"
  fi
  fail "$label: each answer must be $want, but:$BAD$(hint)"
}

# refused [KEY]: callers with no valid key get 401 on every path. With KEY, also KEY with one more character.
refused() {
  expect 401 none "no Authorization header" "${EVERY[@]}"
  expect 401 empty "an empty bearer value" "${EVERY[@]}"
  expect 401 "$WRONG" "a wrong 64-hex key" "${EVERY[@]}"
  if (($#)); then expect 401 "${1}0" "the key with one more character" "${EVERY[@]}"; fi
}

# until_by LIMIT WHAT CMD...: runs CMD each second until it succeeds; fails when the clock passes LIMIT.
until_by() {
  local limit=$1 what=$2
  shift 2
  BAD=""
  until "$@"; do
    (($(date +%s) <= limit)) || fail "$what${BAD:+:$BAD}"
    sleep 1
  done
  (($(date +%s) <= limit)) || fail "$what (it passed only at $(($(date +%s) - limit)) s after the limit)"
}

# wait_until EPOCH: a sleep in the background, so that the INT and TERM trap runs at once.
wait_until() {
  local seconds
  seconds=$(($1 - $(date +%s)))
  if ((seconds > 0)); then sleep "$seconds" & wait $!; fi
}

caddy_active() { systemctl is-active --quiet caddy; }
wait_caddy() { until_by $(($(date +%s) + 30)) "caddy is not active" caddy_active; }
no_lease() { [[ $("$BIN" list 2>&1) == "no lease" ]]; }
# The end timer of the last grant is not active, and no other end timer exists.
timer_gone() { ! systemctl is-active --quiet "$TIMER" && [[ -z $(end_timers) ]]; }
lock_held() { ! flock -n "$LOCK" true; }
stream_open() { kill -0 "$STREAM_PID" 2>/dev/null; }
stream_closed() { ! stream_open; }
stream_result() { cat "$TMP/stream" "$TMP/stream.err" 2>/dev/null | tr '\n' ' ' || true; }

# model_get PATH: a GET straight to the model server on 127.0.0.1, not through the gateway.
model_get() { curl -q --noproxy '*' -sS -m 10 "http://127.0.0.1:$MODEL_PORT$1" 2>/dev/null || true; }
# running: the requests that the model server runs now, or "" when it does not say.
running() {
  if [[ $STUB == yes ]]; then
    model_get /stub/status | sed -n 's/.*"running": *\([0-9][0-9]*\).*/\1/p'
  else
    model_get /metrics | awk '/^(vllm:num_requests_running|sglang:num_running_reqs)[{ ]/ {s += $NF; n++} END {if (n) printf "%d\n", s}'
  fi
}
busy() { local n; n=$(running); [[ -z $n ]] || ((n >= 1)); }
idle() { [[ $(running) == 0 ]]; }

start_stub() {
  python3 "$HERE/stub-model.py" --port "$MODEL_PORT" --interval 0.5 --chunks "$CHUNKS" >>"$TMP/stub.log" 2>&1 &
  STUB_PID=$!
  for _ in {1..20}; do
    if [[ -n $(running) ]]; then return 0; fi
    kill -0 "$STUB_PID" 2>/dev/null || fail "the stub did not start. Is the model server on port $MODEL_PORT? $(cat "$TMP/stub.log")"
    sleep 0.5
  done
  fail "the stub does not answer on 127.0.0.1:$MODEL_PORT"
}

stop_stub() {
  [[ -n $STUB_PID ]] || return 0
  kill -CONT "$STUB_PID" 2>/dev/null || true
  kill "$STUB_PID" 2>/dev/null || true
  wait "$STUB_PID" 2>/dev/null || true
  STUB_PID=""
}

# grant TTL: sparkpass grant; sets KEY, MODEL, DEADLINE (epoch seconds) and TIMER from the pass text and
# the lease file.
grant() {
  local ttl=${1%s} out before after end deadline
  wait_caddy # grant refuses while Caddy is down, and the revoke before it restarts Caddy
  before=$(date +%s)
  out=$("$BIN" grant "$NAME" --ttl "$1") || fail "sparkpass grant $NAME --ttl $1 failed"
  after=$(date +%s)
  KEY=$(sed -n 's/^API key: *//p' <<<"$out")
  MODEL=$(sed -n 's/^Model: *//p' <<<"$out")
  end=$(sed -n 's/^End time: *//p' <<<"$out")
  [[ $KEY =~ ^[0-9a-f]{64}$ ]] || fail "the pass has no 64-hex API key"
  grep -qxF "Endpoint: $PUBLIC_URL/v1" <<<"$out" || fail "the pass has no line \"Endpoint: $PUBLIC_URL/v1\""
  [[ -n $MODEL && $MODEL != *[\"\\]* ]] || fail "the pass has no usable model name: \"$MODEL\""
  DEADLINE=$(date -u -d "$end" +%s) || fail "cannot read the end time of the pass: \"$end\""
  # The deadline is one clock read during grant plus the TTL: the lock wait and the checks do not shorten it.
  ((DEADLINE >= before + ttl && DEADLINE <= after + ttl)) || fail "the end time $end is not the time of the grant plus $ttl s"
  ((after - before <= 30)) || fail "the grant took $((after - before)) s, more than 30 s (a reconcile run can hold the lock: run the test again)"
  deadline=$(sed -n 's/.*"deadline": *\([0-9][0-9]*\).*/\1/p' "$STATE/leases/$NAME.json" 2>/dev/null || true)
  [[ $deadline == "$DEADLINE" ]] || fail "the deadline \"$deadline\" in $STATE/leases/$NAME.json is not the end time of the pass ($DEADLINE)"
  TIMER=sparkpass-end-$NAME-$deadline.timer
  systemctl is-active --quiet "$TIMER" || fail "the grant created no active end timer $TIMER"
  say "grant: the end time is $end, the end timer is $TIMER"
}

ARMED=yes
say "sparkpass expiry test, build phase 1 (API only): $PUBLIC_URL through $ROUTE"
say "TTL ${TTL_S}s; the test takes about $(((2 * TTL_S + 150) / 60)) minutes$([[ $STUB == yes ]] && echo ', plus about 6 minutes for the stub checks')"
say "skipped (build phase 2): each SSH, workspace and home-image check"
if [[ $STUB == yes ]]; then
  start_stub
  say "the stub model server runs on 127.0.0.1:$MODEL_PORT (pid $STUB_PID)"
fi

STEP="1 (deny-all)"
"$BIN" reconcile || fail "sparkpass reconcile failed"
wait_caddy
cmp -s "$TOKEN_FILE" <(printf '# sparkpass: deny-all\nrespond 401\n') || fail "$TOKEN_FILE is not the deny-all rule after reconcile"
refused
say "ok 1: with the deny-all rule, each request gets 401 on every path"

STEP="2 (active lease)"
grant "${TTL_S}s"
KEY1=$KEY
expect 200 "$KEY1" "the key" "GET /v1/models"
refused "$KEY1"
expect 404 "$KEY1" "the key, on a route outside the pass" "${DENIED[@]}"
say "ok 2: the key gets 200 on /v1/models and the 404 of the gateway (no body) on each route outside the pass; other callers get 401 on every path"

STEP="3 (forced end, lock held)"
stream_body=$(printf '{"model": "%s", "stream": true, "max_tokens": %s, "ignore_eos": true, "messages": [{"role": "user", "content": "Count from 1 to 100000, one number on each line."}]}' "$MODEL" "$MAX_TOKENS")
# The key goes to curl in a file (curl 7.55 or later), not in its argv: the process list shows the argv
# for the minutes of the stream. printf is a builtin, so no argv holds the key.
printf 'Authorization: Bearer %s\n' "$KEY1" >"$TMP/auth"
# Not -m 10: the stream must run past the end time. The limit only ends a stream that the cut does not end.
curl -q --noproxy '*' -sS -o /dev/null -w '%{http_code} %{size_download}' -m $((TTL_S + 600)) "${VIA[@]}" \
  -H @"$TMP/auth" -H 'Content-Type: application/json' -d "$stream_body" \
  "$PUBLIC_URL/v1/chat/completions" >"$TMP/stream" 2>"$TMP/stream.err" &
STREAM_PID=$!
sleep 2
stream_open || fail "the stream ended at once: $(stream_result)"
until_by $(($(date +%s) + 15)) "the model server runs no request: the stream did not reach it" busy
say "a stream with the key runs; waiting for the end time"
wait_until $((DEADLINE - 5))
# A different command holds the lock at the end time: the close before the lock still ends the stream
# and the key within 15 s, and the rest of the revoke waits for the lock. -o: only flock holds the lock,
# not its sleep, so the kill of flock in cleanup frees the lock.
flock -o "$LOCK" sleep "$LOCK_HOLD" &
lock_at=$(date +%s)
until_by $((lock_at + 3)) "flock does not hold $LOCK" lock_held
(($(date +%s) < DEADLINE)) || fail "the lock hold started after the end time: use a longer --ttl"
lock_end=$((lock_at + LOCK_HOLD - DEADLINE)) # seconds after the end time
say "a different process holds $LOCK until +${lock_end}s"
wait_until $((DEADLINE - 2))
stream_open || fail "the stream ended before the end time ($(stream_result)), so the test proves nothing. With the real model, raise EXPIRY_MAX_TOKENS"
until_by $((DEADLINE + BOUND)) "the stream is still open $BOUND s after the end time" stream_closed
stream_end=$(($(date +%s) - DEADLINE))
stream_rc=0
wait "$STREAM_PID" || stream_rc=$?
STREAM_PID=""
((stream_rc != 0)) || fail "the stream ended on its own (curl exit 0), not by the cut; raise EXPIRY_MAX_TOKENS or use a shorter --ttl"
read -r stream_code stream_size <"$TMP/stream" || true
[[ ${stream_code:-} == 200 && ${stream_size:-0} -gt 0 ]] || fail "the stream got \"${stream_code:-none}\" with ${stream_size:-0} bytes; it must get 200 with data"
until_by $((DEADLINE + BOUND)) "the key does not get 401 on every path $BOUND s after the end time" answers 401 "$KEY1" "${EVERY[@]}"
cut_at=$(($(date +%s) - DEADLINE))
refused
until_by $((DEADLINE + lock_end + 30)) "sparkpass list still shows a lease 30 s after the end of the lock hold" no_lease
until_by $((DEADLINE + lock_end + 30)) "$TIMER or another end timer still exists 30 s after the end of the lock hold (systemctl list-timers --all 'sparkpass-end-*')" timer_gone
gone_at=$(($(date +%s) - DEADLINE))
if [[ -n $(running) ]]; then
  until_by $(($(date +%s) + BOUND)) "the model server still runs a request after the stream closed (design Open Question 4)" idle
  model_note="the model server runs zero requests"
else
  model_note="NOT CHECKED: the model server shows no running-request count on /metrics; check it by hand (design Open Question 4)"
fi
say "ok 3: with the lock held until +${lock_end}s, the stream ended at +${stream_end}s (curl exit $stream_rc), the key got 401 at +${cut_at}s, the lease and its end timer were gone at +${gone_at}s; $model_note"

STEP="4 (early revoke)"
grant 900s # 15 minutes: room for the stub checks; the early revoke ends it
KEY2=$KEY
expect 200 "$KEY2" "the key of the second grant" "GET /v1/models"
stub_note="not run (no --stub): the 503 and the frozen-model checks"
if [[ $STUB == yes ]]; then
  STEP="4 (stub stopped)"
  stop_stub
  expect 503 "$KEY2" "the key, with the stub stopped" "GET /v1/models" "POST /v1/chat/completions"
  start_stub
  expect 200 "$KEY2" "the key, with the stub started again" "GET /v1/models"
  say "ok: with the stub stopped, the key gets 503"

  STEP="4 (stub frozen)"
  say "the stub is frozen (SIGSTOP); the gateway must answer 504 at its 300 s response header timeout"
  kill -STOP "$STUB_PID"
  frozen_start=$(date +%s)
  printf 'Authorization: Bearer %s\n' "$KEY2" >"$TMP/auth"
  # Not -m 10: the header timeout of the gateway is 300 s. -m 330 tells a hang from that error. In the
  # background: the INT and TERM trap runs at once.
  curl -q --noproxy '*' -sS -o /dev/null -w '%{http_code}' -m 330 "${VIA[@]}" -H @"$TMP/auth" \
    "$PUBLIC_URL/v1/models" >"$TMP/frozen" &
  wait $! || true
  frozen_code=$(cat "$TMP/frozen")
  frozen_s=$(($(date +%s) - frozen_start))
  kill -CONT "$STUB_PID"
  if [[ $frozen_code != 504 ]] || ((frozen_s < 290 || frozen_s > 315)); then
    fail "with the stub frozen, the key got \"$frozen_code\" after $frozen_s s; it must get 504 after 290 to 315 s (the 300 s response header timeout)"
  fi
  stub_note="503 with the stub stopped; 504 after ${frozen_s}s with the stub frozen"
  say "ok: with the stub frozen, the key gets 504 after ${frozen_s}s"
  STEP="4 (early revoke)"
fi
"$BIN" revoke "$NAME" || fail "sparkpass revoke $NAME failed"
wait_caddy
expect 401 "$KEY2" "the key after the early revoke" "${EVERY[@]}"
refused
timer_gone || fail "an end timer still exists after the revoke: $TIMER, or one of: $(end_timers)"
no_lease || fail "sparkpass list still shows a lease after the revoke"
say "ok 4: after the early revoke the key gets 401 on every path, and the end timer is gone"

STEP="5 (re-grant)"
grant "${TTL_S}s"
KEY3=$KEY
[[ $KEY3 != "$KEY1" && $KEY3 != "$KEY2" ]] || fail "the new grant gave an earlier key"
expect 200 "$KEY3" "the key of the new grant" "GET /v1/models"
expect 401 "$KEY1" "the key of the first grant" "${EVERY[@]}"
expect 401 "$KEY2" "the key of the revoked grant" "${EVERY[@]}"
say "the new key works, and the earlier keys get 401; waiting for the end time of the new lease"
# The new lease ends at its own end time (design, Success Criteria): not before it, and not later than the bounds.
wait_until $((DEADLINE - 3))
expect 200 "$KEY3" "the key of the new grant, 3 s before its end time" "GET /v1/models"
until_by $((DEADLINE + BOUND)) "the new key does not get 401 on every path $BOUND s after its end time" answers 401 "$KEY3" "${EVERY[@]}"
recut_at=$(($(date +%s) - DEADLINE))
refused
until_by $((DEADLINE + 30)) "sparkpass list still shows a lease 30 s after the end time of the new lease" no_lease
until_by $((DEADLINE + 30)) "$TIMER or another end timer still exists 30 s after the end time (systemctl list-timers --all 'sparkpass-end-*')" timer_gone
regone_at=$(($(date +%s) - DEADLINE))
ARMED=no
say "ok 5: the new lease ended at its own end time: the key got 401 at +${recut_at}s, the lease and its end timer were gone at +${regone_at}s"

cat <<EOF

PASS: tests/expiry.sh, build phase 1 (API only), through $ROUTE
  deny-all:       401 on every path for no header, an empty bearer value, and a wrong key
  active lease:   200 on /v1/models, the 404 of the gateway (no body) on each route outside the pass; 401 for the other callers
  forced end:     lock held until +${lock_end}s; stream ended at +${stream_end}s (curl exit $stream_rc), key 401 at +${cut_at}s (limit +${BOUND}s), no lease and no end timer at +${gone_at}s (limit +$((lock_end + 30))s)
  model server:   $model_note
  early revoke:   401 on every path, no end timer
  stub:           $stub_note
  re-grant:       the new key works, the earlier keys get 401; at its own end time: key 401 at +${recut_at}s (limit +${BOUND}s), no lease and no end timer at +${regone_at}s (limit +30s)
Not tested (build phase 2): SSH login and its end, the refusal of a new login, the
workspace container, the home image and its removal, the forced erase failure, tests/boundary.sh.
$([[ $VIA_PUBLIC == yes ]] || echo "Run it again with --via-public: the inbound-path run of the Success Criteria.")

EOF
if [[ $REBOOT_NOTE == yes ]]; then manual all; else manual certificate; fi
