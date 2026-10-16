#!/usr/bin/env bash
# Forced-end, deny-all and re-grant test of the guest pass, build phase 1 (API only).
# Design: docs/designs/guest-pass-mvp.md, "Success Criteria" and "Next Steps" 6.
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
# Each "every path" check. The first three are the routes of the pass. On each other route the key gets
# the 404 of the gateway (the route allowlist of gateway/Caddyfile): other routes of the model server can
# change state that the next guest sees.
EVERY=("GET /v1/models" "POST /v1/chat/completions" "POST /v1/completions"
  "GET /v1/chat/completions" "POST /v1/models" "POST /v1/embeddings" "POST /v1/responses"
  "POST /v1/load_lora_adapter" "POST /invocations" "POST /tokenize" "GET /metrics" "GET /health")
DENIED=("${EVERY[@]:3}")

usage() {
  cat <<'EOF'
Usage: sudo tests/expiry.sh [--ttl <n>s|<n>m] [--skip-reboot-note]

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
     15 s after the end time, the stream ends and the key gets 401 on GET /v1/models and
     POST /v1/chat/completions (then on every path, and the other callers too); within
     30 s after the lock hold, sparkpass list shows no lease and the end timer is gone.
     The model server shows zero running requests.
  4  grant and an early revoke: the key gets 401, and the end timer is gone.
  5  a new grant of the same name, with the TTL of step 3: the new key works, and the
     earlier keys get 401. The new lease ends at its own end time: the new key gets 401
     on the two routes of step 3 within 15 s (then on every path), and within 30 s no
     lease and no end timer stay.
  6  a summary.
"Every path": the routes of the pass (GET /v1/models, POST /v1/chat/completions,
POST /v1/completions), then GET /v1/chat/completions, POST /v1/models,
POST /v1/embeddings, POST /v1/responses, POST /v1/load_lora_adapter,
POST /invocations, POST /tokenize, GET /metrics, GET /health.

Options:
  --ttl <n>s|<n>m     TTL of the leases in steps 3 and 5 (default 5m; at least 120s).
  --skip-reboot-note  do not print the reboot procedures at the end.
  -h, --help          print this text and the manual procedures.

Environment:
  EXPIRY_MAX_TOKENS   max_tokens of the stream to the real model (default 131072: the pinned
                      Qwen ended 32768 tokens before a 5-minute end time). The
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
     model runs). journalctl -b -u pass-reconcile.service shows no failed check of the
     boot run; curl exit code 35 there is the race with tailscaled (TODOS.md).
  3. sparkpass revoke $NAME. The key gets 401.

EOF
  fi
  cat <<EOF
Manual: the certificate from tailscaled and the route of Tailscale Funnel (step 1 of the
procedure that install.sh prints). Also after the unit was off for a long time. <name> is
the host of PUBLIC_URL:
  1. grep TS_PERMIT_CERT_UID /etc/default/tailscaled prints TS_PERMIT_CERT_UID=caddy.
  2. tailscale cert --cert-file - <name> >/dev/null succeeds: tailscaled has the certificate.
  3. After sparkpass reconcile, this command shows <name> and a public CA (Let's Encrypt).
     Caddy 2.6.2 logs no line for a certificate from tailscaled, and none for a failed
     handshake, so journalctl -u caddy proves nothing here:
       openssl s_client -connect 127.0.0.1:443 -servername <name> </dev/null | openssl x509 -noout -subject -issuer
     and this command, with the normal certificate check, gives 401:
       curl -sS -o /dev/null -w '%{http_code}\n' --connect-to ::127.0.0.1: https://<name>/v1/models
  4. tailscale funnel status shows TCP 443 of this node, forwarded to 127.0.0.1:443.
  5. getent hosts <name> gives a public address (a relay of Funnel), not a 100.x tailnet
     address: 'tailscale set --accept-dns=false' is on, so the self-check of grant takes the
     public route.
  6. tests/expiry.sh. Each check uses TLS with the name of PUBLIC_URL and a normal
     certificate check, so a pass also proves the certificate.
Check a key with the command below (GATEWAY_CHECK_ADDRESS is always 127.0.0.1):
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

REBOOT_NOTE=yes TTL=5m
while (($#)); do
  case $1 in
    --ttl)
      (($# >= 2)) || usage_error "--ttl needs a value"
      TTL=$2
      shift
      ;;
    --skip-reboot-note) REBOOT_NOTE=no ;;
    -h | --help) usage; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
[[ $TTL =~ ^([0-9]{1,6})([sm])$ ]] || usage_error "--ttl must be <n>s or <n>m, for example 5m"
TTL_S=$((10#${BASH_REMATCH[1]}))
if [[ ${BASH_REMATCH[2]} == m ]]; then TTL_S=$((TTL_S * 60)); fi
# The shortest TTL that grant accepts (grant::HAND_OUT_TIME in src/grant.rs).
MIN_TTL=120
((TTL_S >= MIN_TTL)) || usage_error "--ttl must be at least ${MIN_TTL}s"
MAX_TOKENS=${EXPIRY_MAX_TOKENS:-131072}
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
[[ $ADDRESS == 127.0.0.1 ]] || die "$CONFIG: GATEWAY_CHECK_ADDRESS must be 127.0.0.1, where Caddy listens (sparkpass refuses each other value)"
# Each connection goes to GATEWAY_CHECK_ADDRESS on the port of PUBLIC_URL, as the reconcile check does.
# TLS still checks the name of PUBLIC_URL.
VIA=(--connect-to "::$ADDRESS:")
ROUTE="--connect-to $ADDRESS"
WRONG=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')

STEP=start ARMED=no STREAM_PID="" BAD="" OPEN="" KEY="" MODEL="" DEADLINE=0 TIMER=""
TMP=$(mktemp -d) # mode 0700: $TMP/auth holds a key

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '\nFAIL in step %s: %s\n' "$STEP" "$*" >&2; exit 1; }

cleanup() {
  local rc=$?
  # PIPE too: a closed output pipe (tee, an SSH drop) must not stop the revoke and the marker below.
  trap '' INT TERM HUP PIPE
  trap - EXIT ERR
  set +e
  # The stream, the lock hold (flock -o: the kill frees the lock), a sleep.
  # shellcheck disable=SC2046 # one word for each pid
  kill $(jobs -p) 2>/dev/null
  # A gateway proven open: the marker and the stop come first, because a revoke cannot close it.
  if ((rc != 0)) && [[ -n $OPEN ]]; then close_open_gateway; fi
  if ((rc != 0)) && [[ $ARMED == yes ]]; then
    printf 'expiry.sh: the test failed (exit %s); running: sparkpass revoke %s\n' "$rc" "$NAME" >&2
    "$BIN" revoke "$NAME" || printf 'expiry.sh: the revoke failed too: check sparkpass list\n' >&2
    # After the revoke the last key must get 401 on every path. An HTTP answer other than 401 (not a curl
    # failure, 000) proves an open gateway, also when the failed step was a wait (until_by) and not expect().
    # A 421 is no proof: the request did not reach the token check (grant step 8).
    if [[ -z $OPEN && -n $KEY ]] && ! answers 401 "$KEY" "${EVERY[@]}" && [[ $BAD == *=[1-9]* ]]; then
      if [[ $BAD != *=421* ]]; then
        OPEN="the last key still passed the gateway after the revoke:$BAD"
        close_open_gateway
      else
        printf 'expiry.sh: after the revoke the check at %s failed:%s%s (no marker)\n' "$ADDRESS" "$BAD" "$(hint)" >&2
      fi
    fi
  fi
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
# A 404 with a body is "404+body": only the 404 of the gateway has no body (the model server sends JSON).
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
    printf '\n  000: curl failed (see its error above). For a TLS error: see "the certificate from tailscaled" in --help; also check that tailscale status shows this unit online and that /etc/default/tailscaled has TS_PERMIT_CERT_UID=caddy.'
  fi
  if [[ $BAD == *=404+body* ]]; then
    printf '\n  404+body: the request passed the gateway, and the model server answered it.'
  fi
  if [[ $BAD == *=421* ]]; then
    printf '\n  421: Caddy (strict_sni_host) refused the request before the token check: its Host header is not the TLS name of the gateway. The host of PUBLIC_URL must be SPARKPASS_SITE of caddy.env, with no trailing dot.'
  fi
}

# expect WANT WHO LABEL ROUTE...: answers, or fail. LABEL names WHO; the message never holds a key.
expect() {
  local want=$1 who=$2 label=$3
  shift 3
  answers "$want" "$who" "$@" && return 0
  # An HTTP answer other than 401 (000 is a curl failure, not an answer) proves the gateway open, but a 421
  # is no proof: the request did not reach the token check (grant step 8).
  if [[ $want == 401 && $BAD == *=[1-9][0-9][0-9]* && $BAD != *=421* ]]; then
    OPEN="tests/expiry.sh step $STEP, $(date -u '+%F %T UTC'): the gateway answered$BAD to $label at $ADDRESS, and each answer must be 401: the gateway does not enforce the token file"
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
  model_get /metrics | awk '/^(vllm:num_requests_running|sglang:num_running_reqs)[{ ]/ {s += $NF; n++} END {if (n) printf "%d\n", s}'
}
busy() { local n; n=$(running); [[ -z $n ]] || ((n >= 1)); }
idle() { [[ $(running) == 0 ]]; }

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
  deadline=$(sed -n 's/.*"deadline": *\([0-9][0-9]*\).*/\1/p' "$STATE/leases/$NAME.json" 2>/dev/null || true)
  [[ $deadline == "$DEADLINE" ]] || fail "the deadline \"$deadline\" in $STATE/leases/$NAME.json is not the end time of the pass ($DEADLINE)"
  TIMER=sparkpass-end-$NAME-$deadline.timer
  systemctl is-active --quiet "$TIMER" || fail "the grant created no active end timer $TIMER"
  say "grant: the end time is $end, the end timer is $TIMER"
}

ARMED=yes
say "sparkpass expiry test, build phase 1 (API only): $PUBLIC_URL through $ROUTE"
say "TTL ${TTL_S}s; the test takes about $(((2 * TTL_S + 150) / 60)) minutes"

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
# Two routes time the cut: GET /v1/models and POST /v1/chat/completions, the route of the stream (Codex
# adversarial, P2). Before the cut, the POST sends {}, which starts no stream.
# Every route and the other callers follow after the time limits: 12 to 48 requests would count against
# the limits of the revoke.
until_by $((DEADLINE + BOUND)) "the key does not get 401 $BOUND s after the end time" answers 401 "$KEY1" "GET /v1/models" "POST /v1/chat/completions"
cut_at=$(($(date +%s) - DEADLINE))
until_by $((DEADLINE + lock_end + 30)) "sparkpass list still shows a lease 30 s after the end of the lock hold" no_lease
until_by $((DEADLINE + lock_end + 30)) "$TIMER or another end timer still exists 30 s after the end of the lock hold (systemctl list-timers --all 'sparkpass-end-*')" timer_gone
gone_at=$(($(date +%s) - DEADLINE))
expect 401 "$KEY1" "the key after the end time" "${EVERY[@]}"
refused
if [[ -n $(running) ]]; then
  until_by $(($(date +%s) + BOUND)) "the model server still runs a request after the stream closed (design Open Question 4)" idle
  model_note="the model server runs zero requests"
else
  model_note="NOT CHECKED: the model server shows no running-request count on /metrics; check it by hand (design Open Question 4)"
fi
say "ok 3: with the lock held until +${lock_end}s, the stream ended at +${stream_end}s (curl exit $stream_rc), the key got 401 at +${cut_at}s, the lease and its end timer were gone at +${gone_at}s; $model_note"

STEP="4 (early revoke)"
grant "${TTL_S}s" # the early revoke below ends it
KEY2=$KEY
expect 200 "$KEY2" "the key of the second grant" "GET /v1/models"
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
# The two routes of step 3 time the cut.
until_by $((DEADLINE + BOUND)) "the new key does not get 401 $BOUND s after its end time" answers 401 "$KEY3" "GET /v1/models" "POST /v1/chat/completions"
recut_at=$(($(date +%s) - DEADLINE))
until_by $((DEADLINE + 30)) "sparkpass list still shows a lease 30 s after the end time of the new lease" no_lease
until_by $((DEADLINE + 30)) "$TIMER or another end timer still exists 30 s after the end time (systemctl list-timers --all 'sparkpass-end-*')" timer_gone
regone_at=$(($(date +%s) - DEADLINE))
expect 401 "$KEY3" "the new key after its end time" "${EVERY[@]}"
refused
ARMED=no
say "ok 5: the new lease ended at its own end time: the key got 401 at +${recut_at}s, the lease and its end timer were gone at +${regone_at}s"

cat <<EOF

PASS: tests/expiry.sh, build phase 1 (API only), through $ROUTE
  deny-all:       401 on every path for no header, an empty bearer value, and a wrong key
  active lease:   200 on /v1/models, the 404 of the gateway (no body) on each route outside the pass; 401 for the other callers
  forced end:     lock held until +${lock_end}s; stream ended at +${stream_end}s (curl exit $stream_rc), key 401 at +${cut_at}s (limit +${BOUND}s), no lease and no end timer at +${gone_at}s (limit +$((lock_end + 30))s)
  model server:   $model_note
  early revoke:   401 on every path, no end timer
  re-grant:       the new key works, the earlier keys get 401; at its own end time: key 401 at +${recut_at}s (limit +${BOUND}s), no lease and no end timer at +${regone_at}s (limit +30s)
Not tested here: the public route through Tailscale Funnel (grant step 8 checks it at each grant).

EOF
if [[ $REBOOT_NOTE == yes ]]; then manual all; else manual certificate; fi
