# TODOS

## Pass tool

### Stronger erase of guest data

**What:** Encrypt the home image of each lease (LUKS) with a random key that revoke discards, and restart the model server between guests.

**Why:** After a plain delete, the guest's files stay in the storage blocks, and recent prompts can stay in the memory of the model server.

**Context:** From the eng review of 2026-10-05 (outside-voice finding O-4, decision D13). The pass text now tells the guest that the delete is not a secure erase. The key must survive a reboot inside an active lease, or the guest's data is lost; decide where it lives before you build. A model restart costs about 2 minutes with the TensorFold boot model (11 to 13 minutes with vLLM), and its prompt cache keeps recent prompts in memory until then. Start at "pass grant" step 5 and "pass revoke" step 5 in `docs/designs/guest-pass-mvp.md`.

**Effort:** M
**Priority:** P3
**Depends on:** Build phase 2 complete (the home image exists).

### One retry of the reconcile probe on a network error

**What:** In `check_gateway`, when a wrong-token request fails in curl (exit 7, 28, 35), wait 1 to 2 seconds and send the two requests once more before Caddy stops. An answer other than 401 still stops Caddy at once.

**Why:** One transient failure during an active lease stops the gateway for up to 5 minutes, and the end time of the pass does not move.

**Context:** From the /ship adversarial review of 2026-10-06 (Claude adversarial, INVESTIGATE). Add it only when tests/expiry.sh on the units, with a reboot inside an active lease, shows a probe failure right after the start that passes on the next run. A transport error proves nothing about the token check, so the owner decides.

**Effort:** S
**Priority:** P3
**Depends on:** The systemd units and tests/expiry.sh on the units.

## Gateway (Caddyfile step)

### Prove the gateway step on the units

**Status (2026-10-15):** done on spark-3: install.sh, the Funnel procedure, the settings, the certificate from tailscaled (Let's Encrypt, served by Caddy), the serve config that src/funnel.rs requires, `gh attestation verify` on the CI binary, and `tests/expiry.sh` against the real model: PASS (the forced end cut the stream 2 s after the end time; the key got 401 at once). Dropped for now (owner: move fast): `--stub` (tests/gateway.sh covers its 503 case in CI) and `--via-public`. From the home ISP, 2 of the 4 relay addresses of the ts.net name never accept a TCP connection, while servers in 8 other countries reach all of them (check-host.net) and get 401. So from home, about half of the new connections hang: `--via-public` fails, and grant's public self-check fails closed about 1 time in 2 to 4 (run grant again). Guests elsewhere are not affected; each new connection from outside takes 3 to 17 s (the ingress nodes reach the unit through DERP). The manual checks passed on 2026-10-15 (owner decision D17): a reboot inside a lease with the clock not synchronized at boot (NTP pointed at an address that does not answer: Caddy stayed stopped and port 443 refused until the sync, then reconcile created the end timer again and it fired at the end time), and a reboot across the end time (the end passed while the unit was off; the boot run of reconcile revoked the lease, then started Caddy). The boot `{}` window did not show in 3 boots (no serve-config line and no curl exit code 35 in the boot run of reconcile). It showed on 2026-10-21, after a power cut with no lease: the clock synced at 00:28:01, the boot run of reconcile read `{}` and sent one false serve-config notification, and its gateway check failed with curl exit code 35; tailscaled reached Running at 00:28:05, and the next run (00:30) started the gateway. Fixed (owner decisions D4 and D5, as planned): pass-reconcile.service waits up to 10 s for tailscaled before the run (`ExecStartPre=-/usr/bin/tailscale wait --timeout=10s`; TimeoutStartSec 195), and a serve config that does not match counts only while `tailscale status --json` shows BackendState Running (journal only otherwise; grant names the state). The proof of the wait is the next boot. The `--stub` and `--via-public` modes of tests/expiry.sh were removed on 2026-10-16 (Codex review F3): CI's tests/gateway.sh covers the 503 of a stopped model server, and each grant checks the public route. Still open: one long request with a key through a relay of Funnel ("Long requests through the gateway"); the NOTIFY_URL message reached the owner on 2026-10-21 (Completed).

**What:** On the head unit, after milestone 1 (firewall/rules.sh, the settings): run `sudo ./install.sh`, follow the Tailscale Funnel procedure that it prints (TS_PERMIT_CERT_UID=caddy, `tailscale set --accept-dns=false`, `tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443`, one `tailscale cert`), fill /etc/sparkpass/config and caddy.env, and run `sudo tests/expiry.sh --stub`, `sudo tests/expiry.sh`, and `sudo tests/expiry.sh --via-public`. Then the manual checks that the script prints: a reboot inside an active lease (with the boot race of tailscaled: the boot run of reconcile starts Caddy and checks it at once, and Caddy 2.6.2 gets the certificate of the ts.net name only after tailscaled has its first netmap; a failed boot check, curl exit code 35, keeps the gateway stopped until the next timer run, so if the check shows it, add a bounded wait in reconcile until `tailscale status --json` shows BackendState Running and the name in CertDomains; owner decision D5 of the /ship review), a boot with no network (the gateway stays closed), and the certificate from tailscaled and the route of Funnel. Also: `tailscale serve status --json` gives exactly the one handler that src/funnel.rs requires (its JSON form comes from `ipn.ServeConfig` in the Tailscale source, not from the unit), so grant passes step 1 and reconcile journals no serve-config line; after a reboot, whether the boot run of reconcile reads `{}` (tailscaled keeps an empty serve config until its first netmap), which sends one false serve-config notification for each boot and makes a grant in that window refuse (the next run removes the marker with no message; adversarial review A2 of 2026-10-13, owner decision D4: check first, then choose between journal-only for `{}`, which also hides a Funnel reset, and a wait for BackendState Running, which uses the last 10 s of the reconcile budget); `gh attestation verify sparkpass -R hussu010/sparkpass` on the CI binary; one real `NOTIFY_URL` message (for example a REVOKE-FAILED test lease); `systemctl show -p After multi-user.target` for the chrony-wait drop-in (with no network the boot waits for the clock); `systemctl reload caddy` over the admin socket with the Ubuntu package, as the caddy user (grant step 7 does it): that package is 2.6.2 rebuilt with Go 1.22, and the Docker image caddy:2.6.2 of tests/gateway.sh has Go 1.19.2 (Go changed the Host header of a request to a unix socket in 1.20.6; Go 1.22 sends an empty Host, which the admin API of 2.6.2 accepts); the self-check of grant step 8 through a relay of Funnel (accept-dns off) and a check from an outside network; the first handshake with a certificate that tailscaled must order (within the 8-second limit of the reconcile check, or the `tailscale cert` step is required); list the `/v1` routes of the pinned model server with its flags (runtime LoRA load and unload, a stored Responses API, file or batch upload), and check that the routes outside the pass in tests/expiry.sh (DENIED) and tests/gateway.sh (denied) cover the routes that change state, because a guest can change state that the next guest or the host sees (owner decision D14); after `tests/expiry.sh --via-public`, check `journalctl -u tailscaled | grep 'failed to TCP proxy'`: tailscaled logs the client address of each Funnel connection that it cannot forward, and the pass text says so (owner decision D10); and prove on the unit that a `systemctl try-restart caddy` of the end timer's revoke, sent while reconcile's `systemctl start caddy` is still activating, restarts Caddy after the start (systemd 240 and later collapse a try-restart of an activating unit into a restart; then the old key gets 401 at once; owner decision D17, from Codex round 3).

**Why:** The Caddyfile is proven in Docker, and the tool with fakes, but only the units prove systemd, the caddy package, the inbound path (Tailscale Funnel and the certificate from tailscaled), the stream cut within 15 seconds, and the boot gate.

**Context:** Split from "Fail closed when the gateway does not enforce the token file" (TODO batch 2 of 2026-10-06). The review notes of the batch are in the PR of the branch. The code parts landed on branch feat/tunnel-and-p1-code (2026-10-07), with the owner decisions of that day: the inbound method is Tailscale Funnel with raw TCP passthrough (TLS ends at Caddy, the certificate comes from tailscaled, Caddy listens on 127.0.0.1 only and has no port-80 listener, and the access log keeps no client address); the admin API is on `unix//run/caddy/admin.sock` with `RuntimeDirectory=caddy` (the reloads of tests/gateway.sh go over the socket, on 2.6.2 and 2.11); a guest key reaches only GET /v1/models, POST /v1/chat/completions and POST /v1/completions, and each other route gets the gateway's 404 (D14); reconcile reads `systemctl show -p ActiveState --value caddy` after a failed step (activating and deactivating stop Caddy); `GATEWAY_CHECK_ADDRESS` must be 127.0.0.1, where Caddy listens (rule 3 of the completed item "Fail closed when the gateway does not enforce the token file"; owner decision D3 of the /ship review); and grant step 8 confirms an answer other than 401 of the public route through the loopback check before it writes the marker. The /ship review of the branch added (owner decisions D4 and D5): a Host header other than the TLS name gets 421 (`strict_sni_host`), and the default logger keeps the same filtered fields as the site log, also for a served request with the site name in other letter case (D7); grant step 8 names a listener with no key check for a 2xx or 3xx public answer and notifies; tests/expiry.sh --via-public confirms a non-401 answer through 127.0.0.1 before it writes the marker, and each cut is timed on one route (two routes since item 4 of "Review follow-ups of the Funnel branch", 2026-10-13); pass-reconcile.service starts after tailscaled (After= only, so that an owner's stop of tailscaled lasts; D8); tests/expiry.sh needs --ttl 180s or more with --via-public (D9); the pass text names the relays of Tailscale and the journal of tailscaled (D10).

**Effort:** M
**Priority:** done (2026-10-15). Open: the 300 s question ("Long requests through the gateway").
**Depends on:** Milestone 1 (Next Steps 1 to 3 of the design: the model on the pair, the Funnel setup, firewall/rules.sh).

### Review follow-ups of the Funnel branch

**What:** Fix the small items that the /ship review of branch feat/tunnel-and-p1-code found in its last cycle and in its adversarial step:
1. (Done.) The test `reconcile_unit_orders_after_tailscaled_and_does_not_start_it` (src/reconcile.rs) matches keys with `strip_prefix("Wants=")`, so a valid systemd line `Wants = tailscaled.service` (spaces around "=") passes. Parse as `admin_socket_is_in_the_runtime_directory_of_the_caddy_unit` does (split at "=", trim the key). That test in src/gateway.rs also misses an empty `RuntimeDirectory=` line, which resets the list.
2. (Done.) The cleanup comment of tests/expiry.sh ("an HTTP answer other than 401 ... proves an open gateway") does not say that with --via-public, proven_open decides.
3. (Done.) The pass text names no route. Add "Routes: GET /v1/models, POST /v1/chat/completions and POST /v1/completions only; each other route gets 404." and pin it in the pass-text test.
4. (Done in code; the proof is a run on the unit.) tests/expiry.sh times each 15-second cut on GET /v1/models only. Also send POST /v1/chat/completions in the timed check (Codex adversarial, P2).
5. (Done.) A PUBLIC_URL whose host ends with "." (the DNSName of `tailscale status --json`) gets 421 from strict_sni_host, and check_gateway then writes a false gateway-open marker with the wrong repair hint. Refuse such a PUBLIC_URL in read_settings, or count 421 as a failed check (stop, no marker).
6. (Done.) Grant step 8 sends no notification for a public 2xx or 3xx answer when the loopback check fails, and none for a listener that serves only POST (the GET gets 401, the POST a 400 or 422 of the model server). Consider one notification for each public answer other than 401.
7. (Not proven: the mode `tests/expiry.sh --stub --via-public` was removed on 2026-10-16; the question is open in the item above.) On the unit: check that a Funnel relay does not close a silent connection before the 300 s response-header limit of Caddy (a long prefill), for example with one `tests/expiry.sh --via-public` request whose first header comes after about 290 s.
Optional (advisory; done): proven_open can use `local VIA=("${DIRECT[@]}")` (bash locals are dynamically scoped) in place of the save and restore; tests/expiry.sh can refuse a GATEWAY_CHECK_ADDRESS other than 127.0.0.1 before it arms.

**Why:** Each item fails closed or is a gap in a test, but together they make the errors and the tests of the gateway exact before the first guest.

**Context:** From cycle 3 and Step 11 of the /ship review of branch feat/tunnel-and-p1-code (specialists, red team, the Claude adversarial pass, the Codex adversarial challenge; 2026-10-07). A /ship run stops before the push when a third fixing cycle edits a file, so the owner moved these items to the next branch (owner decisions D11 and D12). Item 5 matters on the unit now: put the ts.net name with no trailing dot in PUBLIC_URL and SPARKPASS_SITE.

**Effort:** S
**Priority:** done, except item 7 (now "Long requests through the gateway")
**Depends on:** None (items 4 and 7 run on the head unit).
**Completed (items 1, 2, 3, 5 and 6):** branch fix/funnel-review-followups (2026-10-08). Item 4 in code: branch fix/funnel-check-and-expiry-items (2026-10-13); steps 3 and 5 of tests/expiry.sh time the cut on GET /v1/models and POST /v1/chat/completions (the POST sends `{}`, which starts no stream), and a run on the unit proves it. Item 7 and the optional advisories: the same branch (2026-10-13). The frozen-stub request of `tests/expiry.sh --stub --via-public` is silent for 300 s on a relay of Funnel, so that run proves item 7; its failure text names a relay that closes a silent connection, and --help says so. proven_open uses `local VIA=("${DIRECT[@]}")`, and the script refuses a GATEWAY_CHECK_ADDRESS other than 127.0.0.1 before it arms. Item 1: the test helper `gateway::unit_values` reads a unit key as systemd does (split at "=", the key trimmed), both unit-file tests use it, and the test of the caddy drop-in honors an empty `RuntimeDirectory=` (a reset; a dependency such as Wants= has no reset). Item 2: the comment names proven_open for --via-public. Item 3: the pass text has the routes line, and `routes_of_the_pass_text_are_the_routes_of_the_caddyfile` compares it with `@sparkpass_route` of gateway/Caddyfile. Item 5, both ways: `read_settings` refuses a PUBLIC_URL host with a trailing dot and names the fix, and the gateway check (grant steps 1 and 8, reconcile) counts a 421 as a failed check (stop, no marker), and so does tests/expiry.sh at the check address (in proven_open, expect and the cleanup check); etc/config.example, etc/caddy.env.example and install.sh say "no trailing dot". Item 6: each stop of step 8 for a public answer other than 401 sends one notification after the stop, with a text that names the case (also a 400 or 422 to the POST: a listener with no key check); a proven answer sends only the notification of the marker.

### Long requests through the gateway

**Status (2026-10-18):** measured through one pinned relay address of the ts.net name, with no key and no model load: a TLS connection with no request stayed open for 960 s of silence (the test limit), and a keep-alive connection after one 401 closed at 301 s (Caddy's own 5-minute idle limit). So a relay does not close a silent connection within 16 minutes, and the only limit was Caddy's `response_header_timeout 300s`. Raised to 960 s (gateway/Caddyfile, tests/gateway.sh, the design): 4 queued GLM requests of 472k tokens that are not streamed end after about 916 s. A streamed request gets its header at once and is not affected by this limit.

Installed on spark-3 on 2026-10-18 during the pass of 2026-10-17 (a copy of gateway/Caddyfile and `systemctl reload caddy`; Caddy logged "load complete", and the next reconcile run passed).

**What is left:** one real long request with a key through the relay: one request that is not streamed and ends after 300 to 900 s.

**Effort:** S
**Priority:** P2
**Depends on:** a gap between passes.

## Firewall (milestone 1)

### Firewall rules with Tailscale on the units

**What:** Done in code (branch feat/firewall-rules, 2026-10-15): firewall/rules.sh decides by interface (loopback and the two ConnectX-7 interfaces; SSH, ICMP, WireGuard 41641, DHCP replies and mDNS elsewhere), drops forwarding to the link, and exits non-zero while tailscaled adds its jumps; tests/firewall.sh tests it with a real iptables in Docker. Proven on the units (2026-10-15): nodivert on both; `install.sh --second-unit` on spark-4 and a load by hand on spark-3; the temporary `sparkpass-temp-25000` rules removed; from the LAN (Ethernet, Wi-Fi, IPv6) and the tailnet (IPv4, IPv6), port 25000 is dropped and SSH works; over the link, the other unit reaches port 25000 and a vLLM port; the same after `systemctl restart tailscaled` on each unit; after a reboot of spark-4, sparkpass-firewall.service loads the rules 11 s after boot; the model starts and serves under the rules. Left: spark-3 loads the rules at boot only after install.sh (reconcile) in Phase 3; in Phase 3, prove that the Funnel route still reaches Caddy (the peer API connection from a tailnet device made no kernel socket on spark-3, so tailscaled takes it before the kernel). In the tailnet policy, give tailnet sources no access to the units except the owner's SSH. Repeat the boundary checks after `systemctl restart tailscaled` with one tailnet device as the source.

Background: in its default netfilter mode, tailscaled puts `-j ts-input` and `-j ts-forward` first in INPUT and FORWARD at each start; ts-input accepts all traffic on tailscale0, and ts-forward ends with `-o tailscale0 -j ACCEPT`. So a control port that binds 0.0.0.0 is open to each tailnet device (port 25000 was, on 2026-10-14), and after a `systemctl restart tailscaled` while Docker runs, ts-forward comes before DOCKER-USER and a container on a Docker bridge can reach the tailnet.

**Why:** The boundary rules of the design named the LAN and the internet; the inbound route of 2026-10-07 adds the tailnet. Multi-node serving opens control ports that permit code execution.

**Context:** From the security specialist and the red team of the /ship review of branch feat/tunnel-and-p1-code (owner decision D5, 2026-10-07). The design now says "the LAN, the tailnet, and the internet" in its constraint and its Success Criteria. install.sh copies firewall/rules.sh to /usr/local/lib/sparkpass/rules.sh.

**Effort:** M
**Priority:** done (2026-10-15). Tailnet policy: no change (owner decision of 2026-10-18). The tailnet has two admin accounts, the owner's and a second admin's, so the default policy (each member reaches each device) is correct; the firewall leaves tailnet devices only SSH and, on spark-3, the gateway. SSH on both units accepts keys only since 2026-10-18 (`/etc/ssh/sshd_config.d/10-sparkpass-keys-only.conf`, owner decision D33); the second admin needs a key on both units. Left (P2): the boundary checks after a `systemctl restart tailscaled` from a tailnet device.
**Depends on:** nothing more (the ports and bind addresses were listed on 2026-10-15).

### The worker starts vLLM even when its firewall rules did not load

**What:** Since the Codex review of 2026-10-16 (F1), sparkpass-model.service loads the rules of the head unit as root before each start of the model. It cannot check the worker: sparkpass-firewall.service loads the rules there at boot, and a failed load does not stop sparkrun from starting the worker container. One way: an ExecStartPre that runs `ssh <worker-cx7> systemctl is-active --quiet sparkpass-firewall.service` as the sparkrun user (no sudo needed); install.sh then needs the worker address.

**Why:** The control ports of vLLM permit code execution. On a worker with no rules they accept connections from the LAN and the tailnet.

**Effort:** S
**Priority:** done (2026-10-17): `firewall/check-workers.sh` runs as the second ExecStartPre of sparkpass-model.service. It reads the hosts of the sparkrun cluster (`sparkrun cluster show pair --json`), skips the addresses of the head, and needs `systemctl is-active sparkpass-firewall.service` over SSH on each other host; a failure stops the start, and the unit tries again in 30 s. Tested by tests/check-workers.sh (fakes) and by hand on spark-3.
**Depends on:** nothing.

## Models

### Model profiles and one command

**Status (2026-11-06):** a text model can be switched by hand: README "Run another model" (sparkrun search, export and validate; `RECIPE=` in /etc/sparkpass/model.env; a restart of sparkpass-model.service). From 2026-10-17 the pair served GLM-5.3-Flash with vLLM (`templates/glm53-flash.yaml`, RECIPE= in /etc/sparkpass/model.env on spark-3): warm start 304 s; one stream 23-28 tokens/s; 4 requests at the same time; 4 x 126k and 1 x 472k prompt tokens passed with at least 5.96 GiB free (earlyoom kills near 2.4 GiB). Its loader needs io_uring, so the recipe names `templates/seccomp-io-uring.json`. Since 2026-11-05 the boot model is GLM-5.3-Flash with the TensorFold recipe 1104 (README, "The boot model: TensorFold 1104"; the drop-in `systemd/sparkpass-model-tf1104.conf` on spark-3): one stream 40 tokens/s for prose and 60 for code, 86 in total for 4 streams, 8 requests at the same time, a 1,048,576-token context, and 10 GiB free on each unit; after the power cut of 2026-11-06 the boot service had the API back in 108 s. Still open: the command below.

**What:** `sparkpass model use <model>`: find a tested recipe (the sparkrun registries, templates/, or a drop-in such as the TensorFold one), check the memory (`sparkrun recipe vram`, or the memory check of the recipe), refuse while a lease is active, stop the old model, start the new one, run its smoke test, and give the pass text the tips of that model (thinking, Claude Code). A model with no tested recipe: stop with a message, not a guess. One model runs at a time.

**Why:** Owner requirement of 2026-10-15: one model at a time, with one command and no code for each model. Text models only (owner decision of 2026-11-06): the routes of the pass stay the four text routes, and the one-time video showcase with MiniMax H3 is removed from both units. Owner decision D12: design it after Phase 3 (tests/expiry.sh) passes on the units.

**Context:** A model still needs its own recipe: on a DGX Spark many models need a specific image, quantization or patch (Qwen needed the shard-35 prefetch and the management interface; GLM-5.3-Flash runs about 1.7 times as fast on TensorFold as on vLLM). The thinking tip of the pass text describes the TensorFold boot model (src/grant.rs); a profile would carry it.

**Effort:** M
**Priority:** P2 (after milestone 1)
**Depends on:** nothing more (Phase 3 passed on the units on 2026-10-15).

### Compare TensorFold 1104 with the vLLM recipe

**What:** Run the same checks on both engines, at temperature 0 and with the same thinking setting: quality (lm-eval-harness GSM8K, IFEval, and HumanEval in a container, because it runs the generated code), 10 to 15 coding tasks in an agent on a scratch copy of a repository (pass or fail, time, broken tool calls), and the speed of the vLLM recipe with the recipe's `docs/speed/harness/bench2.py` (TensorFold: README). Then choose the draft model for a pass with commercial use (`DRAFTER=mtp`), and measure it.

**Why:** EXL3 at 4 bits is a different quantization from the FP4 checkpoint of NVIDIA, and no check compared the answers. The default draft model of TensorFold (DFlash2) is CC BY-NC-ND 4.0.

**Effort:** M (4 to 6 hours of runs)
**Priority:** P2
**Depends on:** a gap between passes: each engine switch leaves no model for about 5 minutes, and the runs take all 8 slots.

### No restart after a stop of the memory guard

**What:** The memory guard of the TensorFold `start.sh` stops the model when a unit stays under 2.5 GiB free. sparkpass-model.service is a oneshot unit, so it stays active (exited), and nothing starts the model until a reboot or `systemctl restart sparkpass-model.service`; reconcile sends the notification of a model outage. One way: reconcile restarts sparkpass-model.service after several failed health checks in a row, with a limit, so that a memory leak cannot hide behind a restart loop.

**Why:** A guest has no model until the owner acts. The vLLM recipe has the same gap when its server stops.

**Effort:** S
**Priority:** P3
**Depends on:** nothing.

## Setup

### One setup command for other owners

**Status (2026-10-15):** done: `setup.sh` (owner decision D15). Proven only by a second run on spark-3 and spark-4, where each step found its work done. A first run on a fresh pair is not proven.

**What:** A `setup.sh` on the head unit that runs the steps of "Set up the pair" in README.md in order: the sparkrun install and its setup commands (SSH between the units, the Docker group, earlyoom), linger on both units, `sparkrun run templates/pair.yaml`, `install.sh`, and the Funnel procedure that install.sh prints. It cannot change the tailnet, so it checks the three admin settings from the unit with no API token and stops with the console link when one is missing: `tailscale status --json` shows the certificate name in `CertDomains` (HTTPS on), `funnel` in `Self.CapMap` (the node attribute), and no `KeyExpiry` in `Self` (key expiry off; checked on spark-3, 2026-10-14). It also stops when `/proc/cmdline` of a 7.0 kernel has no `kho=off`, and it names the licence clause before it starts the model.

**Why:** The first setup on spark-3 and spark-4 (2026-10-14) took about 15 separate steps: three admin settings, five sparkrun and host commands on two units, the self-SSH of the head, and checks of the kernel and the licence. An owner without that history gets stuck on them.

**Context:** Owner decision D7 of 2026-10-14: document the commands now (README.md, "Set up the pair") and write the script only after milestone 1, because the firewall, install.sh, the Funnel procedure and tests/expiry.sh are not proven on the units yet, and a script of unproven steps needs a rewrite. This changes Premise 1 of the design ("Own pair only. No installer for other owners in this build"), so change the premise in the same branch. `sparkrun setup wizard --hosts <head>,<worker>` does the SSH, Docker group, sudoers and earlyoom steps in one call, but it asks questions; the first setup ran the separate sparkrun commands instead, and the wizard is not tested on the units.

**Effort:** M
**Priority:** P2: prove it on the second pair (owner decisions D24 = the owner runs the README as a new user, D25 = a new Tailscale account). Waiting for: the address of each unit, the user name, and the Mac's SSH key on both units. Rules of the run: follow only the README, fix the repo (not the unit) at each stop, then a 2m pass from outside and a reboot.
**Depends on:** Milestone 1 proven on the units (done).

### Power for the pair

**What:** A UPS for both units (and the router), or at least a note in the pass text of the risk.

**Why:** Both units share one power source. Cuts from the boot logs (both units at the same minute, no shutdown lines): 2026-10-15 07:03 (about 1 min), 2026-10-16 07:20 (about 8 min), 2026-10-16 20:32 (about 1 min), 2026-10-18 06:53 (about 45 min, during a pass: the boot path brought GLM back at 07:46, so the guest had no model for about 53 min), 2026-10-21 00:10 (about 15 min, no pass), 2026-10-24 about 09:57, 2026-11-02 21:28 (about 8 min; no model started, because sparkpass-model.service had been disabled by hand), 2026-11-06 17:20 (about 1 min, during a pass: the TensorFold boot model answered at 17:23:34). The units come back by themselves, but an active pass loses the time, and the end time does not move. After the cut of 2026-11-06, spark-4 stayed off the tailnet: it uses Wi-Fi (its Ethernet port has no cable), its Wi-Fi got no address while the router started, and NetworkManager stopped trying. The model was not affected (it uses the ConnectX-7 link), but SSH to spark-4 over the tailnet was. Cable spark-4, or set its Wi-Fi connection to retry forever (`nmcli connection modify <name> connection.autoconnect-retries 0`).

**Sizing (estimate, not measured):** each unit has a 240 W adapter; plan 300 to 500 W with the router, pure sine output. 15 min covers each known cut except the 45-minute one (the length of the cut of 2026-10-24 is not known); that one needs about 1 h at 400 W, about 400 Wh usable (in Nepal, a home inverter with a 150 Ah battery). Measure the real draw with a plug-in meter. Three of the cuts came between 06:53 and 07:20: ask whether they are scheduled.

**Effort:** hardware
**Priority:** P2
**Depends on:** nothing.

## Completed

The completed items (21 items, 2026-10-06 to 2026-10-13) are in `git show d3ea640:TODOS.md` and in the merged pull requests.

- **One real NOTIFY_URL message** (2026-10-21): after the power cut of 2026-10-21, the boot run of reconcile sent its serve-config message through NOTIFY_URL (an ntfy topic), and it reached the owner. The message was a false alarm, fixed by the wait for tailscaled (owner decisions D4 and D5).
- **Claude Code through the gateway** (2026-11-06, branch feat/tf1104-boot-and-messages-route): POST /v1/messages is a route of the pass (gateway/Caddyfile, the pass text, tests/gateway.sh with the `?beta=true` URL of Claude Code, tests/expiry.sh), and the pass text gives the settings of Claude Code. Claude Code 2.1.302 completed a task with a tool call against TensorFold 1104 through the SSH tunnel. (Done in code; the proof is a run through Funnel with a pass key.)
- **The TensorFold boot model in the repository** (2026-11-06, same branch): README "The boot model: TensorFold 1104", `systemd/sparkpass-model-tf1104.conf` and `templates/tf1104-local.sh`; the pass text says that GLM thinks only when a request asks for it.
