# TODOS

## Pass tool

### Stronger erase of guest data

**What:** Encrypt the home image of each lease (LUKS) with a random key that revoke discards, and restart the model server between guests.

**Why:** After a plain delete, the guest's files stay in the storage blocks, and recent prompts can stay in the memory of the model server.

**Context:** From the eng review of 2026-10-05 (outside-voice finding O-4, decision D13). The pass text now tells the guest that the delete is not a secure erase. The key must survive a reboot inside an active lease, or the guest's data is lost; decide where it lives before you build. A model restart costs 11 to 13 minutes of load time for each guest. Start at "pass grant" step 5 and "pass revoke" step 5 in `docs/designs/guest-pass-mvp.md`.

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

**What:** On the head unit, after milestone 1 (firewall/rules.sh, the settings): run `sudo ./install.sh`, follow the Tailscale Funnel procedure that it prints (TS_PERMIT_CERT_UID=caddy, `tailscale set --accept-dns=false`, `tailscale funnel --bg --tcp=443 tcp://127.0.0.1:443`, one `tailscale cert`), fill /etc/sparkpass/config and caddy.env, and run `sudo tests/expiry.sh --stub`, `sudo tests/expiry.sh`, and `sudo tests/expiry.sh --via-public`. Then the manual checks that the script prints: a reboot inside an active lease, a boot with no network (the gateway stays closed), and the certificate from tailscaled and the route of Funnel. Also: `gh attestation verify sparkpass -R hussu010/sparkpass` on the CI binary; one real `NOTIFY_URL` message (for example a REVOKE-FAILED test lease); `systemctl show -p After multi-user.target` for the chrony-wait drop-in (with no network the boot waits for the clock); `systemctl reload caddy` over the admin socket with the Ubuntu package, as the caddy user (grant step 7 does it): that package is 2.6.2 rebuilt with Go 1.22, and the Docker image caddy:2.6.2 of tests/gateway.sh has Go 1.19.2 (Go changed the Host header of a request to a unix socket in 1.20.6; Go 1.22 sends an empty Host, which the admin API of 2.6.2 accepts); the self-check of grant step 8 through a relay of Funnel (accept-dns off) and a check from an outside network; the first handshake with a certificate that tailscaled must order (within the 8-second limit of the reconcile check, or the `tailscale cert` step is required); list the `/v1` routes of the pinned model server with its flags (runtime LoRA load and unload, a stored Responses API, file or batch upload), and check that the five routes outside the pass in tests/expiry.sh cover the routes that change state, because a guest can change state that the next guest or the host sees (owner decision D14); and prove on the unit that a `systemctl try-restart caddy` of the end timer's revoke, sent while reconcile's `systemctl start caddy` is still activating, restarts Caddy after the start (systemd 240 and later collapse a try-restart of an activating unit into a restart; then the old key gets 401 at once; owner decision D17, from Codex round 3).

**Why:** The Caddyfile is proven in Docker, and the tool with fakes, but only the units prove systemd, the caddy package, the inbound path (Tailscale Funnel and the certificate from tailscaled), the stream cut within 15 seconds, and the boot gate.

**Context:** Split from "Fail closed when the gateway does not enforce the token file" (TODO batch 2 of 2026-10-06). The review notes of the batch are in the PR of the branch. The code parts landed on branch feat/tunnel-and-p1-code (2026-10-07), with the owner decisions of that day: the inbound method is Tailscale Funnel with raw TCP passthrough (TLS ends at Caddy, the certificate comes from tailscaled, Caddy listens on 127.0.0.1 only and has no port-80 listener, and the access log keeps no client address); the admin API is on `unix//run/caddy/admin.sock` with `RuntimeDirectory=caddy` (the reloads of tests/gateway.sh go over the socket, on 2.6.2 and 2.11); a guest key reaches only GET /v1/models, POST /v1/chat/completions and POST /v1/completions, and each other route gets the gateway's 404 (D14); reconcile reads `systemctl show -p ActiveState --value caddy` after a failed step (activating and deactivating stop Caddy); `GATEWAY_CHECK_ADDRESS` must be a loopback address (rule 3 of the completed item "Fail closed when the gateway does not enforce the token file"); and grant step 8 confirms an answer other than 401 of the public route through the loopback check before it writes the marker.

**Effort:** M
**Priority:** P1 (before the first guest)
**Depends on:** Milestone 1 (Next Steps 1 to 3 of the design: the model on the pair, the Funnel setup, firewall/rules.sh).

## Completed

### Read the clock again after the lock

**What:** In `reconcile` (and in `grant`), read the system clock after `paths.lock()` returns, and use that value to sort the leases into overdue and active, and to compute `--on-active` and the deadline.

**Why:** `main` reads the clock before the lock wait. After a wait of up to about 2 minutes, a lease whose deadline passed during the wait counts as active: reconcile creates a timer from the stale time and starts Caddy, which serves an expired key until the timer fires. In grant, the same wait shortens the guest's TTL.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Codex structured review [P1] at src/reconcile.rs:46-48, Codex adversarial, and the Claude adversarial pass found it independently; the owner chose to land it before the first guest (D10). Today only `main` reads the clock ("Only main reads the system clock" in src/time.rs); the fix needs a clock parameter (for example `now: &dyn Fn() -> u64`) for `grant` and `reconcile`, with a test that advances the clock during the lock wait.

**Effort:** S
**Priority:** P1 (before the first guest)
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06). Grant takes the deadline from one clock read after the lock and after the checks of step 1, and checks the clock again before step 7; reconcile reads the clock after the lock, through a wrapper that never goes back within one run.

### Grant checks that the end-timer binary exists and runs

**What:** In grant step 1, run `/usr/local/bin/sparkpass list` (through the runner) and refuse the grant if it fails.

**Why:** The end timer always runs `/usr/local/bin/sparkpass revoke <name>`. If the owner runs a build from target/release before install, or the installed file is an old build, the timer fails at the deadline with 203/EXEC, and the key stays live; grant still prints the pass.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Claude adversarial pass, src/lease.rs:178 and src/config.rs:9 (`BINARY`). The owner chose to land it before the first guest (D10). A FakeRunner test covers the refusal.

**Effort:** S
**Priority:** P1 (before the first guest)
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06). Grant runs the end-timer call itself (`sparkpass revoke <name> --deadline 0`), so an old build that refuses `--deadline` is also refused.

### The self-check with the real key requires HTTP 200

**What:** Make the first self-check request use `-w %{http_code}` and require `200`, as the wrong-token request does.

**Why:** `curl -f` exits with 0 for a redirect or a 204, so grant can hand out a pass while `/v1/models` does not serve the model.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Codex structured [P2] and Codex adversarial, src/grant.rs:98-99. The owner chose P1 (D10). Combine with the TODO "One curl helper for both self-check requests".

**Effort:** S
**Priority:** P1 (before the first guest)
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06).

### Correct the old revoke step numbers in four comments

**What:** The deny-all write is revoke step 1, the restart step 2, the timer stop step 3. Correct src/gateway.rs:66-73 (doc and inline comments of `close`), src/revoke.rs:25 (`closed` parameter), src/lease.rs:205 (`stop_end_timer`), src/reconcile.rs:83.

**Why:** The order was changed in the ship review; these comments still describe the old order, in the modules where the step order is the safety property.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): maintainability, cycle 3 (confidence 9). Comments only; no test changes.

**Effort:** S
**Priority:** P1
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06).

### Make reconcile run the token-file check before step 3

**What:** Run the two token-file checks (a rule with no lease; an active lease whose file is not its rule) directly after the overdue leases are revoked, independent of later failures.

**Why:** When the timer check or `systemd-run` in step 3 fails, reconcile returns early, and an empty or cut token file stays while a running Caddy serves; the check is skipped on each run until step 3 succeeds.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): red team, cycle 3, src/reconcile.rs:69. Test: an active lease with an empty token file and a timer check that hangs; the deny-all write and try-restart still run.

**Effort:** S
**Priority:** P2
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06).

### Revoke must not trust an earlier cut for a REVOKE-FAILED lease

**What:** In `revoke()`, close the gateway again when the lease state is `revoke-failed`, also when `closed` is true.

**Why:** `closed` proves only this process's own close. A lease that is already REVOKE-FAILED can hold a token that an earlier failed close left live; a revoke with `closed = true` then deletes the lease and the mark, and reconcile never cuts the token.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): red team, cycle 3, src/revoke.rs:89 (confidence 3).

**Effort:** S
**Priority:** P2
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06).

### Bind a revoke to the lease that it was made for

**What:** Give the end timer the deadline that it was created for (for example an internal `revoke <name> --deadline <unix seconds>`), and make that call a no-op when the lease file has a different deadline. Also make the close before the lock in `revoke <name>` safe against a lease that another revoke and a new grant replaced in the meantime.

**Why:** A delayed end-timer service can revoke a new lease of the same name; and a close before the lock can overwrite a replacement guest's new token. Both fail closed (a guest loses access early), but the owner holds a pass that does not work.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Codex structured [P2] src/lease.rs:178-180 and src/revoke.rs:78-82; the red team reported the timer case in cycles 1 and 2.

**Effort:** M
**Priority:** P2
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06). The close before the lock can still cut a new key of the SAME name in a narrow window; the ponytail comment in src/revoke.rs names it, and the reconcile dead-key gate revokes that lease.

### One history record for each lease, also after a partial commit

**What:** Give a failed lease-file delete its own error text, sync the lease directory after the delete, and make a retried revoke reuse the history record of the first try instead of a new `-N` record.

**Why:** If the directory sync after the history rename fails, or the delete of the lease file fails, the retry writes a second record of the same lease, possibly with a different end time.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Codex adversarial [P2] src/lease.rs:77 and the Claude adversarial pass src/revoke.rs:51-53. Access is not affected.

**Effort:** S
**Priority:** P2
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06).

### Two test gaps from the cycle-3 review

**What:** (1) A row in `token_file_that_is_not_the_rule_of_the_active_lease_is_closed_before_the_gateway_starts` with a directive after the complete rule (`<rule>respond 200\n`). (2) Pin the `state` and `end` fields of the history record after a retried revoke in `failed_timer_stop_gives_revoke_failed_and_the_gateway_still_closes`.

**Why:** A relaxed `is_rule_of` (`starts_with`) and a change of the record contract pass the suite today.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): testing specialist, cycle 3, src/reconcile.rs:253 and src/revoke.rs:179.

**Effort:** S
**Priority:** P2
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06).

### Smaller hardening items from the adversarial review

**What:** (1) Use `writeln!` on a locked stdout in `main`; on error, tell the owner that the lease is active with no printed pass and give the revoke command. (2) Make `-q` the first argument of each curl call, so that root's `~/.curlrc` cannot add `--insecure`, `--proxy`, or `-L`. (3) In `revoke <name>`, treat a token file that holds that name's rule as "the lease exists". (4) Send the wrong-token probe also as `POST /v1/chat/completions`. (5) Bound the output that `RealRunner` keeps in memory.

**Why:** Each closes a small failure mode: a panic after a complete grant; a self-check that root's curl config changes; a key that stays live when the lease file is lost; a token rule on only some routes; memory exhaustion by a broken command.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Claude adversarial pass (items 3, 4, 5, 7) and Codex adversarial (unbounded output). src/main.rs:87, src/grant.rs:70/98/108, src/revoke.rs:78, src/runner.rs:108.

**Effort:** M
**Priority:** P3
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06). Each curl call also has `--noproxy *`.

### One curl helper for both self-check requests

**What:** One closure that runs `curl -sS -o /dev/null -m <limit> -w %{http_code} -H "Authorization: Bearer <value>" <url>` and returns the status, for the real key and the wrong key.

**Why:** The two match blocks in `hand_out` repeat the same error handling; one helper is about 6 lines shorter.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): simplification (advisory), src/grant.rs:98. Do it together with "The self-check with the real key requires HTTP 200".

**Effort:** S
**Priority:** P3
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06).

### Least privilege and provenance for the release binary

**What:** Add `permissions: contents: read` to .github/workflows/ci.yml, and publish a sha256 or a build-provenance attestation with the artifact.

**Why:** The job token gets the repository default, which can be write, and the binary runs as root on the units with no checksum.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Claude adversarial pass, item 8.

**Effort:** S
**Priority:** P3
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest (2026-10-06). The sha256 shares the artifact with the binary; see the completed item "Build-provenance attestation for the release binary".

### Owner notification

**What:** Send a push message to the owner when a lease becomes `REVOKE-FAILED` or when the model endpoint is down during an active lease.

**Why:** The guest sees 503 until the owner restarts the model by hand, and the owner does not know. A guest can lose hours of a 24-hour slot.

**Context:** From the eng review of 2026-10-05 (finding A-3, decision D12). Revoke already cuts access first and retries each 5 minutes, so safety does not depend on this item. The faults show only in the journal and in `pass list`. Start at `systemd/pass-reconcile.service`: add an `OnFailure=` unit that sends one message, plus a health-check timer for the model endpoint during a lease. It needs a message channel and its secret (for example ntfy or a chat webhook).

**Effort:** S
**Priority:** P3
**Depends on:** Build phase 1 complete (API-only pass works).
**Completed:** branch fix/todos-before-first-guest, TODO batch 2 (2026-10-06). Grant, revoke and reconcile POST one plain-text message to the optional `NOTIFY_URL` of /etc/sparkpass/config (owner decision D3): a lease that becomes REVOKE-FAILED, a model outage during a lease and its end (one message each, through the marker /var/lib/sparkpass/model-down), a gateway that reconcile stops or does not start during a lease and its next start (marker gateway-down, added in the /ship review), and a gateway proven open. In-process, not an OnFailure= unit. Proof with a real topic: see "Prove the gateway step on the units".

### Exact end timers in reconcile after a backward clock step

**What:** Count the `--on-active` time of an end timer that reconcile creates again from a monotonic source (for example `std::time::Instant` in the production clock of main.rs), not from the wall clock.

**Why:** A backward clock step during reconcile steps 1 to 3 adds their time (at most about 20 seconds) to the end of such a timer. The design text names this as the one exception to "an open stream ends not later than 15 seconds after the deadline".

**Context:** From the /ship adversarial review of 2026-10-06 (Codex adversarial P2, verified by a skeptic). Grant has no such gap: it takes the deadline from one clock read after its checks, and `--on-active` is at most the TTL minus the time of its lease write (a clock read right before systemd-run; /ship review of batch 2). Reconcile keeps a monotonic wrapper over the injected clock for one run (src/reconcile.rs), so a test clock stays possible.

**Effort:** S
**Priority:** P3
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest, TODO batch 2 (2026-10-06). The production clock of main.rs is steady: never earlier than its first read plus the time since then (`Instant`), so a backward clock step cannot move an end later in any command.

### The access cut waits for the sync of the token file

**What:** In `gateway::close`, restart Caddy before the fsync of the deny-all file, or give the sync a time limit.

**Why:** `write_rule` calls `sync_all` before `systemctl try-restart caddy`, and that sync has no time limit. On ext4 a journal commit that carries other dirty data (a model download, guest writes in phase 2) can delay the access cut past the 15-second bound, and a stalled device blocks it in D state, where systemd cannot kill the process.

**Context:** From the /ship adversarial review of 2026-10-06, second round (Claude adversarial, INVESTIGATE); the order existed before branch fix/todos-before-first-guest. The boot gate of reconcile already handles each token-file state after a power cut, so the sync before the restart adds little safety. Decide the durability trade-off first.

**Effort:** S
**Priority:** P3
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest, TODO batch 2 (2026-10-06). `gateway::close` restarts Caddy before the fsync of the deny-all file (owner decision D4); a failed sync is an error, so the lease stays REVOKE-FAILED and reconcile closes again.

### Keep a gateway stopped after proof that it is open

**What:** On a proven answer other than 401 to a wrong token (grant step 8 or the reconcile check), write a marker file under /var/lib/sparkpass. Reconcile does not start Caddy while the marker exists (or while its check fails), and names the file to remove after the Caddyfile repair. A curl failure writes no marker.

**Why:** Today each reconcile after such a stop runs start, check, stop: the gateway is open to all for each check window, every 5 minutes, until the owner repairs the Caddyfile. If `PUBLIC_URL` and `GATEWAY_CHECK_ADDRESS` reach different listeners, reconcile starts a gateway that grant proved open and returns success.

**Context:** From the /ship reviews of 2026-10-06: red team cycle 1, Claude adversarial (its top recommendation), verified by a skeptic in a scratch copy. About 20 code lines and 15 test lines. Write the repair step into the Caddyfile item above.

**Effort:** S
**Priority:** P1 (before the first guest)
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest, TODO batch 2 (2026-10-06). The marker /var/lib/sparkpass/gateway-open (with the evidence) is written on a proven non-401 answer in grant step 1, grant step 8 and the reconcile check; reconcile keeps Caddy stopped and grant refuses while it exists; a notification goes out.

### Grant also checks through GATEWAY_CHECK_ADDRESS

**What:** In grant step 1 (or step 8), also send the reconcile check (`--connect-to` to `GATEWAY_CHECK_ADDRESS`) and refuse the grant when it fails.

**Why:** Grant proves the gateway only through `PUBLIC_URL`. With a wrong check address, grant prints a pass, and the next reconcile stops the gateway for the whole lease.

**Context:** From the /ship review of 2026-10-06, red team cycle 1 (confidence 5). It adds two commands to grant: raise `HAND_OUT_TIME` or count them in step 1.

**Effort:** S
**Priority:** P1 (before the first guest)
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest, TODO batch 2 (2026-10-06). Grant step 1 sends the reconcile check after the check that Caddy runs; a failure stops Caddy and refuses.

### Reconcile checks a running Caddy also after a failed step

**What:** When an earlier reconcile step failed, still send the wrong-token check if `systemctl is-active caddy` succeeds, and stop Caddy on an answer other than 401. Keep the rule "no start and no stop" for all other failures.

**Why:** A failure that repeats on each run (for example a REVOKE-FAILED lease whose timer stop fails) stops the only periodic proof of the gateway, and a gateway that answers 200 to a wrong key stays up.

**Context:** From the /ship review of 2026-10-06, red team cycle 2 (confidence 5), at the early return before the start in src/reconcile.rs. It changes the design rule of reconcile step 4.

**Effort:** S
**Priority:** P1 (before the first guest)
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest, TODO batch 2 (2026-10-06). After a failed step, a Caddy that runs gets the same check, and a failed check stops it.

### Build-provenance attestation for the release binary

**What:** Add `actions/attest-build-provenance` (pinned SHA, `subject-path: target/release/sparkpass`, job permissions `id-token: write` and `attestations: write`), and verify on the unit with `gh attestation verify sparkpass -R hussu010/sparkpass`. Optional: `sha256sum sparkpass | tee sparkpass.sha256`, so that the hash is also in the job log.

**Why:** The sha256 file shares the artifact with the binary: it finds a corrupt download, not a changed artifact.

**Context:** From the /ship adversarial review of 2026-10-06 (Claude adversarial, verified). Do it when the CI binary becomes the install path on the units.

**Effort:** S
**Priority:** P3
**Depends on:** None
**Completed:** branch fix/todos-before-first-guest, TODO batch 2 (2026-10-06). CI has a separate release job (push to main only) with `id-token: write` and `attestations: write`, `actions/attest-build-provenance` v4.2.2 (pinned SHA), and the sha256 also in the job log (tee). The check `gh attestation verify` on the unit is part of "Prove the gateway step on the units".

### Fail closed when the gateway does not enforce the token file

**What:** Write the Caddyfile so that it refuses each request when the import holds no rule, and prove it on the units with tests/expiry.sh. Acceptance rules for this step:
1. Import the token file once, as the first line inside one top-level `route { }` block that holds all the routing (for example `route { import /etc/sparkpass/token.caddy; reverse_proxy /v1/* 127.0.0.1:<MODEL_PORT>; respond 404 }`). A per-route or per-`handle` import leaves other paths of the model server open (`/invocations`, `/tokenize`, `/metrics`, `/v1/completions`) while both wrong-token checks get 401.
2. The caddy unit starts with `caddy run --environ --config <Caddyfile>`, never with `--resume`, which loads the last autosaved config and not the Caddyfile.
3. `GATEWAY_CHECK_ADDRESS` reaches the same site block as `PUBLIC_URL` on THIS host: a loopback or a local address, never the other Spark, because its 401 answers would make reconcile trust a local Caddy that is open. Consider a check in `read_settings` (a loopback address, or one that `ip -o addr` lists). Upgrade order: set the key in /etc/sparkpass/config before you install this build, at a time with no active lease. Without it, reconcile keeps Caddy stopped (an active guest loses access) and grant refuses.
4. The ACME procedure for the first certificate and for a host that was off past the end of its certificate: stop pass-reconcile.timer, start caddy, wait for the certificate, start the timer, run `sparkpass reconcile`. Include first issuance in the tests/expiry.sh proof.
5. Extend tests/expiry.sh: during an active lease, a wrong token to `/v1/completions`, `/invocations`, `/tokenize`, `/metrics` and a path outside `/v1` gets 401; after a grant and a revoke, the old token gets 401.

**Why:** A gateway that does not import the token file is open to all. The code part is done (see Context), but only the Caddyfile and the unit decide what the gateway enforces.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): security CRITICAL (confidence 6) at src/grant.rs:110 and red team at src/reconcile.rs:92, cycle 3. The code part landed on branch fix/todos-before-first-guest (2026-10-06): grant stops Caddy on any self-check failure, and reconcile sends the same two wrong-token requests after each start through `--connect-to` to `GATEWAY_CHECK_ADDRESS` and stops Caddy on any other answer. Rules 1, 2 and 4 come from the /ship adversarial review of 2026-10-06 (Claude adversarial, Codex adversarial, and a completeness critic), each verified by a skeptic.

**Effort:** M
**Priority:** P1 (before the first guest)
**Depends on:** The Caddyfile and the systemd units (plan steps A1 and C1).
**Completed:** branch fix/todos-before-first-guest, TODO batch 2 (2026-10-06), except the proof on the units. gateway/Caddyfile (rule 1: one route, the import first, then a guard that refuses each request without the pass marker of `gateway::rule`, so an empty or cut token file refuses too), systemd/caddy-sparkpass.conf (rule 2), install.sh (rule 3 upgrade order, the ACME procedure of rule 4), tests/expiry.sh (rule 5). tests/gateway.sh proves the Caddyfile with a real Caddy in Docker, on 2.11 and 2.6.2 (the Ubuntu 24.04 package), in CI too. The proof on the units is the new item "Prove the gateway step on the units". On 2026-10-07, the loopback check of read_settings replaced the "consider" of rule 3, and the Tailscale Funnel procedure of install.sh replaced the ACME procedure of rule 4 (owner decision of that day).
