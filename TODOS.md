# TODOS

## Pass tool

### Read the clock again after the lock

**What:** In `reconcile` (and in `grant`), read the system clock after `paths.lock()` returns, and use that value to sort the leases into overdue and active, and to compute `--on-active` and the deadline.

**Why:** `main` reads the clock before the lock wait. After a wait of up to about 2 minutes, a lease whose deadline passed during the wait counts as active: reconcile creates a timer from the stale time and starts Caddy, which serves an expired key until the timer fires. In grant, the same wait shortens the guest's TTL.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Codex structured review [P1] at src/reconcile.rs:46-48, Codex adversarial, and the Claude adversarial pass found it independently; the owner chose to land it before the first guest (D10). Today only `main` reads the clock ("Only main reads the system clock" in src/time.rs); the fix needs a clock parameter (for example `now: &dyn Fn() -> u64`) for `grant` and `reconcile`, with a test that advances the clock during the lock wait.

**Effort:** S
**Priority:** P1 (before the first guest)
**Depends on:** None

### Grant checks that the end-timer binary exists and runs

**What:** In grant step 1, run `/usr/local/bin/sparkpass list` (through the runner) and refuse the grant if it fails.

**Why:** The end timer always runs `/usr/local/bin/sparkpass revoke <name>`. If the owner runs a build from target/release before install, or the installed file is an old build, the timer fails at the deadline with 203/EXEC, and the key stays live; grant still prints the pass.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Claude adversarial pass, src/lease.rs:178 and src/config.rs:9 (`BINARY`). The owner chose to land it before the first guest (D10). A FakeRunner test covers the refusal.

**Effort:** S
**Priority:** P1 (before the first guest)
**Depends on:** None

### The self-check with the real key requires HTTP 200

**What:** Make the first self-check request use `-w %{http_code}` and require `200`, as the wrong-token request does.

**Why:** `curl -f` exits with 0 for a redirect or a 204, so grant can hand out a pass while `/v1/models` does not serve the model.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Codex structured [P2] and Codex adversarial, src/grant.rs:98-99. The owner chose P1 (D10). Combine with the TODO "One curl helper for both self-check requests".

**Effort:** S
**Priority:** P1 (before the first guest)
**Depends on:** None

### Correct the old revoke step numbers in four comments

**What:** The deny-all write is revoke step 1, the restart step 2, the timer stop step 3. Correct src/gateway.rs:66-73 (doc and inline comments of `close`), src/revoke.rs:25 (`closed` parameter), src/lease.rs:205 (`stop_end_timer`), src/reconcile.rs:83.

**Why:** The order was changed in the ship review; these comments still describe the old order, in the modules where the step order is the safety property.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): maintainability, cycle 3 (confidence 9). Comments only; no test changes.

**Effort:** S
**Priority:** P1
**Depends on:** None

### Make reconcile run the token-file check before step 3

**What:** Run the two token-file checks (a rule with no lease; an active lease whose file is not its rule) directly after the overdue leases are revoked, independent of later failures.

**Why:** When the timer check or `systemd-run` in step 3 fails, reconcile returns early, and an empty or cut token file stays while a running Caddy serves; the check is skipped on each run until step 3 succeeds.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): red team, cycle 3, src/reconcile.rs:69. Test: an active lease with an empty token file and a timer check that hangs; the deny-all write and try-restart still run.

**Effort:** S
**Priority:** P2
**Depends on:** None

### Revoke must not trust an earlier cut for a REVOKE-FAILED lease

**What:** In `revoke()`, close the gateway again when the lease state is `revoke-failed`, also when `closed` is true.

**Why:** `closed` proves only this process's own close. A lease that is already REVOKE-FAILED can hold a token that an earlier failed close left live; a revoke with `closed = true` then deletes the lease and the mark, and reconcile never cuts the token.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): red team, cycle 3, src/revoke.rs:89 (confidence 3).

**Effort:** S
**Priority:** P2
**Depends on:** None

### Bind a revoke to the lease that it was made for

**What:** Give the end timer the deadline that it was created for (for example an internal `revoke <name> --deadline <unix seconds>`), and make that call a no-op when the lease file has a different deadline. Also make the close before the lock in `revoke <name>` safe against a lease that another revoke and a new grant replaced in the meantime.

**Why:** A delayed end-timer service can revoke a new lease of the same name; and a close before the lock can overwrite a replacement guest's new token. Both fail closed (a guest loses access early), but the owner holds a pass that does not work.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Codex structured [P2] src/lease.rs:178-180 and src/revoke.rs:78-82; the red team reported the timer case in cycles 1 and 2.

**Effort:** M
**Priority:** P2
**Depends on:** None

### One history record for each lease, also after a partial commit

**What:** Give a failed lease-file delete its own error text, sync the lease directory after the delete, and make a retried revoke reuse the history record of the first try instead of a new `-N` record.

**Why:** If the directory sync after the history rename fails, or the delete of the lease file fails, the retry writes a second record of the same lease, possibly with a different end time.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Codex adversarial [P2] src/lease.rs:77 and the Claude adversarial pass src/revoke.rs:51-53. Access is not affected.

**Effort:** S
**Priority:** P2
**Depends on:** None

### Two test gaps from the cycle-3 review

**What:** (1) A row in `token_file_that_is_not_the_rule_of_the_active_lease_is_closed_before_the_gateway_starts` with a directive after the complete rule (`<rule>respond 200\n`). (2) Pin the `state` and `end` fields of the history record after a retried revoke in `failed_timer_stop_gives_revoke_failed_and_the_gateway_still_closes`.

**Why:** A relaxed `is_rule_of` (`starts_with`) and a change of the record contract pass the suite today.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): testing specialist, cycle 3, src/reconcile.rs:253 and src/revoke.rs:179.

**Effort:** S
**Priority:** P2
**Depends on:** None

### Smaller hardening items from the adversarial review

**What:** (1) Use `writeln!` on a locked stdout in `main`; on error, tell the owner that the lease is active with no printed pass and give the revoke command. (2) Make `-q` the first argument of each curl call, so that root's `~/.curlrc` cannot add `--insecure`, `--proxy`, or `-L`. (3) In `revoke <name>`, treat a token file that holds that name's rule as "the lease exists". (4) Send the wrong-token probe also as `POST /v1/chat/completions`. (5) Bound the output that `RealRunner` keeps in memory.

**Why:** Each closes a small failure mode: a panic after a complete grant; a self-check that root's curl config changes; a key that stays live when the lease file is lost; a token rule on only some routes; memory exhaustion by a broken command.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Claude adversarial pass (items 3, 4, 5, 7) and Codex adversarial (unbounded output). src/main.rs:87, src/grant.rs:70/98/108, src/revoke.rs:78, src/runner.rs:108.

**Effort:** M
**Priority:** P3
**Depends on:** None

### One curl helper for both self-check requests

**What:** One closure that runs `curl -sS -o /dev/null -m <limit> -w %{http_code} -H "Authorization: Bearer <value>" <url>` and returns the status, for the real key and the wrong key.

**Why:** The two match blocks in `hand_out` repeat the same error handling; one helper is about 6 lines shorter.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): simplification (advisory), src/grant.rs:98. Do it together with "The self-check with the real key requires HTTP 200".

**Effort:** S
**Priority:** P3
**Depends on:** None

### Owner notification

**What:** Send a push message to the owner when a lease becomes `REVOKE-FAILED` or when the model endpoint is down during an active lease.

**Why:** The guest sees 503 until the owner restarts the model by hand, and the owner does not know. A guest can lose hours of a 24-hour slot.

**Context:** From the eng review of 2026-10-05 (finding A-3, decision D12). Revoke already cuts access first and retries each 5 minutes, so safety does not depend on this item. The faults show only in the journal and in `pass list`. Start at `systemd/pass-reconcile.service`: add an `OnFailure=` unit that sends one message, plus a health-check timer for the model endpoint during a lease. It needs a message channel and its secret (for example ntfy or a chat webhook).

**Effort:** S
**Priority:** P3
**Depends on:** Build phase 1 complete (API-only pass works).

### Stronger erase of guest data

**What:** Encrypt the home image of each lease (LUKS) with a random key that revoke discards, and restart the model server between guests.

**Why:** After a plain delete, the guest's files stay in the storage blocks, and recent prompts can stay in the memory of the model server.

**Context:** From the eng review of 2026-10-05 (outside-voice finding O-4, decision D13). The pass text now tells the guest that the delete is not a secure erase. The key must survive a reboot inside an active lease, or the guest's data is lost; decide where it lives before you build. A model restart costs 11 to 13 minutes of load time for each guest. Start at "pass grant" step 5 and "pass revoke" step 5 in `docs/designs/guest-pass-mvp.md`.

**Effort:** M
**Priority:** P3
**Depends on:** Build phase 2 complete (the home image exists).

## Gateway (Caddyfile step)

### Fail closed when the gateway does not enforce the token file

**What:** When the wrong-token self-check gets an answer other than 401, stop Caddy (not only revoke), and say in the error that the Caddyfile must be repaired before reconcile. In reconcile, after `systemctl start caddy`, send the same wrong-token request through PUBLIC_URL and stop Caddy on any answer other than 401 (reconcile then reads the settings file and fails closed without it). Write the Caddyfile so that it refuses each request when the import holds no rule.

**Why:** A gateway that does not import the token file is open to all. Today grant only revokes, which cannot close such a gateway, and reconcile starts Caddy with no proof; a stop alone holds only until the next reconcile, at most 5 minutes.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): security CRITICAL (confidence 6) at src/grant.rs:110 and red team at src/reconcile.rs:92, cycle 3; the 401 probe in reconcile was also proposed in cycle 1 (D7 item 6, skipped then because a public-route outage would stop the gateway every 5 minutes; decide that trade-off with the Caddyfile). The owner chose P1 for the Caddyfile step (D9). Prove the 401 on the units with tests/expiry.sh.

**Effort:** M
**Priority:** P1 (before the first guest)
**Depends on:** The Caddyfile and the systemd units (plan steps A1 and C1).

## CI

### Least privilege and provenance for the release binary

**What:** Add `permissions: contents: read` to .github/workflows/ci.yml, and publish a sha256 or a build-provenance attestation with the artifact.

**Why:** The job token gets the repository default, which can be write, and the binary runs as root on the units with no checksum.

**Context:** From the /ship review of 2026-10-06 (branch feat/api-only-pass): Claude adversarial pass, item 8.

**Effort:** S
**Priority:** P3
**Depends on:** None

## Completed
