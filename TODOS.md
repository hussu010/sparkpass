# TODOS

## Pass tool

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

## Completed
