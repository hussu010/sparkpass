# sparkpass

[![ci](https://github.com/hussu010/sparkpass/actions/workflows/ci.yml/badge.svg)](https://github.com/hussu010/sparkpass/actions/workflows/ci.yml)

Time-limited guest API keys for a model that runs on two linked NVIDIA DGX Spark units.

The owner runs one command:

```bash
sudo sparkpass grant alice --ttl 24h
```

The guest gets an OpenAI-compatible endpoint, a key, and a fixed end time. At the end time a systemd timer
removes the key and closes open requests, and the next request gets 401. There is no daemon, no database
and no web page.

## Status

- Works on the author's pair since 2026-10-15. The default recipe, `templates/glm53-flash.yaml`: GLM-5.3-Flash
  (NVIDIA FP4 build) with tensor parallel 2 across the two units, 500,000 tokens of context, up to 4 requests at
  the same time, 23 to 28 tokens/s for one stream. A prompt of 471,835 tokens ran in 229 s. The second tested
  recipe, `templates/pair.yaml` (Qwen3.8-Flash-Next), is faster (see "Run another model").
- API only. The SSH workspace for guests (build phase 2 of the design) is not built.
- One model at a time, and one owner's pair. `setup.sh` has run on one pair only.
- The GLM-5.3-Flash weights permit commercial use (NVIDIA Open Model Agreement; the base model is MIT). The Qwen
  weights of `templates/pair.yaml` are under the Qwen Community License 1.0: its clause 2 ("Model as a Service")
  needs a separate license from Qwen before you charge for a pass.

## How it works

```
guest ──https──> Tailscale Funnel ──raw TCP──> Caddy on 127.0.0.1:443 ──> model on 127.0.0.1:8000
                 (relays, ts.net name)          key check, 4 routes          head unit + worker over
                                                                             the ConnectX-7 link
```

- The model runs across both units. `setup.sh` starts it with [sparkrun](https://pypi.org/project/sparkrun/) and
  vLLM (`templates/glm53-flash.yaml`); the first pair boots the faster TensorFold recipe 1104 instead ("The boot
  model: TensorFold 1104" below). The API listens on the loopback address of the head unit only.
- Tailscale Funnel carries the guest traffic to Caddy with TLS intact. Caddy ends TLS with the certificate
  of the ts.net name, checks the key, and permits `GET /v1/models`, `POST /v1/chat/completions`,
  `POST /v1/completions` and `POST /v1/messages` only. The access log keeps no client address and no prompt.
- `sparkpass grant` creates the end timer before it prints the key, then checks the public route with the
  real key and with a wrong key. Any failure removes the pass.
- `sparkpass reconcile` runs at boot and every 5 minutes. It revokes passes that are past their end time,
  keeps the gateway stopped until the clock is synchronized, loads the firewall, and stops the gateway when
  a wrong key gets an answer other than 401.
- `firewall/rules.sh` lets the control ports of vLLM (which permit code execution) accept connections only
  from the ConnectX-7 link, not from the LAN or the tailnet.

The design, with the reason for each safety rule, is in
[`docs/designs/guest-pass-mvp.md`](docs/designs/guest-pass-mvp.md). Open work is in [`TODOS.md`](TODOS.md).

## Requirements

- Two DGX Spark units (DGX OS, Ubuntu 24.04) with the ConnectX-7 ports cabled back to back, an address on
  that link, and SSH between the units (the cluster setup of NVIDIA Sync does this). Below, `<head-cx7>`
  and `<worker-cx7>` are those addresses, for example `10.100.0.1` and `10.100.0.2`.
- Kernel `7.0.0-1019-nvidia` breaks NCCL over RoCE unless the kernel command line has `kho=off`
  (`cat /proc/cmdline`). NVIDIA's update adds it with `/etc/default/grub.d/nvidia-spark-kho.cfg`.
- A Tailscale account on which you can enable HTTPS certificates and Funnel.
- Wired Ethernet on the head unit: it downloads about 190 GB, and it carries the guest traffic. On the first
  setup, Wi-Fi gave 80 Mb/s and Ethernet 220 Mb/s on the same internet line.

## Set up the pair

1. In the Tailscale admin console:
   - DNS page: MagicDNS on, then HTTPS Certificates, Enable HTTPS.
   - Access controls: add the Funnel attribute for your user to the policy file,
     `"nodeAttrs": [{"target": ["<your login>"], "attr": ["funnel"]}],`
   - Machines page: the head unit, Disable key expiry.

   Check on the head unit: `tailscale status --json` shows the ts.net name in `CertDomains`, `funnel` in
   `Self.CapMap`, and no `KeyExpiry` in `Self`.

2. On the head unit, as your user:

   ```bash
   git clone https://github.com/hussu010/sparkpass && cd sparkpass
   ./setup.sh <worker-cx7>        # for example 10.100.0.2
   ```

   It installs sparkrun, sets up the cluster, the firewall and the gateway, starts the model (the first start
   downloads about 190 GB and compiles kernels for about 11 minutes), and ends with checks and the URLs. Run it again at any time: it skips what is
   done. Each step, with the reason for it, is in [`docs/setup-by-hand.md`](docs/setup-by-hand.md).

   It asks for passwords: `sudo` on each unit (more than once), and `sparkrun setup ssh` for the SSH
   password of each unit when the units have no SSH keys yet.

   To update later: `git pull`, then `./setup.sh <worker-cx7>` again. It also installs during a pass: the
   key of the pass stays, and the gateway reloads instead of a stop. A build that cannot read the pass
   refuses; then revoke the pass first, or wait for its end.

## Give a guest pass

On the head unit:

```bash
sudo sparkpass grant <name> --ttl <n>s|m|h|d   # for example --ttl 24h; at least 2m
sudo sparkpass list                            # active passes and their end times
sudo sparkpass revoke <name>                   # end a pass now
```

`grant` prints the text to send to the guest, in a private message:

```
Endpoint: https://<head unit>.<tailnet>.ts.net/v1
API key:  <key>
Model:    glm-5.3-flash
End time: 2026-10-16 10:00:00 UTC

Rules:
- Routes: GET /v1/models, POST /v1/chat/completions, POST /v1/completions and POST /v1/messages only; each other route gets 404.
...
```

The end time does not move. When `grant` fails, it hands out nothing, and the error says why. A failed
public self-check also stops the gateway: run `sudo sparkpass reconcile`, which starts it again after its
checks, then run `grant` again. Set `NOTIFY_URL` in `/etc/sparkpass/config` (for example an ntfy topic) to
get a message when something goes wrong during a pass: a failed revoke, a model outage, a stopped gateway,
or a gateway that accepts a wrong key.

Clients that worked through the gateway: opencode (an agent task with tool calls), and any client that
uses `/v1/chat/completions` or `/v1/completions` (streaming, tool calls, fill-in-the-middle). Claude Code uses
`/v1/messages`: set `ANTHROPIC_BASE_URL` to `https://<name>` (no `/v1`), `ANTHROPIC_AUTH_TOKEN` to the key and
`ANTHROPIC_MODEL` to `glm-5.3-flash`. `ANTHROPIC_API_KEY` does not work: Claude Code sends it as `x-api-key`, and
the gateway reads the key from the `Authorization` header only. Claude Code 2.1.302 completed a task with a tool
call against TensorFold 1104 through the SSH tunnel; through Funnel it is not tested yet. Clients that need other
routes do not work: Codex CLI (`/v1/responses`) and embeddings.

## The boot model: TensorFold 1104

The first pair boots GLM-5.3-Flash with the
[TensorFold recipe 1104](https://github.com/MiaAI-Lab/GLM-5.3-Flash-DGX-Sparks-1104) (an EXL3 4-bit checkpoint,
one rank on each unit over the ConnectX-7 link), not with sparkrun and vLLM. Measured on the pair on 2026-11-08
with the recipe's `docs/speed/harness/bench2.py` (greedy, thinking off, `DRAFTER=mtp`): one stream 42 tokens/s for
prose and 49 for code, 73 in total for 4 streams, prefill about 1,750 tokens/s (36 s for a 64k prompt), 8 requests
at the same time, a 1,048,576-token context, and 10 GiB free on each unit. The vLLM recipe gives about 25
tokens/s, 4 requests and 500k tokens. After the power cut of 2026-11-06, the boot service had the API back in 108 s.

- It thinks only when a request sends `reasoning_effort`, as the tip of the pass text says. The vLLM recipe
  thinks at the highest effort unless told.
- Its prompt cache keeps recent prompts in memory until a restart, as the pass text says. A restart between
  guests takes about 2 minutes.
- Its memory guard stops the model when a unit stays under 2.5 GiB free. Then nothing starts it until a reboot
  or `sudo systemctl restart sparkpass-model.service` (TODOS.md).
- Licences: Apache 2.0 for the recipe and the engine. The recipe's default draft model (DFlash2) is CC BY-NC-ND
  4.0, so `templates/tf1104-local.sh` sets `DRAFTER=mtp`, the checkpoint's own head. Against DFlash2 on the pair
  (2026-11-08) it gave the same text and was 2% slower for prose, 10% for code and 19% for 4 streams. Do not set
  `ABLIT=1` for guests.

On the head unit, as the user of sparkrun, with no active pass, in the repository:

1. Get the recipe at the tested commit, and the settings that keep the port, the bind address and the model
   name of sparkpass:

   ```bash
   git clone https://github.com/MiaAI-Lab/GLM-5.3-Flash-DGX-Sparks-1104 ~/GLM-5.3-Flash-DGX-Sparks-1104
   git -C ~/GLM-5.3-Flash-DGX-Sparks-1104 checkout 13f2464ee84ab2b5dabf0bb264d1144b02cf5fb7
   cp templates/tf1104-local.sh ~/GLM-5.3-Flash-DGX-Sparks-1104/scripts/local.sh   # then set WORKER in it
   ```

2. Start it by hand one time. The first start downloads 166 GiB, sends it to the worker, and builds the engine
   image in about 6 minutes, which is longer than the time limit of `sparkpass-model.service`:

   ```bash
   sparkrun stop --all --cluster pair
   ~/GLM-5.3-Flash-DGX-Sparks-1104/start.sh   # ends with "is now LIVE! on port 8000"
   ```

3. Make it the model of each boot, then prove it with a restart through the unit:

   ```bash
   sudo mkdir -p /etc/systemd/system/sparkpass-model.service.d
   sed "s|@HOME@|$HOME|g" systemd/sparkpass-model-tf1104.conf | sudo tee /etc/systemd/system/sparkpass-model.service.d/tf1104.conf >/dev/null
   sudo systemctl daemon-reload
   ~/GLM-5.3-Flash-DGX-Sparks-1104/stop.sh && sudo systemctl restart sparkpass-model.service
   curl -s http://127.0.0.1:8000/v1/models
   ```

While the drop-in exists, the unit does not read `/etc/sparkpass/model.env`. Back to the vLLM recipe:
`sudo rm /etc/systemd/system/sparkpass-model.service.d/tf1104.conf && sudo systemctl daemon-reload`, then
`~/GLM-5.3-Flash-DGX-Sparks-1104/stop.sh` and `sudo systemctl restart sparkpass-model.service` (about 5 minutes).

## Run another model

A model for guest passes must serve the OpenAI API (`/v1/models`, `/v1/chat/completions`) and `/health` on
`127.0.0.1:8000`. The gateway permits only the four routes of a pass, so sparkpass serves text models only.
`grant` reads the model name from `/v1/models`, so the pass text names the model that runs.

On the head unit, as the user of sparkrun, in the repository:

1. Find a recipe in the sparkrun registries, and check that it fits in memory:

   ```bash
   sparkrun search <text>                 # for example: sparkrun search qwen
   sparkrun show <recipe>
   sparkrun recipe vram <recipe> --tp 2   # memory for each unit
   ```

2. Save a copy in `templates/`, then edit it (the header of `templates/pair.yaml` shows these changes):

   ```bash
   sparkrun export recipe <recipe> --save templates/<name>.yaml
   ```

   - Set `defaults.host: 127.0.0.1` and `defaults.port: 8000`. Another host opens the model API, with no key,
     to each network that the firewall does not close.
   - Pin `model_revision` and the container image: a tag can change.
   - Remove `--enable-prompt-tokens-details`: with it, the next guest can see which prompt prefix the last
     guest sent.
   - Read the licence of the weights, and of any draft model.
   - Check the file: `sparkrun recipe validate templates/<name>.yaml`.

3. Make sure that no pass is active (`sudo sparkpass list`), then start the new model by hand. The first
   start downloads the weights and copies them to the worker, and that can take longer than the time limit
   of `sparkpass-model.service` (about 16 min). The firewall needs no change: it closes each port except SSH.

   ```bash
   sparkrun stop --all --cluster pair
   sparkrun run templates/<name>.yaml --cluster pair --no-follow
   until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/health)" = 200 ]; do sleep 10; done   # Ctrl-C if it never ends: sparkrun logs --cluster pair
   ```

4. Make it the model of each boot:

   ```bash
   echo RECIPE=templates/<name>.yaml | sudo tee /etc/sparkpass/model.env
   ```

   To go back to the default model, delete `/etc/sparkpass/model.env`, then run
   `sparkrun stop --all --cluster pair` and `sudo systemctl restart sparkpass-model.service` (about 5 min:
   its weights are on disk). With the TensorFold drop-in installed, the unit reads neither file: remove the
   drop-in first ("The boot model: TensorFold 1104"). A pass that is active during a switch has no model until
   the new one answers, and its end time does not move. Recipes for one unit (`min_nodes: 1`) are not tested
   with sparkpass.

`templates/pair.yaml` is the second tested recipe: Qwen3.8-Flash-Next (NVFP4, about 140 GB). It is faster:
about 65 tokens/s for one stream and 16 requests at the same time, where the GLM recipe of vLLM gives about 25
and 4, with 262,144 tokens of context. Its license needs a separate license from Qwen before you charge for a
pass. Before its first start, fetch its shard 35 on both units (`docs/setup-by-hand.md`, step 3, or `setup.sh`
with `RECIPE=templates/pair.yaml` in `/etc/sparkpass/model.env`).

The weight loader of the default recipe needs `io_uring`, which Docker's default seccomp profile refuses. The
recipe names `templates/seccomp-io-uring.json` (that profile plus the three `io_uring` calls), which
`install.sh` copies to `/usr/local/lib/sparkpass/` on both units.

## Use the model from your own editor

Point the editor's OpenAI-compatible provider at `http://localhost:8000/v1`, model `glm-5.3-flash` (the
name that `GET /v1/models` gives for another recipe), no
key (streaming, tool calls and `/v1/completions` work). The port comes from SSH to the head unit over the
tailnet, not through Funnel, and it uses no guest pass:

```bash
ssh -N -o ServerAliveInterval=30 -L 127.0.0.1:8000:127.0.0.1:8000 <head unit>
```

On macOS, a LaunchAgent keeps it up (`~/Library/LaunchAgents/com.sparkpass.tunnel.plist` on the first
setup: that command with `RunAtLoad` and `KeepAlive`). For Claude Code through the tunnel, set
`ANTHROPIC_BASE_URL` to `http://localhost:8000`, `ANTHROPIC_AUTH_TOKEN` to any text (for example `none`) and
`ANTHROPIC_MODEL` to `glm-5.3-flash`. Guests use `https://<name>/v1` with the key of `sparkpass grant`.

## Development

The tool is one Rust binary with no network library: it calls `curl`, `systemctl` and `systemd-run`. The
checks run in Docker and need no DGX Spark: unit tests, clippy, shellcheck, the Caddyfile against a real
Caddy (`tests/gateway.sh`), and the firewall rules against a real iptables (`tests/firewall.sh`). The
commands and the rules for tests are in [`CLAUDE.md`](CLAUDE.md). `install.sh`, `setup.sh` and
`tests/expiry.sh` change the host: run them only on the head unit.

## License

The code is under the [MIT License](LICENSE). The model weights that the recipes name have their own licenses:
NVIDIA Open Model Agreement for `templates/glm53-flash.yaml` (base model MIT), Qwen Community License 1.0 for
`templates/pair.yaml`. The TensorFold recipe 1104 and its engine are under Apache 2.0, and its default draft
model (DFlash2, off in `templates/tf1104-local.sh`) under CC BY-NC-ND 4.0 ("The boot model: TensorFold 1104").
