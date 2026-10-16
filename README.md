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

- Works on the author's pair since 2026-10-15: Qwen3.8-Flash-Next (NVFP4) with tensor parallel 2 across the
  two units, 262,144 tokens of context, up to 16 requests at the same time, 64 to 73 tokens/s for one stream.
- API only. The SSH workspace for guests (build phase 2 of the design) is not built.
- One model at a time, and one owner's pair. `setup.sh` has run on one pair only.
- The model weights are under the Qwen Community License 1.0. Its clause 2 ("Model as a Service") needs a
  separate license from Qwen before you charge for a pass.

## How it works

```
guest ──https──> Tailscale Funnel ──raw TCP──> Caddy on 127.0.0.1:443 ──> vLLM on 127.0.0.1:8000
                 (relays, ts.net name)          key check, 3 routes          head unit + worker over
                                                                             the ConnectX-7 link
```

- [sparkrun](https://pypi.org/project/sparkrun/) and vLLM serve the model across both units
  (`templates/pair.yaml`). The API listens on the loopback address of the head unit only.
- Tailscale Funnel carries the guest traffic to Caddy with TLS intact. Caddy ends TLS with the certificate
  of the ts.net name, checks the key, and permits `GET /v1/models`, `POST /v1/chat/completions` and
  `POST /v1/completions` only. The access log keeps no client address and no prompt.
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
- Wired Ethernet on the head unit: it downloads about 140 GB, and it carries the guest traffic. On the first
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
   downloads about 140 GB), and ends with checks and the URLs. Run it again at any time: it skips what is
   done. Each step, with the reason for it, is in [`docs/setup-by-hand.md`](docs/setup-by-hand.md).

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
Model:    qwen3.8-flash-next
End time: 2026-10-16 10:00:00 UTC

Rules:
- Routes: GET /v1/models, POST /v1/chat/completions and POST /v1/completions only; each other route gets 404.
...
```

The end time does not move. When `grant` fails, it hands out nothing, and the error says why. A failed
public self-check also stops the gateway: run `sudo sparkpass reconcile`, which starts it again after its
checks, then run `grant` again. Set `NOTIFY_URL` in `/etc/sparkpass/config` (for example an ntfy topic) to
get a message when something goes wrong during a pass: a failed revoke, a model outage, a stopped gateway,
or a gateway that accepts a wrong key.

Clients that worked through the gateway: opencode (an agent task with tool calls), and any client that
uses `/v1/chat/completions` or `/v1/completions` (streaming, tool calls, fill-in-the-middle). Clients that
need other routes do not work: Codex CLI (`/v1/responses`), Claude Code (the Anthropic API), and embeddings.

## Run another model

A model for guest passes must serve the OpenAI API (`/v1/models`, `/v1/chat/completions`) and `/health` on
`127.0.0.1:8000`. The gateway permits only the three guest routes, so a video or image model works for the
owner only (through the SSH tunnel), not for guests. `grant` reads the model name from `/v1/models`, so the
pass text names the model that runs.

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

3. Make sure that no pass is active (`sudo sparkpass list`), then switch:

   ```bash
   echo RECIPE=templates/<name>.yaml | sudo tee /etc/sparkpass/model.env   # the model of each boot
   sparkrun stop --all --cluster pair
   sudo systemctl restart sparkpass-model.service   # starts $RECIPE and waits until it answers (up to 12 min)
   ```

   To go back to the default model, delete `/etc/sparkpass/model.env` and run the last two commands again.
   A pass that is active during a switch has no model until the new one answers, and its end time does not
   move. Recipes for one unit (`min_nodes: 1`) are not tested with sparkpass.

## Use the model from your own editor

Point the editor's OpenAI-compatible provider at `http://localhost:8000/v1`, model `qwen3.8-flash-next`, no
key (streaming, tool calls and `/v1/completions` work). The port comes from SSH to the head unit over the
tailnet, not through Funnel, and it uses no guest pass:

```bash
ssh -N -o ServerAliveInterval=30 -L 127.0.0.1:8000:127.0.0.1:8000 <head unit>
```

On macOS, a LaunchAgent keeps it up (`~/Library/LaunchAgents/com.sparkpass.tunnel.plist` on the first
setup: that command with `RunAtLoad` and `KeepAlive`). Guests use `https://<name>/v1` with the key of
`sparkpass grant`.

## Development

The tool is one Rust binary with no network library: it calls `curl`, `systemctl` and `systemd-run`. The
checks run in Docker and need no DGX Spark: unit tests, clippy, shellcheck, the Caddyfile against a real
Caddy (`tests/gateway.sh`), and the firewall rules against a real iptables (`tests/firewall.sh`). The
commands and the rules for tests are in [`CLAUDE.md`](CLAUDE.md). `install.sh`, `setup.sh` and
`tests/expiry.sh` change the host: run them only on the head unit.

## License

The code is under the [MIT License](LICENSE). The model weights that `templates/pair.yaml` names have their
own license (Qwen Community License 1.0).
