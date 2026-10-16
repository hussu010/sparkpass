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

- Two DGX Spark units with the ConnectX-7 ports cabled back to back (DGX OS, Ubuntu 24.04).
- A Tailscale account on which you can enable HTTPS certificates and Funnel.
- Wired Ethernet on the head unit, and about 140 GB of download for the image and the model.

## Set up the pair

These are the commands of the first setup (spark-3 head, spark-4 worker, 2026-10-14). After "Before you
start" and step 1, one command on the head unit, as your user, runs steps 2 to 5 and ends with checks:

```bash
git clone https://github.com/hussu010/sparkpass && cd sparkpass
./setup.sh <worker-cx7>        # for example 10.100.0.2; run it again at any time: it skips what is done
```

It prints the editor and guest URLs at the end. The steps below are what it does, and why.

Before you start:

- The two units have the ConnectX-7 ports cabled back to back, with an address on that link and SSH between
  the units (the cluster setup of NVIDIA Sync does this). Below, `<head-cx7>` and `<worker-cx7>` are those
  addresses, for example `10.100.0.1` and `10.100.0.2`.
- Kernel `7.0.0-1019-nvidia` breaks NCCL over RoCE unless the kernel command line has `kho=off`
  (`cat /proc/cmdline`). NVIDIA's update adds it with `/etc/default/grub.d/nvidia-spark-kho.cfg`.
- Put the head unit on wired Ethernet: it downloads about 140 GB, and it carries the guest traffic. On the
  first setup, Wi-Fi gave 80 Mb/s and Ethernet 220 Mb/s on the same internet line.

1. In the Tailscale admin console:
   - DNS page: MagicDNS on, then HTTPS Certificates, Enable HTTPS.
   - Access controls: add the Funnel attribute for your user to the policy file,
     `"nodeAttrs": [{"target": ["<your login>"], "attr": ["funnel"]}],`
   - Machines page: the head unit, Disable key expiry.

   Check on the head unit: `tailscale status --json` shows the ts.net name in `CertDomains`, `funnel` in
   `Self.CapMap`, and no `KeyExpiry` in `Self`.

2. On the head unit, as your user:

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   uv tool install sparkrun==0.3.10
   sparkrun setup telemetry --disable
   sparkrun cluster create pair --hosts <head-cx7>,<worker-cx7> --transfer-mode push --transfer-interface cx7 \
     --mgmt-interface <cx7-iface>                # for example enp1s0f0np0, the same name on both units
   sparkrun cluster set-default pair
   sparkrun setup ssh --cluster pair            # SSH between the units and from the head to itself
   sparkrun setup docker-group --cluster pair
   sparkrun setup earlyoom --cluster pair
   for h in <head-cx7> <worker-cx7>; do
     ssh -t "$h" "sudo loginctl enable-linger $USER; echo SPARKRUN_MGMT_IFACE=<cx7-iface> | sudo tee -a /etc/environment"
   done
   ```

   The head connects to itself over SSH, because it is the first host of the cluster. `sparkrun setup ssh`
   asks for passwords. On the first setup, the key of NVIDIA Sync was added to the `authorized_keys` of the
   head and to its `~/.ssh/config` for `<head-cx7>` instead. Linger keeps the shared memory of vLLM when no
   user is logged in.

   The control traffic of vLLM (the rendezvous on port 25000 and about 15 other ports per unit) must use the
   ConnectX-7 link: these ports permit code execution, and on the default route they listen on the LAN and
   are open to the tailnet. `--mgmt-interface` moves most of them. sparkrun 0.3.10 still takes the master
   address from the default route, because its head-IP check does not get the cluster setting, so
   `SPARKRUN_MGMT_IFACE` in `/etc/environment` gives it to that check too. Check after a start:
   `docker exec <head container> grep -m1 master_addr /tmp/sparkrun_serve.log` names the head's ConnectX-7
   address. Port 25000 still listens on all addresses; only the firewall closes it.

3. Start the model on the head unit (the first run downloads the image and the model, then copies them to
   the worker over the ConnectX-7 link):

   ```bash
   git clone https://github.com/hussu010/sparkpass && cd sparkpass
   # Shard 35 of the base model (2.8 GB, the MXFP8 prefill weights): the serve command fetches it at start
   # when it is missing, and sparkrun stops a head that is not ready after about 2 minutes.
   I=ghcr.io/ursuciprian/spark-vllm-b12x:k94-20261013-21e0b201-d21d7ade-warm
   for h in <head-cx7> <worker-cx7>; do ssh "$h" "docker pull -q $I >/dev/null; docker run --rm --user \$(id -u):\$(id -g) \
     -e HF_HOME=/cache/huggingface -v \$HOME/.cache/huggingface:/cache/huggingface --entrypoint python3 $I -c \
     \"from huggingface_hub import snapshot_download as d; d('local-inference-lab/Qwen3.8-Flash-Next-NVFP4', \
     revision='7c4f1bc1a2d6847e0cbc01ac6b823f00251de8dd', \
     allow_patterns=['model-00035-of-00036.safetensors', 'model.safetensors.index.json'])\""; done
   sparkrun run templates/pair.yaml --cluster pair --no-follow
   until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/health)" = 200 ]; do sleep 10; done
   ```

   The API listens on `127.0.0.1:8000` of the head unit only. Guests reach it through the gateway. On the
   first setup: the first start took 6 min 54 s and a later one 4 min 25 s, and one stream gave 64 to 73
   tokens/s (512 tokens, thinking off).

4. The firewall (`firewall/rules.sh`): new connections from the LAN and the tailnet get no model or control
   port; SSH stays open. On the worker, from a copy of this repository:

   ```bash
   sudo tailscale set --netfilter-mode=nodivert   # on both units; the rules refuse to load without it
   sudo ./install.sh --second-unit                # loads the rules now and at each boot
   ```

   On the head unit, step 5 installs the same rules, and `sparkpass reconcile` loads them at boot and every
   5 minutes.

5. The gateway: `sudo ./install.sh` on the head unit, then the steps that it prints (the Tailscale Funnel
   procedure and the settings files). It also installs `sparkpass-model.service`, which starts the model at
   each boot (run it with `sudo` as the user of sparkrun).

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
