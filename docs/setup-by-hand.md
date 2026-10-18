# Set up the pair by hand

`./setup.sh <worker-cx7>` runs these steps (README, "Set up the pair"). This page shows each step with the
reason for it, for a pair where the script fails or for a reader who wants to know what it changes.
The requirements and step 1 (the Tailscale admin console) are in the README. These are the commands of the
first setup (spark-3 head, spark-4 worker, 2026-10-14).

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
# The seccomp profile of the recipe, on both units (step 4 and step 5 install it the same way).
for h in <head-cx7> <worker-cx7>; do scp templates/seccomp-io-uring.json "$h": && \
  ssh -t "$h" 'sudo install -D -m 0644 seccomp-io-uring.json /usr/local/lib/sparkpass/seccomp-io-uring.json'; done
sparkrun run templates/glm53-flash.yaml --cluster pair --no-follow
until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/health)" = 200 ]; do sleep 10; done
```

The API listens on `127.0.0.1:8000` of the head unit only. Guests reach it through the gateway. On the
author's pair: the first start took 10.8 min (kernel compilation) and a later one 5 min, and one stream gave
23 to 28 tokens/s.

For `templates/pair.yaml` (Qwen) instead, fetch its shard 35 on both units first (2.8 GB, the MXFP8 prefill
weights: the serve command fetches it at start when it is missing, and sparkrun stops a head that is not ready
after about 2 minutes):

```bash
I=ghcr.io/ursuciprian/spark-vllm-b12x:k94-20261013-21e0b201-d21d7ade-warm
for h in <head-cx7> <worker-cx7>; do ssh "$h" "docker pull -q $I >/dev/null; docker run --rm --user \$(id -u):\$(id -g) \
  -e HF_HOME=/cache/huggingface -v \$HOME/.cache/huggingface:/cache/huggingface --entrypoint python3 $I -c \
  \"from huggingface_hub import snapshot_download as d; d('local-inference-lab/Qwen3.8-Flash-Next-NVFP4', \
  revision='7c4f1bc1a2d6847e0cbc01ac6b823f00251de8dd', \
  allow_patterns=['model-00035-of-00036.safetensors', 'model.safetensors.index.json'])\""; done
sparkrun run templates/pair.yaml --cluster pair --no-follow
```

It gave 64 to 73 tokens/s for one stream (512 tokens, thinking off); its first start took 6 min 54 s.

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
