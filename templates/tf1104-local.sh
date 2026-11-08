# shellcheck shell=bash disable=SC2034
# scripts/local.sh of the TensorFold recipe 1104 (README, "The boot model: TensorFold 1104"). The API listens on
# 127.0.0.1:8000 with the model id of templates/glm53-flash.yaml, so the gateway, the checks of sparkpass and the
# settings of the guests stay the same. The other values are the served settings of the recipe's README.
WORKER=spark@10.100.0.2 # <user>@<worker-cx7>: the worker on the ConnectX-7 link
PORT=8000
HOST=127.0.0.1
SERVED_NAME=glm-5.3-flash
# mtp is the checkpoint's own head. The recipe's default, DFlash2, is faster with several streams, but its weights are
# CC BY-NC-ND 4.0 (non-commercial): set DRAFTER=dflash2 only when no pass is for commercial use.
DRAFTER=mtp
PARALLEL=8
CONTEXT=auto
KV=fp8
DENSE=q8
HEAD=q8
ABSORB_MMA=1
MEMORY_RESERVE_GIB=9.5
HOST_CACHE_GIB=0
# The first start downloads the weights on this unit and sends them to the worker. The first pair downloaded them by
# hand and uses MODEL_SOURCE=local and WORKER_WEIGHTS=check: then each weights folder needs the .revision file that a
# finished download of the recipe writes (the full pinned revision).
WORKER_WEIGHTS=rsync
