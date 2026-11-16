#!/usr/bin/env bash
# Run clab-color-trace on macOS (Docker Desktop / OrbStack).
# Containerlab's nodes live inside Docker's Linux VM, so the capture has to run
# there too: this starts a short-lived privileged helper container that shares
# the VM's PID namespace (for nsenter into each node) and the Docker socket,
# with the current folder mounted at the same path. All arguments are passed
# through to clab-color-trace. Run it from the folder with your topology file.
set -euo pipefail
TOOL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/clab_color_trace.py"
[ -f "$TOOL" ] || { echo "clab_color_trace.py must sit next to this script" >&2; exit 1; }
ENVARGS=()
TTYARGS=()
[ -t 0 ] && [ -t 1 ] && TTYARGS=(-t)       # Ctrl-C reaches the tool (it cleans up the overlay)
[ -n "${CLAB_TOPOLOGY:-}" ] && ENVARGS+=(-e "CLAB_TOPOLOGY=$CLAB_TOPOLOGY")
exec docker run --rm -i ${TTYARGS[@]+"${TTYARGS[@]}"} --init --privileged --pid host --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD":"$PWD" -w "$PWD" \
  -v "$TOOL":/opt/clab_color_trace.py:ro \
  ${ENVARGS[@]+"${ENVARGS[@]}"} \
  docker:cli sh -c 'apk add -q --no-cache python3 py3-pillow tcpdump util-linux-misc iproute2 >/dev/null && exec python3 /opt/clab_color_trace.py "$@"' _ "$@"
