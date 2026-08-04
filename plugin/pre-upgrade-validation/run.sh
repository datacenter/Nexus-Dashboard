#!/bin/bash
# NDP entry point — runs the pre-upgrade validation script locally on the ND node.
# The script is invoked without --ndip so it runs against the local cluster.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "${RESCUE_USER_PASS}" ]; then
    echo "ERROR: RESCUE_USER_PASS environment variable is required" >&2
    exit 1
fi
ND_IP="${ND_IP:-$(hostname -I | awk '{print $1}')}"

exec python3 "${SCRIPT_DIR}/ND-Preupgrade-Validation.py" --ndip "${ND_IP}" -p "${RESCUE_USER_PASS}" "$@"
