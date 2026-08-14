#!/bin/sh
# Start the real mavlink-router, then measure it. Same invocation used in the
# recorded run: forward ingress 14550 -> 14551. Note that `-t 0` is
# --tcp-port and merely disables the TCP server; the broadcast routing that
# makes the router forward without a prior announcement comes from
# target_system = 0 in the probe's payload, not from any flag here.
set -e
/src/mavlink-router/build/src/mavlink-routerd -t 0 -e 127.0.0.1:14551 0.0.0.0:14550 >/tmp/router.log 2>&1 &
ROUTER_PID=$!

# Wait for the UDP server to be listening, not just for the process to exist.
# A fixed sleep was a flake waiting to happen: on a loaded machine the probe
# would send the baseline before the socket was bound, the control row would
# read "nothing forwarded", and the run would now exit 1 — indistinguishable
# from a real regression. Poll the log instead, and fail fast if the relay dies.
WAITED=0
while [ "$WAITED" -lt 100 ]; do
    if grep -q "Opened UDP Server" /tmp/router.log 2>/dev/null; then
        break
    fi
    if ! kill -0 "$ROUTER_PID" 2>/dev/null; then
        echo "  mavlink-routerd did not stay up. Its log:"
        sed 's/^/    /' /tmp/router.log
        exit 1
    fi
    sleep 0.1
    WAITED=$((WAITED + 1))
done

if ! grep -q "Opened UDP Server" /tmp/router.log 2>/dev/null; then
    echo "  mavlink-routerd did not open its UDP server within 10s. Its log:"
    sed 's/^/    /' /tmp/router.log
    kill "$ROUTER_PID" 2>/dev/null || true
    exit 1
fi

echo "  Relay : mavlink-router @ commit 2362c62 (built from source)"
echo "  Run   : mavlink-routerd -t 0 -e 127.0.0.1:14551 0.0.0.0:14550"
echo

# `set -e` would abort the script here on a nonzero exit, skipping both the
# router log and the cleanup below, so the failure path is handled explicitly.
if python3 /probe.py; then
    RC=0
else
    RC=$?
fi

# The claim that the discarded bytes are silent is worth showing rather than
# asserting, so the router's own log goes to stdout either way.
echo
echo "  Router log for the whole run:"
sed 's/^/    /' /tmp/router.log

kill "$ROUTER_PID" 2>/dev/null || true
exit $RC
