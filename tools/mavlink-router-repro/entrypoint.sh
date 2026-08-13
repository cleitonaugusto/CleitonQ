#!/bin/sh
# Start the real mavlink-router, then measure it. Same invocation used in the
# recorded run: route by target (broadcast), forward ingress 14550 -> 14551.
set -e
/src/mavlink-router/build/src/mavlink-routerd -t 0 -e 127.0.0.1:14551 0.0.0.0:14550 >/tmp/router.log 2>&1 &
ROUTER_PID=$!
sleep 1
echo "  Relay : mavlink-router @ commit 2362c62 (built from source)"
echo "  Run   : mavlink-routerd -t 0 -e 127.0.0.1:14551 0.0.0.0:14550"
echo
python3 /probe.py
RC=$?
kill "$ROUTER_PID" 2>/dev/null || true
exit $RC
