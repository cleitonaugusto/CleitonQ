# Reproduction: mavlink-router strips authentication appended after the frame

This is the independent, end-to-end reproduction behind the MAVLink case of the
`unsign` class. Unlike `tools/unsign mavlink`, which is a self-contained
illustration of the mechanism, this harness builds a **real, third-party relay**
(`mavlink-router`) from source and measures what it actually does to bytes
appended after a valid MAVLink v2 frame.

The point is that nothing here is simulated. The relay is the upstream project,
built at a pinned commit; the probe only sends frames and reads what comes back.

## Run it

```
docker build -t unsign-mavlink-repro .
docker run --rm unsign-mavlink-repro
```

The build compiles `mavlink-router` at commit `2362c62`. The container starts it
with `mavlink-routerd -t 0 -e 127.0.0.1:14551 0.0.0.0:14550`, then sends four
COMMAND_LONG frames to the ingress and captures each one on the output endpoint.

## Expected output

```
  Auth scheme              Sent  Received    Lost  Result
  ---------------------  ------  --------  ------  ------------------------------
  baseline, no auth          45        45       0  control passes
  HMAC-SHA3-256              77        45      32  FAIL - auth gone
  Ed25519 signature         109        45      64  FAIL - auth gone
  ML-DSA-87 signature      4672        45    4627  FAIL - auth gone
```

## How to read it

- **The baseline is the control.** A frame with nothing appended must arrive
  intact (45 -> 45). If it does not, the setup is wrong and the rest means
  nothing. It passes here.
- Every other case sends the same 45-byte frame with `N` authentication bytes
  appended after the frame's CRC. The relay parses the frame, re-emits exactly
  what the `LEN` field accounts for, and the `N` appended bytes never come back.
- The receiving end gets a well-formed, unauthenticated frame, with no error and
  nothing in the router log about the discarded bytes.

This is not a bug in `mavlink-router`. It re-emits precisely what the MAVLink v2
framing defines, which is correct behaviour. The failure is in assuming that
bytes appended outside the frame boundary survive a relay hop. Any authenticator
too large for MAVLink's native signature field (a 64-byte Ed25519 signature does
not fit; a post-quantum one is far larger) is forced outside the frame, and is
therefore stripped.

## Fix

Carry authentication material inside a field the framing counts, so the relay
forwards it as data. See the class write-up and the wire-format proposal linked
from the repository root.

## Files

- `Dockerfile` — builds `mavlink-router` at the pinned commit and the probe.
- `probe.py` — sends the frames and measures what returns. No dependencies.
- `entrypoint.sh` — starts the relay, runs the probe.
