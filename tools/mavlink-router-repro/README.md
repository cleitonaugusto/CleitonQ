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
with `mavlink-routerd -t 0 -e 127.0.0.1:14551 0.0.0.0:14550`, then sends five
COMMAND_LONG frames to the ingress and captures each one on the output endpoint.

## Expected output

```
  Auth scheme              Sent  Received    Lost  Truncatable  Result
  ---------------------  ------  --------  ------  -----------  ------------------------------
  baseline, no auth          45        45       0  no           control passes
  HMAC-SHA3-256              77        45      32  no           auth gone
  Ed25519 signature         109        45      64  no           auth gone
  below read buffer        1120        45    1075  no           auth gone
  ML-DSA-87 signature      4672        45    4627  yes          auth gone

  Router log for the whole run:
    mavlink-router version v4-16-g2362c62
    Could not open conf file '/etc/mavlink-router/main.conf' (No such file or directory)
    Opened UDP Client [4]CLI: 127.0.0.1:14551
    Opened UDP Server [6]CLI: 0.0.0.0:14550
```

## How to read it

- **The baseline is the control.** A frame with nothing appended must arrive
  intact (45 -> 45). If it does not, the setup is wrong and the rest means
  nothing. It passes here.
- Every other case sends the same 45-byte frame with `N` authentication bytes
  appended after the frame's CRC. The relay parses the frame, re-emits exactly
  what the `LEN` field accounts for, and the `N` appended bytes never come back.
- The receiving end gets a well-formed, unauthenticated frame, with no error.
  The router's log is printed above so the silence is shown rather than claimed:
  four startup lines, nothing about the discarded bytes.

### The `Truncatable` column, and why the 1120-byte row is the one that matters

There is a rival explanation for a large append going missing, and it has
nothing to do with MAVLink framing. `mavlink-router` reads each datagram into a
buffer of `RX_BUF_MAX_SIZE = MAVLINK_MAX_PACKET_LEN * 4` = **1120 bytes**
(`src/endpoint.cpp`). A UDP datagram larger than that is truncated by the kernel
at `recvfrom`, so its tail is discarded *before* any MAVLink parsing happens.
The observable result is identical: 45 bytes come back either way.

The ML-DSA-87 row sends 4,672 bytes on the wire, so it sits in that ambiguous
region — marked `Truncatable: yes`. On its own it cannot tell the two mechanisms
apart, and it should not be cited as if it could.

The `below read buffer` row exists to settle it. It sends **exactly 1120 bytes**:
the whole datagram fits the read buffer, truncation is impossible, the router
demonstrably saw every byte — and it still re-emits only the 45 the `LEN` field
accounts for, dropping 1,075. That is frame re-emission, isolated from any
buffer effect, and it is what carries the argument. The post-quantum row then
shows the same outcome at realistic signature size, corroborated rather than
load-bearing.

**That isolation rests on one detail, so the probe enforces it.** `mavlink-router`
reads into `rx_buf` with only the space that is left over, and it keeps anything
from the first `0xFD`/`0xFE` it finds as a partial frame. The filler byte here is
`0xA5`, which is neither, so the remainder is discarded and the buffer is empty
when the next datagram arrives — which is the only reason the 1120-byte read is
a full one. Swap the filler for realistic material and the property is silently
lost: measured, with a `0xFD` filler in the preceding datagram, the 1120-byte
case is **not forwarded at all**, while the table would still print
`Truncatable: no`. A real ML-DSA-87 signature contains `0xFD` bytes, so that edit
is an easy one to make by accident. `probe.py` therefore asserts the filler is
not a start byte rather than leaving the invariant unstated.

## Exit status

The harness exits **0** when the measurement is interpretable and **1** when it
is not, printing how many cases failed. `auth gone` is the expected finding, not
an error, so it does not affect the exit code.

A case is *not* interpretable when nothing came back, when the control lost
bytes, or when a partial amount came back (`unexpected: N B out`) — that last one
is neither the append surviving nor the append being stripped, so it measures
nothing and must gate the exit like the others. The container also exits 1 if
the relay never started or never opened its UDP server, rather than printing a
table of empty rows that reads like a result.

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
- `entrypoint.sh` — starts the relay, checks it stayed up, runs the probe, and
  prints the router log.
