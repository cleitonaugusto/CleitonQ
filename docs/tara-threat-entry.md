# Threat catalogue entry: authentication stripped by a conformant intermediary

Written to be pasted into a TARA. It uses ISO 21434 vocabulary, states what it
does and does not claim, and ends with the test that decides whether the entry
applies to a given item. Licensed CC BY 4.0 — copy it, adapt it, no permission
needed.

If your catalogue already covers this, the useful part is the test at the end.
Run it and close the entry with evidence rather than with an assumption.

---

## Threat scenario

Authentication material attached to a message outside the region the protocol's
framing accounts for is not reproduced when an intermediary rebuilds that
message from the fields it parsed. The receiving component acts on a
well-formed, unauthenticated command and cannot distinguish it from a command
that was never authenticated.

## Asset

Integrity and authenticity of a command or control message in transit between
two components separated by a gateway, router, bridge or broker.

## Damage scenario

A component acts on a command whose origin cannot be established. Where that
component actuates, the damage scenario is the actuation itself: unintended
motion, unintended state change, unintended safe-state exit. Where it does not
actuate, the damage is loss of non-repudiation for anything downstream that
relied on the authentication being present.

## Attack path

1. A legitimate sender attaches authentication outside the framing boundary.
   No attacker involvement.
2. A conformant intermediary on the path parses the message and re-emits it
   from the parsed representation. The attached material is not part of that
   representation and is not re-emitted. **No attacker involvement.**
3. Any party able to inject on the segment downstream of the intermediary now
   faces an unauthenticated command channel, and needs no cryptographic
   capability, because no cryptography remains on the path to defeat.

Steps 1 and 2 are ordinary operation. Only step 3 requires an adversary, and
the capability it requires is whatever injection on that segment already
required before authentication was deployed.

## Attack feasibility

Rate step 3 by your existing criteria for injection on the relevant segment.
Steps 1 and 2 add no feasibility cost, because they are not attacker actions.

The practical consequence for the rating: **deploying the authentication does
not reduce the feasibility of step 3 at all**, while the risk register will
usually record it as if it did. That mismatch is the reason this entry exists.

## Impact

Inherit the impact of the underlying command being accepted without
authentication. This entry does not introduce a new damage scenario; it removes
a control that a previously accepted damage scenario was assumed to have.

## Preconditions — all four must hold

| | |
|---|---|
| **C1** | messages are delimited by a length field or a schema |
| **C2** | authentication sits outside what that boundary accounts for |
| **C3** | something on the path parses and rebuilds rather than forwarding octets |
| **C4** | the receiver performs no integrity check over the raw octets received |

If any one fails, the item is not exposed by this path, and that should be
recorded with the evidence that made it fail.

## Where it has been measured

| protocol | intermediary | outcome |
|---|---|---|
| MAVLink v2 | mavlink-router `2362c62` | stripped |
| ROS2 / DDS | CycloneDDS 11.0.1 | stripped |
| SOME/IP | vsomeip 3.7.0 | stripped; error returned to the sender, not the receiver |
| CAN / ISO-TP | Linux kernel reassembler | stripped at two boundaries |
| MQTT 5 → 3.1.1 | mosquitto 2.1.2 | stripped on version downgrade |
| EVM cross-chain | Wormhole contracts | **not** an instance: exact consumption enforced |

The last row belongs in the entry. A parser that refuses to proceed unless it
consumed exactly what it was handed does not exhibit this threat, and naming one
that does it correctly is what makes the rest of the table usable.

## Two findings that constrain the entry rather than widen it

**Post-quantum signature sizes do not uniformly make this worse.** They push
authentication out of fixed fields, which creates C2 systematically. But where a
transport refuses to carry the oversized unit, the result is a loss of
availability instead of a silent bypass: a classical ISO-TP FirstFrame carries a
12-bit length and cannot declare 4,627 octets at all, and a SOME/IP datagram of
that size exceeds the implementation's maximum and is discarded. Loud, and
therefore not this threat.

**On SOME/IP the deciding behaviour is unspecified.** Whether a receiver acts on
a valid message that shared a datagram with unparseable octets is not determined
by any specification, and implementations settle it by judgement. Two conformant
stacks can differ on whether your item is exposed. Do not infer this entry's
applicability from the protocol; determine it from the implementation you ship.

## Risk treatment

**Effective.** Carry authentication inside the region the framing accounts for,
so an intermediary parses it as data and rebuilds it with everything else. Where
it does not fit, define a first-class protocol unit that carries it rather than
appending past the one you have. Measured at post-quantum scale: a 4,627-octet
ML-DSA-87 signature carried inside a SOME/IP-TP payload arrives intact through a
parse-and-rebuild gateway.

**Partial, and record them as partial.** Test the intermediary you actually
deploy rather than the one in the specification. Treat an intermediary software
update as a change to the item's authentication properties, requiring
re-verification. Have receivers treat a missing authenticator as unauthenticated
rather than as absent, which converts a silent acceptance into a visible
rejection.

None of the partial measures restores non-repudiation.

**Not effective.** Transport encryption, because the intermediary terminates it.
Increasing the strength of the authentication algorithm, because the algorithm
is never reached. Signing at the sender only, because that is the configuration
being described.

## Regulatory mapping

Assess under the Tampering category of UN Regulation No. 155 Annex 5 for any
gateway handling safety-relevant PDUs. Confirm the mapping against the current
text of the regulation before citing it in a submission; this entry states where
it belongs, not what your assessor will accept.

## The test that closes the entry

Do not decide C1–C4 by reading. Ten minutes, no dependencies, no hardware:

```
git clone https://github.com/cleitonaugusto/CleitonQ
cd CleitonQ
./tools/unsign --conditions     # the four conditions per protocol measured
./tools/unsign mavlink          # or ros2, mqtt, can, someip
```

Each adapter builds a real message, attaches an authenticator, passes it through
an intermediary for that protocol, and reports whether the authenticator
arrived. Every one opens with a control that must pass before the rest means
anything — three times during this work a broken setup produced output identical
to a perfect strip, and only the control told them apart.

For a protocol not covered above, the adapter interface is small and the same
procedure applies.

---

Full analysis, including the negative results:
[doi:10.5281/zenodo.21840073](https://doi.org/10.5281/zenodo.21840073)

Cleiton Augusto Correa Bezerra · augusto.cleiton@gmail.com
