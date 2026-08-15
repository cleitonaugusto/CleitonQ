# Threat catalogue entry: message provenance silently removed by conformant HL7 v2 → FHIR conversion

Written to be pasted into a medical device Security Risk Management file or threat
model. It uses the vocabulary of FDA Section 524B premarket cybersecurity and the
2026 guidance, states what it does and does not claim, and ends with a test that
decides whether the entry applies to a given device or data pipeline. Licensed
CC BY 4.0 — copy it, adapt it, no permission needed.

If your threat model already covers this, the useful part is the test at the end.
Run it and close the entry with evidence rather than with an assumption.

This is an HL7 interoperability instance of a broader class: authentication or
integrity material removed by a conformant intermediary that parses and rebuilds a
message, with no attacker at the moment of removal. The class and its four
preconditions are described in
[doi:10.5281/zenodo.21840073](https://doi.org/10.5281/zenodo.21840073).

A companion entry covers the medical-imaging instance:
[dicom-provenance-threat-entry.md](dicom-provenance-threat-entry.md). The two are
independent findings on the *same clinical data path*, which is the reason to read
both.

---

## Threat scenario

An HL7 v2 message carries integrity or provenance material — a token, a MAC, a
signature over the message, a chain-of-custody marker — in a Z-segment, the
segment range HL7 v2 reserves for site-specific data. A conversion step on the
path rebuilds the message as FHIR resources for an API, an app, a registry or an
AI/ML pipeline. The Z-segment has no standard mapping, so it is not carried into
the bundle. The FHIR output is well-formed and complete by its own schema. No
party is told anything was removed.

**The uncomfortable part is that the standard points you here.** HL7's own privacy
and security guidance states that for HL7 v2, *envelope signatures should be
applied **outside the message frame** to avoid breaking parsers*. Placing
integrity material outside what the standard mappings account for is therefore not
a mistake by an integrator — it is the documented way to add integrity to v2
without breaking conformant parsers. And the official HL7 `v2-to-fhir`
implementation guide states that z-data "may not be considered for inclusion in
standard mappings".

So one standard recommends putting the proof outside the frame, and the mapping
that consumes it is not obliged to carry what sits there.

## Asset

Authenticity and integrity provenance of a clinical message as it crosses from an
HL7 v2 feed into a FHIR-based API, registry, app ecosystem or AI/ML pipeline.

## Harm scenario

A downstream consumer — a clinician viewing data through a FHIR app, a registry
ingesting results, a model consuming a training or validation feed — relies on
data whose origin can no longer be established. Where the feed serves an AI/ML
device, altered or substituted records enter with no provenance check available to
detect them. Where a human relies on it, the harm is loss of any assurance that
the record is the one the sending system produced. This entry does not introduce a
new harm; it removes a control that a previously accepted harm scenario was
assumed to have.

## Path — no attacker at the moment of removal

1. A sending system emits an HL7 v2 message with integrity material in a
   Z-segment, following the guidance to keep it outside the frame. Ordinary
   operation.
2. A conformant converter maps the message to FHIR. The Z-segment has no standard
   mapping, so nothing corresponding to it appears in the bundle. Ordinary
   operation. **No attacker involvement.**
3. Any party able to alter or substitute the record downstream of the conversion
   faces no cryptographic barrier, because none remains, and needs no
   cryptographic capability to defeat.

Steps 1 and 2 are normal data handling. Only step 3 requires an adversary, and the
capability it requires is whatever alteration on that pipeline already required
before the integrity material was deployed.

## Feasibility

Rate step 3 by your existing criteria for tampering on the relevant pipeline
segment. Steps 1 and 2 add no feasibility cost, because they are not attacker
actions. The practical consequence: **adding integrity material to your v2 feed
does not reduce the feasibility of step 3 at all** for consumers on the FHIR side
of a conversion, while the risk file will usually record it as if it did.

## Preconditions — all four must hold

| | |
|---|---|
| **C1** | the message is delimited by a schema (HL7 v2 segments and the converter's known segment set) |
| **C2** | the integrity material sits outside what the standard mappings account for — a Z-segment, or any field the mapping does not name |
| **C3** | something on the path parses and rebuilds the message into a representation with no place for unmapped data (FHIR resources) rather than forwarding it |
| **C4** | the downstream consumer performs no integrity check over the original v2 octets |

If any one fails, the item is not exposed by this path, and that should be
recorded with the evidence that made it fail. C4 fails, for example, if your FHIR
consumer re-verifies against an out-of-band provenance record, or if the v2
message is retained and checked alongside the bundle.

## Where it has been measured

An `ADT^A01` message carrying a 32-character token in a `ZAU` segment, with a
control carrying no Z-segment and a positive control carrying the same token in
`PID-3`, a field the mappings do name. Three runs each.

| component | role | token in output |
|---|---|---|
| LinuxForHealth `hl7v2-fhir-converter` 1.0.10 | HL7 v2 → FHIR | **gone** |
| Microsoft `FHIR-Converter` 1.0.497-preview | HL7 v2 → FHIR (engine behind Azure Health Data Services) | **gone** |
| Mirth Connect 4.5.2 | HL7 v2 routing / interface engine | **preserved**, byte for byte |
| positive control (`PID-3`, both converters) | — | present |

Two independent converters — different vendor, different language, same
specification — produce the same result, and in both the bundle is the same size
as the control's: the Z-segment contributed nothing at all, not even an extension.

**The Mirth row is the one that tells you where to look.** Mirth genuinely
reconstructs the message — it goes through an XML representation and back, and its
strict parser rewrites enough that the output changes length — and the Z-segment
survives intact. Its target format is HL7 v2 again, which has a generic place for
a Z-segment. The converters' target is FHIR, which has no place for a segment it
does not map.

**So the loss is at the FHIR mapping boundary, not at the interface engine.** If
your architecture diagram shows both, the conversion step is where this entry
applies.

## Is it reported anywhere?

Log levels were swept on the converter that has a logger to sweep. At `error`,
`warn` and `info` — every level an operator would run in production — nothing is
emitted about the discarded segment. Only at `debug` does the underlying parser
note it, and what it says is about class loading (`Failed to load
...segment.ZAU`), not that data is being dropped.

The managed engine is quieter still: for the same request its log reads *"Convert
operation completed without errors"* and *"Request succeeded"*.

Nothing reaches the consumer of the bundle in either case.

## What constrains this entry rather than widens it

**This is not a defect in any converter.** There is no standard mapping for a
site-specific segment, so there is nothing for a converter to emit. Filing it as a
vendor bug will get a correct answer and no fix.

**Whether your feed actually carries integrity material in a Z-segment is the
question this entry cannot answer for you.** The standard's guidance points that
way and Z-segments are where custom data goes, but prevalence is a property of
your deployment, not of the standard. That is precisely what the test below
determines.

**A Z-segment carries other things too.** If yours carries operational data rather
than integrity material, the data-loss concern may still apply but this entry —
which is about a *security control* — does not.

## Risk control

**Effective.** Carry provenance in a form the conversion preserves. On the FHIR
side that means a `Provenance` resource, whose `signature` element exists for this
purpose, populated by the conversion step rather than left to chance. Where the
converter cannot be changed, retain the original v2 message and verify against it
out of band, so the proof survives outside the mapping.

**Partial, and record them as partial.** Test the converter you actually deploy,
not the one in the specification — including the managed one, if you consume
conversion as a service. Treat a converter or template update as a change to the
message's authenticity properties, requiring re-verification. Have FHIR-side
consumers treat missing provenance as unverified rather than as absent, converting
a silent acceptance into a visible one.

**Not effective.** Transport encryption, because the converter terminates it and
operates on plaintext messages. Strengthening the algorithm used in the
Z-segment, because the segment is removed rather than defeated. Signing at the
interface engine, because the engine is not where the loss occurs.

## Regulatory mapping

Assess under the Security Risk Management expected by FDA Section 524B and the
2026 premarket cybersecurity guidance, as a loss of a data-integrity control in
the total product lifecycle — particularly for AI/ML-enabled devices and for
FHIR-based data exchange whose upstream is a v2 feed. Confirm the mapping against
the current guidance text before citing it in a submission; this entry states
where it belongs, not what your reviewer will accept.

## The test that closes the entry

Do not decide C1–C4 by reading. Take a real message shape from your feed, append a
Z-segment with a marker token, and run your own converter:

```bash
docker run -d --name fc -p 8090:8080 \
  mcr.microsoft.com/healthcareapis/fhir-converter:1.0.497-preview

# the test message: marker token in a Z-segment
cat > test.hl7 <<'EOF'
MSH|^~\&|SENDER|FAC|RECEIVER|FAC|20260101120000||ADT^A01|MSG1|P|2.5.1
EVN|A01|20260101120000
PID|1||PATID1234^^^FAC^MR||DOE^JOHN||19700101|M
ZAU|1|UNSIGN-TEST-TOKEN-0123456789
EOF

# the positive control: same token in PID-3, a field the mappings DO name
sed 's/PATID1234/UNSIGN-TEST-TOKEN-0123456789/; /^ZAU/d' test.hl7 > control.hl7

for f in test.hl7 control.hl7; do python3 -c "
import json, urllib.request
hl7 = open('$f').read().strip().replace('\n', '\r')
body = json.dumps({'InputDataFormat': 'Hl7v2', 'RootTemplateName': 'ADT_A01',
                   'InputDataString': hl7}).encode()
r = urllib.request.urlopen(urllib.request.Request(
    'http://localhost:8090/convertToFhir?api-version=2024-05-01-preview',
    data=body, headers={'Content-Type': 'application/json'}))
print('$f -> token in FHIR:', 'UNSIGN-TEST-TOKEN' in r.read().decode())
"; done
```

Expected on a pipeline where this entry applies:

```
test.hl7    -> token in FHIR: False
control.hl7 -> token in FHIR: True
```

**Read both lines, not just the first.** `False` on the test alone proves nothing —
a malformed message produces `False` too. It is the `True` on the positive control
that says the harness works and the only variable is where the token sat. If the
control is also `False`, fix the harness before concluding anything.

(The message is passed through `python3` rather than inlined into `curl` on
purpose: the `\&` in the `MSH` encoding characters is not a valid JSON escape, and
a hand-escaped one-liner silently fails validation and returns `False` for both
cases — which reads exactly like a positive finding and is not one.)

Run it against the converter your pipeline actually uses, and close the entry with
the result.

---

Full analysis of the class, including the negative results:
[doi:10.5281/zenodo.21840073](https://doi.org/10.5281/zenodo.21840073)

Cleiton Augusto Correa Bezerra · augusto.cleiton@gmail.com
