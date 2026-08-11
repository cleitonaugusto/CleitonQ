# Threat catalogue entry: image provenance silently removed by conformant de-identification

Written to be pasted into a medical device Security Risk Management file or threat
model. It uses the vocabulary of FDA Section 524B premarket cybersecurity and the
2026 guidance, states what it does and does not claim, and ends with a test that
decides whether the entry applies to a given device or data pipeline. Licensed
CC BY 4.0 — copy it, adapt it, no permission needed.

If your threat model already covers this, the useful part is the test at the end.
Run it and close the entry with evidence rather than with an assumption.

This is a medical-imaging instance of a broader class: authentication or integrity
material removed by a conformant intermediary that parses and rebuilds a message,
with no attacker at the moment of removal. The class and its four preconditions
are described in [doi:10.5281/zenodo.21840073](https://doi.org/10.5281/zenodo.21840073).

---

## Threat scenario

A DICOM object carries a digital signature (DICOM PS3.15 Digital Signatures) that
attests its origin and integrity. A de-identification step on the path — required
for research release, AI/ML training and validation datasets, cloud archives and
external data sharing — removes the Digital Signatures Sequence and does not
re-sign. The object continues downstream well-formed and unsigned. No party is
told it was ever signed, and nothing re-establishes the proof.

The removal is expected behaviour. DICOM PS3.15 has the de-identification profile
remove the Digital Signatures Sequence — the Certificate of Signer can carry
identifying information — and its own note states that re-signing by the
de-identifier is **not required by the Standard**. The gap is not a defect in any
one tool; it is that the origin proof is destroyed by a standard de-identification
step and restoring it is optional.

## Asset

Authenticity and integrity provenance of a DICOM object as it flows through
de-identification into a research, AI/ML, archival or data-sharing pipeline.

## Harm scenario

A downstream consumer — a clinician on a research view, a model in training or
validation, an external collaborator — relies on an image whose origin cannot be
established. Where the image feeds an AI/ML device, an altered or substituted
image enters the training or validation set with no provenance check available to
detect it. Where a human relies on it, the harm is loss of any assurance that the
image is the one the acquiring device produced. This entry does not introduce a
new harm; it removes a control that a previously accepted harm scenario was
assumed to have.

## Path — no attacker at the moment of removal

1. An acquisition device or archive signs a DICOM object (PS3.15 Digital
   Signature). Ordinary operation.
2. A conformant de-identifier applies the PS3.15 Basic Application Level
   Confidentiality Profile. It removes the Digital Signatures Sequence and does
   not re-sign. Ordinary operation. **No attacker involvement.**
3. Any party able to alter, relabel or substitute the object downstream of the
   de-identifier faces no cryptographic barrier, because none remains, and needs
   no cryptographic capability to defeat.

Steps 1 and 2 are normal data handling. Only step 3 requires an adversary, and
the capability it requires is whatever alteration on that pipeline already
required before signing was deployed.

The sharpest form: the signature can cover **image content the de-identifier does
not touch** (pixel data, dimensions, modality). In that case the removed
signature would still have verified — the proof was valid and was destroyed
anyway.

## Feasibility

Rate step 3 by your existing criteria for tampering on the relevant pipeline
segment. Steps 1 and 2 add no feasibility cost, because they are not attacker
actions. The practical consequence: **deploying image signing does not reduce the
feasibility of step 3 at all** once a de-identification step is on the path, while
the risk file will usually record it as if it did.

## Preconditions — all four must hold

| | |
|---|---|
| **C1** | the object is delimited by a schema (the DICOM data set) |
| **C2** | the authenticity proof sits in an attribute the de-identifier does not preserve |
| **C3** | something on the path parses and rebuilds the object rather than forwarding octets |
| **C4** | the downstream consumer performs no integrity check over the received object |

If any one fails, the item is not exposed by this path, and that should be
recorded with the evidence that made it fail. C4 fails, for example, if your
downstream re-verifies against an out-of-band provenance record.

## Where it has been measured

Signed Secondary Capture object, signature over content attributes the
de-identifier leaves intact, then de-identified:

| tool | Digital Signatures Sequence after de-identification |
|---|---|
| dcm4che `deidentify` (PS3.15 Basic Profile) | **removed** — silently; content untouched; not re-signed; MAC Parameters Sequence left orphaned |
| dicognito 0.19.0 | **kept** — a targeted anonymiser leaves it in place |

Two conformant tools disagree on whether the proof survives. Determine the entry's
applicability from the de-identifier your pipeline actually runs, not from the
standard.

The object above was constructed for the test, and the claim is that the
de-identifier **removes the Digital Signatures Sequence** — which holds
independently of whether the signature was cryptographically valid, since a
removed sequence cannot be verified at all.

## What constrains this entry rather than widens it

**DICOM digital signature adoption is low.** Most objects in production are never
signed, so for most pipelines C2 does not arise today. This entry applies where
signing is deployed — and it states the consequence of deploying it, which is that
a downstream de-identification step silently undoes it.

**De-identification legitimately invalidates signatures over changed attributes.**
Removing a signature that covered a patient identifier you just changed is
reasonable. The concerning case, and the one measured above, is when the signed
content is untouched and the proof is destroyed anyway with no re-signing.

## Risk control

**Effective.** Re-sign after de-identification. The standard permits it and does
not require it; require it in your pipeline. Where re-signing is not possible,
carry provenance in a record the de-identification step preserves or reproduces,
rather than only in the Digital Signatures Sequence it removes.

**Partial, and record them as partial.** Test the de-identifier you actually
deploy, not the one in the standard. Treat a de-identification software update as
a change to the object's authenticity properties, requiring re-verification. Have
downstream consumers treat a missing signature as unverified rather than as
absent, converting a silent acceptance into a visible one.

**Not effective.** Transport encryption, because the de-identifier terminates it
and operates on plaintext objects. Strengthening the signing algorithm, because
the signature is removed rather than defeated.

## Regulatory mapping

Assess under the Security Risk Management expected by FDA Section 524B and the
2026 premarket cybersecurity guidance, as a loss of a data-integrity control in
the total product lifecycle — particularly for AI/ML-enabled devices whose
training or validation data passes through de-identification. Confirm the mapping
against the current guidance text before citing it in a submission; this entry
states where it belongs, not what your reviewer will accept.

## The test that closes the entry

Do not decide C1–C4 by reading. With open tools:

```
# 1. build a signed DICOM object (pydicom + any signing), or use one you have
# 2. run the de-identifier your pipeline uses, e.g. dcm4che:
docker run --rm -v "$PWD":/w -w /w dcm4che/dcm4che-tools \
    deidentify /w/signed.dcm /w/out.dcm
# 3. check whether the signature survived:
python -c "import pydicom; d=pydicom.dcmread('out.dcm'); \
    print('signature present:', 0xFFFAFFFA in [e.tag for e in d])"
```

If the Digital Signatures Sequence is gone and nothing re-signed the object, the
entry applies. Run it against your own de-identifier and your own signing, and
close the entry with the result.

---

Full analysis of the class, including the negative results:
[doi:10.5281/zenodo.21840073](https://doi.org/10.5281/zenodo.21840073)

Cleiton Augusto Correa Bezerra · augusto.cleiton@gmail.com
