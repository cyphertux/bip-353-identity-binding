# BIP Draft Notes (M8)

## Authority

`BIP-XXX.md` (repository root) is a **transcription** of `PROTOCOL_FREEZE_V1.md` (this directory).  
The freeze remains authoritative if any wording conflict appears.

## Non-modifications

* No wire-format changes
* No vector regeneration or edits
* No V2 features introduced as normative V1 requirements
* Fingerprints remain raw `bstr`
* Candidate A and `B353ID` OP_RETURN unchanged

## Diagnostic error codes

`PROTOCOL_FREEZE_V1.md` §21 lists the essential V1 error set.  
The reference verifier also emits more specific document-parse diagnostics used by frozen invalid vectors, including:

* `INVALID_DOMAIN`
* `DOMAIN_IDENTIFIER_INCONSISTENT`
* `FIELD_TYPE:*`
* `PARSE_ERROR:*`

These are compatible with the freeze (stricter diagnostics). They are not alternate wire formats.

## BIP number

The placeholder `XXX` awaits assignment by the Bitcoin BIP editor process. No IANA/BIP namespace reservation is claimed beyond this draft.

## Suggested public review focus

1. Claim matrix honesty (especially freshness / human identity)
2. Dual Bitcoin binding (`raw_tx` authority)
3. Multi-B353ID rejection rule
4. Header context `trusted` vs `untrusted`
