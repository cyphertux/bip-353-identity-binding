# Spec-only Schnorr V2 audit harness (Phase 13)

**EXPERIMENTAL — NON-NORMATIVE**

Minimal verifier constructed from documentation + frozen vectors.
Does **not** import `reference/schnorr_v2/` or the independent JS tree.

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python audit/schnorr_v2_spec_only/verify_from_spec.py
```

See [`docs/SCHNORR_V2_SPEC_AUDIT.md`](../../docs/SCHNORR_V2_SPEC_AUDIT.md).
