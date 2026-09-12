# Batch106 — Promotion Gate / Integration PR Controller

Batch106 closes the final promotion gap between a Batch105 verified isolation branch and `main`.

The gate intentionally separates two decisions:

1. **PR creation eligibility** — Batch105 must already report `verified-on-isolated-branch`, repository tests must pass, the persisted integration verifier must pass, and successful CI evidence must refer to the exact verified head SHA.
2. **Merge authorization** — immediately before merge, the repository base HEAD, verified branch HEAD, PR base/head, embedded proof markers and CI evidence are checked again.

## Promotion proof

A promotion manifest binds:

- base branch and expected base HEAD;
- verified isolation branch and exact verified head SHA;
- candidate `event|challenge|family` signature;
- Batch105 verification digest;
- repository-test digest;
- full-regression digest;
- expected-delta digest;
- successful CI run metadata.

The resulting `promotionId` is derived deterministically from this proof.

## PR evidence markers

`buildPromotionPrRequest()` renders the promotion id, candidate signature, verified head SHA, expected base HEAD and verification digest into the integration PR body. Merge validation requires those markers to remain present.

## TOCTOU policy

A promotion becomes stale when either:

- `main` no longer equals the expected base HEAD; or
- the isolated integration branch no longer equals the verified head SHA.

A stale promotion returns `stale-revalidation-required`; it must go through the validation path again. Batch106 never treats a previous green test or previous verification result as authorization for a later repository state.

## Merge contract

`authorizePromotionMerge()` emits `merge-authorized` only for an exact point-in-time match and returns:

- squash merge policy;
- exact `expectedHeadSha`;
- exact base HEAD that must still match.

The repository client must still pass `expectedHeadSha` to the final merge operation. Batch106 does not directly merge branches.
