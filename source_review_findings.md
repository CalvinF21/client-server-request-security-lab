# Initial Source Review Findings

**Status:** Preliminary static-review observations, 2026-10-26. These are not confirmed vulnerabilities in TikTok production.

## LAB-SR-001 — Potential sensitive data in diagnostic logs
**Evidence from prior review:** `six_param_realtime.js` was described as logging URLs and MD5 input previews. URLs/query strings can contain identifiers or tokens.  
**Risk:** Secrets or identifiers may enter terminal logs, CI artifacts, or incident bundles.  
**Validation:** Use synthetic canary tokens in an isolated harness and confirm logs redact them.  
**Remediation:** Allowlist logged fields; omit query strings and signing preimages; redact cookies, authorization, tokens, device IDs, and signature headers.

## LAB-SR-002 — Python default-argument lifetime may reuse values
**Evidence:** Reviewed patterns include `random_bytes=urandom(4)` and a generated `sec_device_id` in a function signature. Python evaluates defaults once when defining the function, not on each call.  
**Risk:** A value intended to be fresh per call may instead be reused. Impact depends on whether callers override it and how the field is used.  
**Validation:** Compare repeated calls in one process and fresh processes using synthetic input.  
**Remediation:** Use `None` defaults and generate values inside the function where freshness is intended; document whether each value is per-install, per-session, or per-request.

## LAB-SR-003 — Embedded constants in client-side signing code
**Evidence:** The reviewed SignerPy Argus source contains byte constants named `sign_key` and `sm3_output`; other supplied code was also described as containing hardcoded signing constants.  
**Risk:** Client-distributed constants can be extracted. This does not prove they are production secrets or sufficient to forge accepted requests.  
**Validation:** Confirm internally whether constants are fixtures, protocol constants, or secret material; verify server-side enforcement and rotation.  
**Remediation:** Do not rely on a client-embedded secret as the sole trust boundary; bind integrity checks to identity, request content, freshness, and replay state.

## LAB-SR-004 — Example `/sign` service may be exposed as an unauthenticated signing oracle
**Evidence:** The reviewed `tr4cex/TikTok-Encryption` entry point was described as a Flask `/sign` API binding to `0.0.0.0:80`, with no visible authentication in that entry point.  
**Risk:** If reachable and deployed as-is, unauthorized callers may request signatures or submit sensitive values. This concerns that example service, not TikTok production.  
**Validation:** In an isolated deployment, inspect bind address, ingress, authentication, authorization, rate limits, and logs.  
**Remediation:** Loopback bind by default; authenticate and authorize remote callers; rate-limit; validate schema; never expose a signing oracle publicly.

## LAB-SR-005 — Replay controls are not proven by signature generation
**Evidence:** Client projects generate timestamps, nonce-like values, tickets, or signature headers; generation alone cannot prove that a server enforces freshness or uniqueness.  
**Risk:** If a verifier accepts repeated or stale signed requests, a valid request might be replayed in its authorization context. Production weakness is unconfirmed.  
**Validation:** Only with an authorized verifier or local mock, test repeated requests, stale timestamps, and atomic replay-state handling.  
**Remediation:** Enforce short validity windows, server-side nonce/ticket uniqueness, request-body binding, atomic replay checks, and idempotency for sensitive actions.

## LAB-SR-006 — Reproducibility gaps / unsupported equivalence claims
**Evidence:** The reviewed `fontjazz/douyin-seven-signatures` snapshot appeared to have a README without implementation or test vectors. The supplied `xtekky` Argus file had unresolved helper/global dependencies and did not appear independently executable.  
**Risk:** Results may be difficult to reproduce or overstated.  
**Validation:** Pin commit SHA, archive exact files, publish synthetic vectors, and distinguish unit tests from authorized server-acceptance tests.  
**Remediation:** Record provenance, checksums, environment, limitations, and independent review.

## LAB-SR-007 — Potential input-validation gaps in example signing API
**Evidence:** The reviewed `tr4cex` service accepted multiple caller-supplied signing fields; validation appeared limited and errors were described as generic.  
**Risk:** Malformed inputs may trigger exceptions, inconsistent outputs, or poor auditability.  
**Validation:** Exercise missing fields, wrong types, oversized values, and malformed encodings locally with synthetic data.  
**Remediation:** Strict schemas, size limits, normalized types, stable client errors, and access-controlled diagnostic logs.

## Confidence and severity
- **Confirmed language behavior:** Python default expressions are evaluated once per function definition.
- **Potential example-tool deployment issue:** all-interface `/sign` binding without visible auth, depending on deployment controls.
- **TikTok production vulnerabilities:** **not confirmed** by these client-side sources.

## Required evidence before a production finding is confirmed
Authorization/scope; exact commit and line numbers; sanitized reproduction; expected vs observed behavior; server-side corroboration; impact and severity rationale; remediation and retest criteria.
