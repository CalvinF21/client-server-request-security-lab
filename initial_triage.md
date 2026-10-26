# Initial Triage Board

This is a follow-up queue, not a claim of confirmed production vulnerabilities.

| ID | Topic | Status | Next evidence |
|---|---|---|---|
| LAB-SR-001 | Sensitive diagnostic logging | Validate locally | Canary-token redaction test and exact source lines |
| LAB-SR-002 | Default argument value reuse | Language behavior confirmed; impact unknown | Same-process and fresh-process synthetic test |
| LAB-SR-003 | Embedded signing constants | Pattern observed; meaning unknown | Owner confirmation and verifier evidence |
| LAB-SR-004 | Example `/sign` service exposure | Potential deployment risk | Bind/auth/ingress checks in isolated deployment |
| LAB-SR-005 | Replay resistance | Production status unknown | Authorized verifier replay tests |
| LAB-SR-006 | Reproducibility gaps | Artifact limitation observed | Pinned commits and reproducible vectors |
| LAB-SR-007 | Input validation | Potential example-service issue | Synthetic boundary tests |

Only mark a production finding **Confirmed** after authorized testing or server-side evidence establishes the control failure and impact.
