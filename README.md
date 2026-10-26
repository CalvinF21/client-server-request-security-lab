# Client–Server Request Security Lab

A local-only defensive lab for request integrity, replay protection, logging hygiene, source review, and incident reporting. It uses a fictional API and synthetic data. It does **not** contact TikTok/Douyin production endpoints or implement their production signatures.

## Start
Requires Python 3.10+; standard library only.

Terminal 1: `python -m lab.server`  
Terminal 2: `python -m lab.client --demo`  
Tests: `python -m unittest discover -s tests -v`

The server binds to `127.0.0.1:8765`. Logs are written to `logs/events.jsonl` with likely sensitive fields redacted.

## Mock protocol
The lab HMAC-signs `timestamp + newline + nonce + newline + SHA256(raw_body)` using a local demo secret. The server checks timestamp freshness, signature integrity, and nonce reuse. These `X-Lab-*` headers are invented for this exercise and are not TikTok headers.

## Evidence boundary
The included source review consolidates observations from the supplied `six_param_offline.py`, `six_param_realtime.js`, `tr4cex/TikTok-Encryption`, `xtekky/TIkTok-X-Argus`, `fontjazz/douyin-seven-signatures`, and `is-L7N/SignerPy` materials as described during review. Findings are preliminary source-level risks, not confirmed TikTok production vulnerabilities. Client code alone cannot establish production server acceptance rules, key custody, or replay protections.

## Safe use
Use only on localhost, owned systems, or explicitly authorized environments. Do not upload credentials, cookies, production signatures, or raw sensitive logs. Do not use this project to forge production signatures, bypass protections, or probe live TikTok/Douyin APIs.

## Suggested GitHub repo
Name: `client-server-request-security-lab`  
Topics: `application-security`, `request-integrity`, `replay-protection`, `incident-response`, `security-testing`, `python`.
