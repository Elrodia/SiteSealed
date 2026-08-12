# Evidency Sandbox trust material

SiteSealed validates RFC 3161 tokens offline against a release-pinned Evidency
Sandbox trust path. These files are public certificates, not credentials.

| File | Upstream source | DER SHA-256 |
| --- | --- | --- |
| `evidency-sandbox-root-ca.pem` | `https://api-sandbox.evidency.io/pub/cer/sandbox-root-ca.cer` | `6871a6ed629cbefd77caee74a6bf6a9c22d96a8c26065dac75651e2e36a8b62d` |
| `evidency-sandbox-timestamp-ca.pem` | `https://api-sandbox.evidency.io/pub/cer/sandbox-timestamp-ca.cer` | `05d89655a8bd51ec3100a9d062432b19ce018f861c9e209d50026c7e6322597b` |

The certificates were retrieved and independently fingerprinted on
2026-08-12. Both fingerprints are compiled into `server/rfc3161.js`; a changed
file fails closed. The timestamp CA is treated as an intermediate. Only the
pinned sandbox root is a trust anchor.

Certificate revocation is intentionally reported as `NOT_CHECKED` in
v1.4-alpha.6. Signature, message-imprint, signer-profile, certificate-path and
validity-at-`genTime` verification do not imply a revocation check or qualified
eIDAS status.
