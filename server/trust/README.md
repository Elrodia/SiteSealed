# Evidency Sandbox trust material

SiteSealed validates RFC 3161 tokens offline against a release-pinned Evidency
Sandbox trust path. These files are public certificates, not credentials.

| File | Upstream source | DER SHA-256 |
| --- | --- | --- |
| `evidency-sandbox-root-ca.pem` | `https://api-sandbox.evidency.io/pub/cer/sandbox-root-ca.cer` | `6871a6ed629cbefd77caee74a6bf6a9c22d96a8c26065dac75651e2e36a8b62d` |
| `evidency-sandbox-timestamp-ca.pem` | `https://api-sandbox.evidency.io/pub/cer/sandbox-timestamp-ca.cer` | `05d89655a8bd51ec3100a9d062432b19ce018f861c9e209d50026c7e6322597b` |
| `evidency-sandbox-tsu01.pem` | Original, already chain-verified sandbox regression token in `../fixtures/evidency-sandbox-token-20260812.json` | `2f0bd0feed6b00dbb2d62e2bc374ed30e0b159f957fa4859c9d63308f959881e` |

The checked-in `anchors.v1.json` manifest pins all three certificates' DER
fingerprints. The timestamp CA is an intermediate, not a root. No unapproved
signer or chain from a token is enrolled at runtime. Production has no enrolled
path. See [rotation, emergency procedures and scope](../../ROTATION.md).

Provider revocation (CRL/OCSP) is reported as `NOT_CHECKED`.
Signature, message-imprint, signer-profile, certificate-path and
validity-at-`genTime` verification do not imply a revocation check or qualified
eIDAS status.
