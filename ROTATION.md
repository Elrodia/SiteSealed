# Evidency timestamp certificate rotation

The checked-in [trust manifest](server/trust/anchors.v1.json) is SiteSealed's local approval policy. Deploy it together with the public certificates it references. Do not fetch or promote new trust anchors while serving a request. An RFC 3161 response can carry its signer's certificate (`certReq`); possession of that certificate is not an approval. Never put private keys, API keys or credentials in this directory.

## How a path is accepted

Each path stays in one environment: signer → timestamp issuer → root. The manifest pins SHA-256 over the **DER certificate**, not over the PEM text. The chain, signature and message imprint must still pass the RFC 3161 verifier. Several approved paths can be active simultaneously.

| Status | New issuance | Historical verification |
| --- | --- | --- |
| `active` | Allowed if every member of the path passes verification | Allowed at the token's signed `genTime`, subject to normal validity checks |
| `retiring` | Not accepted for new issuance | Allowed only for tokens with `genTime` **strictly before** the recorded UTC cutoff (`retireAt`) |
| `revoked` | Rejected | Rejected by the current local policy, including pre-revocation tokens |

These restrictions apply to **every member** of the path. Keep the old public certificates, dated manifest revisions and original tokens. A present-day local refusal is neither permission to alter the historical evidence nor a legal determination that every earlier token is invalid. The local denylist is **not** a CRL or OCSP service: do not report a positive issuer revocation check or qualified status based on this manifest.

## Planned rotation

1. Assign someone to review the vendor's [certification page, certificate history and published revocation lists](https://evidency.io/en/eidas-certification/). Do not rely on receiving advance notice. Use `/api/health` to monitor the release's 90-day expiration warnings; it cannot discover a new certificate or a provider revocation by itself.
2. Obtain the replacement public certificate and independently confirm its provenance, environment, role, issuer and DER SHA-256 before approval. For a local PEM certificate: `openssl x509 -in candidate.pem -noout -fingerprint -sha256 -dates -subject -issuer`. Compare the complete fingerprint with an authenticated reference; for a new root or ambiguous publication, obtain separate confirmation through a known vendor channel. A new issuer is not necessarily a new root. An item moving to the vendor's history page does not itself prove revocation.
3. In one reviewed change, add the certificate files and manifest entries under new IDs, point each child to its approved parent, increment `revision`, and record the source and reason in the commit. Keep the old path active during any overlap in which the provider can still issue with either signer. Avoid replacing a certificate's bytes under its existing ID.
4. Exercise valid tokens for both paths, an unapproved signer and the retirement boundary. Run `npm test` and `npm run verify:dual-rail-freeze`. Release one immutable revision to both the web service and the rails worker. If the deployments cannot switch together, pause processing until both are on that revision. Confirm health and a fresh sample before resuming.
5. Once the provider has stopped using the old path, mark the superseded member `retiring` with its documented exclusive UTC cutoff. Do not retire a parent that another active path still needs. Test a historical token from before the cutoff, a token at the cutoff, and rejection for new issuance. Repeat the release checks above.

## Unexpected signer, suspected compromise or emergency revocation

- Unknown certificate: retain the original token for investigation, refuse a verified status, and obtain independent confirmation. Do not infer trust from an unfamiliar certificate embedded in a response.
- Suspected compromise: pause affected processing while investigating. For a confirmed revocation, publish a new revision marking the affected member `revoked`. Record the source and time of the decision; review stored proofs through the updated verifier.
- Deploy the deny decision to **both** services before resuming. Verify that affected paths fail even for historical tokens and that independent unaffected paths still work. Never roll back to a manifest revision that re-enables the revoked certificate. If code rollback is needed, carry forward the latest deny decision.

## Production boundary

SANDBOX remains test-only. Adding a PRODUCTION certificate or updating this file does not enable production or establish the qualification of a token. Until production onboarding, independent trust and revocation checks, and explicit production configuration have been completed and tested, do not label an Evidence Record as qualified or sealed on this basis.
