# SiteSealed 1.6.0-alpha.1 — five-locale i18n

This release internationalizes the SiteSealed application and its browser-built
Evidence Reports in five locales:

- English (US) — `en-US`
- Français (Belgique) — `fr-BE`
- Nederlands (België) — `nl-BE`
- Deutsch — `de-DE`
- Português (Brasil) — `pt-BR`

The header language selector persists the selected locale and exposes it through
the `lang` query parameter. Visible application copy, validation and recovery
messages, accessibility labels, metadata, dates, numbers and byte sizes follow
that locale. Google Identity Services receives the corresponding locale code.

The canonical Evidence Report is generated in the selected language. Its human
labels, scope explanations, rail descriptions, PDF metadata and attachment
descriptions are localized. The exact original remains visibly represented and
embedded byte-for-byte in the same PDF.

Canonical evidence data is deliberately language-neutral. Record and rail state
codes, schemas, SHA-256 values, encrypted manifests, RFC 3161 material, Merkle
proofs, transaction hashes and Ethereum calldata are unchanged.

The static whitepaper and specimen documents remain their existing source
documents and are outside this release's translation scope.

The Evidency Sandbox and Ethereum Mainnet implementations, Railway descriptors
and environment-variable contract remain protected by the dual-rail freeze.
