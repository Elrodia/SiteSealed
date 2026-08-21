# SiteSealed 1.6.0-alpha.2 — social metadata and eight-language reports

This release adds the official 1200 × 628 SiteSealed social preview to the
deployed application and declares complete Open Graph and Twitter Card metadata
with absolute HTTPS URLs.

Public-facing application, landing-page and Evidence Report headings no longer
display the software release number. The technical version remains available in
the repository, package metadata, report manifest and runtime status surface.

The application and canonical Evidence Reports now ship in eight locales:
`en-US`, `fr-BE`, `nl-BE`, `de-DE`, `pt-BR`, `es-ES`, `it-IT` and `lb-LU`.
The non-standard input `lu-LU` is accepted and normalized to the standard
Luxembourgish locale `lb-LU`. Open Graph locale alternates cover the full set.

Long translated desktop navigation now compacts before it can exceed the
viewport and switches to the menu layout at 1240 px, preventing the horizontal
page drift previously visible with German copy.

The Evidency sandbox adapter, Ethereum mainnet anchor, Railway service files and
their environment-variable contract are unchanged.
