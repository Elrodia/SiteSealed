# SiteSealed 1.5.0-alpha.3

## Identité visuelle du rapport

- l'en-tête de chaque page du SiteSealed Evidence Report utilise désormais le
  favicon SiteSealed officiel à la place du monogramme provisoire `SS` ;
- le statut `ALPHA DUAL RAIL COMPLETE` est agrandi, centré et maintenu dans son
  cartouche sans débordement ;
- le favicon est incorporé dans le générateur afin que le rapport reste
  déterministe et ne dépende pas d'un chargement réseau au moment de l'export.

## Non-régression du dual rail

Evidency Sandbox, Ethereum Mainnet, le worker Rails, `.env.example` et les deux
configurations Railway restent inchangés. Aucune variable Railway n'est ajoutée,
retirée ou renommée.
