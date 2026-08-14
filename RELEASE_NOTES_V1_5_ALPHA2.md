# SiteSealed 1.5.0-alpha.2

## Correction du parcours de récupération live

La version `alpha.1` contenait toutes les données privées nécessaires dans le
Recovery Kit, mais le portail de vérification ne les exploitait que pour relire
le manifeste. Il exigeait encore la photographie originale, alors que le
parcours caméra live ne garantit pas que l'utilisateur en conserve une copie.

`alpha.2` ferme cette incohérence :

- le Recovery Kit identifie le reçu et fournit la clé AES ainsi que le jeton de
  récupération privé ;
- le navigateur dérive lui-même l'endpoint same-origin du reçu et ne fait pas
  confiance à une URL contenue dans le kit ;
- le ciphertext est récupéré depuis le stockage privé, puis son volume et son
  SHA-256 sont vérifiés avant déchiffrement ;
- AES-256-GCM authentifie et déchiffre l'original exclusivement dans le
  navigateur ;
- le SHA-256 du plaintext est comparé au reçu public avant que le rapport ne
  puisse être généré ;
- le manifeste privé est lui aussi recalculé et comparé à son empreinte
  enregistrée ;
- pour `LIVE_CAPTURE_WEB`, aucune photographie séparée n'est désormais requise.

Le Recovery Kit reste une capacité privée, pas une copie autonome du
ciphertext. Il suffit tant que l'objet chiffré référencé reste disponible. Le
bouton d'export du backup `.ssenc` demeure disponible pour une conservation
indépendante supplémentaire.

## Non-régression du dual rail

Evidency Sandbox, Ethereum Mainnet, le worker Rails, `.env.example` et les deux
configurations Railway ne sont pas modifiés. Aucune variable Railway n'est
ajoutée, retirée ou renommée.
