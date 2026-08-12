# SiteSealed Genesis v1.2

Premier parcours réel de scellement du projet SiteSealed, conforme à la limite
de preuve énoncée dans le Founding Whitepaper v1.0.

La v1.2 permet de :

- sélectionner un vrai fichier dans le navigateur ;
- calculer son empreinte SHA-256 localement ;
- construire puis chiffrer son manifeste et son original en AES-256-GCM localement ;
- conserver la clé exclusivement dans un kit privé téléchargé par le client ;
- envoyer uniquement le ciphertext de l'original vers un Bucket S3 privé ;
- enregistrer dans MySQL les empreintes, la référence S3, le manifeste chiffré et un reçu serveur ;
- retrouver le reçu avec un identifiant public non séquentiel ;
- recalculer localement l'empreinte d'un original et la comparer au reçu ;
- récupérer le ciphertext S3 uniquement avec le jeton du kit privé ;
- exporter un bundle JSON et un reçu PDF dynamique.

L'original lisible, le manifeste lisible et la clé AES ne sont jamais transmis
à l'API. Le navigateur envoie seulement le ciphertext authentifié de l'original
et les empreintes. La route JSON de création refuse explicitement les champs
supplémentaires qui pourraient contenir un original encodé.

## Limite honnête de la v1.2

Le reçu v1.2 est une preuve d'intégrité en développement. Il ne constitue pas
encore le scellement dual-rail défini par le whitepaper :

- aucun jeton qualifié RFC 3161 n'est émis ;
- aucun ancrage Merkle n'est écrit sur une blockchain publique ;
- l'heure affichée est celle du serveur SiteSealed/MySQL, sans présomption
  eIDAS ;
- le parcours web est une importation explicitement étiquetée, pas une capture
  live attestée ;
- aucune identité, position GNSS, attestation d'appareil, qualité d'auteur ou
  véracité du contenu n'est prouvée.

Ces absences sont enregistrées et affichées comme `NOT_ISSUED` et
`NOT_ANCHORED`. Elles ne sont jamais remplacées par des preuves simulées, sauf
pour le dossier historique portant explicitement la mention `SPECIMEN`.

## Architecture

- `client/` : React 19 + Vite, hachage Web Crypto et chiffrement client ;
- `server/` : Node 22 + Express, API, PDF, MySQL et S3 compatible ;
- `server/storage.js` : validation du ciphertext, stockage S3 privé et contrôle d'intégrité ;
- `server/database.js` : migrations idempotentes et index persistant des objets ;
- `scripts/verify-bundle.mjs` : vérificateur local indépendant ;
- `railway.json` : compilation, migration préalable, démarrage et healthcheck.

## Développement local

Prérequis : Node.js 22.13 ou supérieur.

```bash
npm ci
npm run dev:full
```

Sans MySQL ni S3 local, l'application utilise des mémoires temporaires. Les
reçus et ciphertexts créés ainsi disparaissent au redémarrage ; cette
possibilité sert uniquement au développement.

Pour une base et un stockage S3 compatibles en local, copier `.env.example`
vers `.env`, adapter `MYSQL_URL` et les cinq variables `S3_*`, puis exécuter :

```bash
npm run db:migrate
npm run dev:full
```

## Vérification complète

```bash
npm test
```

La suite compile React et contrôle notamment : validation des requêtes,
chiffrement du manifeste, idempotence, persistance abstraite MySQL, rails
externes honnêtement absents, chiffrement de l'original, stockage privé S3,
contrôle du jeton de récupération, bundle JSON, PDF dynamique, limite anonyme,
healthcheck et service de la SPA.

Un bundle téléchargé peut aussi être vérifié hors du site :

```bash
npm run verify:bundle -- SiteSealed_RECORD_proof-bundle.json original.pdf encrypted-original.ssenc
```

Ce script recalcule le SHA-256 du reçu et, lorsqu'ils sont fournis, ceux du
fichier original et du ciphertext téléchargé. Il rappelle explicitement que
l'heure qualifiée et l'ancrage public n'existent pas encore.

## Déploiement Railway

Le projet utilise trois services Railway normaux :

- `SiteSealed` : React compilé puis servi par Express, API comprise ;
- `MySQL` : base persistante et son volume ;
- `Bucket S3` : stockage privé des originaux chiffrés côté client.

Dans les variables du service `SiteSealed` :

```text
MYSQL_URL=${{MySQL.MYSQL_URL}}
DATABASE_MODE=required
PUBLIC_BASE_URL=https://app.sitesealed.com
SEAL_RATE_LIMIT_PER_HOUR=20
S3_ACCESS_KEY=${{"Bucket S3".ACCESS_KEY_ID}}
S3_BUCKET=${{"Bucket S3".BUCKET}}
S3_ENDPOINT=${{"Bucket S3".ENDPOINT}}
S3_REGION=${{"Bucket S3".REGION}}
S3_SECRET_KEY=${{"Bucket S3".SECRET_ACCESS_KEY}}
```

Ne jamais copier la valeur réelle de `MYSQL_URL`, `S3_ACCESS_KEY` ou
`S3_SECRET_KEY` dans Git. Avec `DATABASE_MODE=required`, la v1.2 refuse de
démarrer si une des cinq variables S3 manque : elle ne peut donc pas basculer
silencieusement sur un stockage volatile en production. Railway exécute
automatiquement `npm run build`, puis `npm run db:migrate` en pre-deploy, puis
`npm start`.

Après déploiement, `/api/health` doit indiquer :

```json
{
  "ok": true,
  "service": "sitesealed",
  "version": "1.2.0",
  "sealing": {
    "workflow": "IMPORTED_FILE_CLIENT_ENCRYPTED_STORAGE_RECEIPT",
    "clientEncryptedObjectStorage": true,
    "qualifiedTimestamp": false,
    "publicChainAnchor": false
  },
  "database": {
    "mode": "mysql",
    "status": "connected",
    "persistent": true,
    "writable": true
  },
  "objectStorage": {
    "mode": "s3",
    "status": "connected",
    "persistent": true,
    "writable": true,
    "private": true,
    "clientEncryptedOnly": true
  }
}
```

La migration `003_private_encrypted_object_storage` enrichit la table v1.1 sans
supprimer le spécimen existant ni les tables réservées aux futurs rails A et B.
Le démarrage vérifie également que le Bucket est joignable et inscriptible.
