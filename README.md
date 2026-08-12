# SiteSealed Genesis v1.3

SiteSealed v1.3 prolonge le premier parcours réel de scellement avec une couche
d'exploitation distribuée, sans modifier la limite de preuve du Founding
Whitepaper v1.0.

## Ce qui est réellement fonctionnel

- sélection d'un fichier réel dans le navigateur ;
- calcul local de l'empreinte SHA-256 ;
- chiffrement local AES-256-GCM du manifeste et de l'original ;
- clé AES et jeton de récupération conservés uniquement dans le kit privé ;
- stockage du seul ciphertext dans un Bucket S3 privé ;
- registre persistant des reçus, empreintes et références S3 dans MySQL ;
- journal opérationnel append-only et hash-chaîné dans PostgreSQL ;
- limitation de débit distribuée, verrou d'idempotence court et cache de
  vérification public dans Redis ;
- identifiant public, vérification locale, bundle JSON, récupération chiffrée
  et reçu PDF dynamique.

Le serveur ne reçoit jamais l'original lisible, le manifeste lisible ou la clé
AES. PostgreSQL ne reçoit que des empreintes et références publiques du reçu.
Redis ne contient aucune donnée faisant autorité et peut être vidé sans perdre
un reçu ou un objet.

## Limite honnête de la v1.3

La chaîne PostgreSQL détecte les altérations accidentelles et ordonne les
événements applicatifs, mais elle reste administrée par SiteSealed. Elle n'est
donc ni une preuve indépendante, ni un horodatage qualifié, ni un ancrage
public. La v1.3 ne fournit toujours pas :

- de jeton qualifié RFC 3161 émis par un QTSP ;
- de racine Merkle ancrée sur une blockchain publique ;
- de capture in-app attestée avec identité, appareil et GNSS ;
- de preuve que la scène était vraie ou non mise en scène.

MySQL, PostgreSQL, Redis et S3 sont des composants d'exploitation. Aucun ne
remplace les deux rails externes exigés par le whitepaper.

## Répartition stricte des responsabilités

| Service | Rôle | Source de vérité | Données lisibles originales |
| --- | --- | --- | --- |
| MySQL | Registre opérationnel des reçus et références S3 | Oui, pour l'index applicatif v1.3 | Non |
| Bucket S3 | Ciphertexts AES-256-GCM privés | Oui, pour les octets chiffrés | Non |
| PostgreSQL | Événements de reçus append-only, reliés par SHA-256 | Oui, pour l'audit interne uniquement | Non |
| Redis | Limites distribuées, verrous courts et cache public | Non | Non |

Le protocole de dépôt chiffré reste `1.2` pour préserver les objets et kits déjà
créés. La version de l'application et du bundle enrichi est `1.3`.

## Structure

- `client/` : React 19, Vite, Web Crypto et interface responsive ;
- `server/database.js` : registre MySQL et migrations `001` à `003` ;
- `server/storage.js` : validation et stockage S3 du ciphertext ;
- `server/audit.js` : migration PostgreSQL, événements append-only et chaîne SHA-256 ;
- `server/coordination.js` : Redis distribué et adaptateur mémoire local ;
- `server/server.js` : API Express, healthcheck et service du build React ;
- `scripts/verify-bundle.mjs` : vérification locale du reçu et de l'événement d'audit ;
- `railway.json` : build, migrations préalables, démarrage et healthcheck.

## Développement local

```bash
npm ci
npm run dev:full
```

Avec `DATABASE_MODE=optional`, les services absents sont remplacés par des
adaptateurs mémoire réservés au développement. Ils disparaissent au redémarrage.

Pour utiliser les quatre dépendances localement, copie `.env.example` vers
`.env`, adapte les URL et les cinq variables S3, puis exécute :

```bash
npm run db:migrate
npm run dev:full
```

## Tests

```bash
npm test
```

La suite compile React et contrôle notamment le chiffrement client, les limites
de taille, MySQL, le stockage S3, la chaîne d'audit, l'idempotence, le cache,
la limitation de débit, les bundles, les reçus PDF et la limite honnête des
preuves externes.

Un bundle peut aussi être vérifié hors du site :

```bash
npm run verify:bundle -- ./proof-bundle.json ./original.pdf ./encrypted-original.ssenc
```

## Déploiement Railway

Le projet comprend cinq services :

- `SiteSealed` : React compilé, Express et API ;
- `MySQL` : registre persistant ;
- `Bucket S3` : originaux chiffrés côté client ;
- `Postgres` : audit opérationnel append-only ;
- `Redis` : coordination distribuée non autoritaire.

Dans **SiteSealed > Variables**, configure exactement :

```text
DATABASE_MODE=required
MYSQL_URL=${{MySQL.MYSQL_URL}}
DATABASE_URL=${{Postgres.DATABASE_URL}}
REDIS_URL=${{Redis.REDIS_URL}}

PUBLIC_BASE_URL=https://app.sitesealed.com
SEAL_RATE_LIMIT_PER_HOUR=20

S3_ACCESS_KEY=${{"Bucket S3".ACCESS_KEY_ID}}
S3_BUCKET=${{"Bucket S3".BUCKET}}
S3_ENDPOINT=${{"Bucket S3".ENDPOINT}}
S3_REGION=${{"Bucket S3".REGION}}
S3_SECRET_KEY=${{"Bucket S3".SECRET_ACCESS_KEY}}
```

Ne copie jamais les valeurs réelles dans Git : utilise les références Railway.
Avec `DATABASE_MODE=required`, le démarrage échoue volontairement si MySQL,
PostgreSQL, Redis ou S3 n'est pas complètement configuré.

Railway exécute `npm run build`, puis `npm run db:migrate` en pre-deploy, puis
`npm start`. La commande de migration applique MySQL et PostgreSQL de manière
idempotente ; Redis ne requiert aucun schéma.

Après déploiement, `/api/health` doit notamment indiquer :

```json
{
  "ok": true,
  "service": "sitesealed",
  "version": "1.3.0",
  "database": {
    "mode": "mysql",
    "status": "connected",
    "persistent": true
  },
  "objectStorage": {
    "mode": "s3",
    "status": "connected",
    "clientEncryptedOnly": true
  },
  "auditDatabase": {
    "mode": "postgresql",
    "status": "connected",
    "appendOnly": true,
    "hashChained": true,
    "independentlyAnchored": false
  },
  "coordination": {
    "mode": "redis",
    "status": "connected",
    "authoritative": false,
    "distributed": true
  }
}
```

Les URL privées `DATABASE_URL` et `REDIS_URL` sont les variables standard
fournies par les services Railway du même projet.
