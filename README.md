# SiteSealed Genesis v1.4-alpha.4

Cette alpha construit les deux rails externes choisis pour le QTSP :

- **Evidency sandbox** pour demander et exporter un jeton RFC 3161 de test ;
- **Ethereum mainnet (chain ID 1)** comme rail public définitif pour les racines
  Merkle horaires.

L'alpha.4 relie le statut public Evidency au worker séparé sans copier ses
secrets dans le service web. L'indicateur ne devient `ON` qu'après réception,
contrôle du digest et stockage d'un vrai jeton sandbox. L'interface sombre
permanente reste active sur desktop et mobile ; le reçu PDF conserve son fond
clair afin de rester imprimable.

Cette version corrige l'incompatibilité observée avec l'API Evidency du
12 août 2026 : l'OpenAPI actuel renvoie `timestamp` sous forme de chaîne
ISO 8601, tandis que l'ancien guide montrait un entier Unix en millisecondes.
L'adaptateur accepte les deux formats documentés, les normalise en UTC et
rejette les dates mal formées ou hors de la fenêtre d'émission attendue.

Le mot `sealed` reste volontairement désactivé. Un jeton Evidency sandbox n'a
aucun effet juridique et ne devient jamais un horodatage qualifié eIDAS. Même
avec un ancrage mainnet finalisé, l'état maximal de cette version est
`ALPHA_DUAL_RAIL_COMPLETE`.

## Ce qui fonctionne réellement

- SHA-256 du fichier dans le navigateur ;
- AES-256-GCM du manifeste et de l'original avant tout envoi ;
- stockage du seul ciphertext dans un Bucket S3 privé ;
- registre MySQL, audit PostgreSQL append-only et coordination Redis ;
- evidence digest séparé par domaine, lié aux empreintes du fichier et du
  manifeste ;
- requête digest-only vers `https://api-sandbox.evidency.io` ;
- contrôle de la réponse Evidency : statut, algorithme et digest renvoyé ;
- conservation et export du jeton RFC 3161 avec sa propre empreinte SHA-256 ;
- arbre Merkle SHA-256 avec séparation de domaine entre feuilles et nœuds ;
- preuve d'inclusion individuelle, sans divulguer les autres reçus ;
- transaction EIP-1559 auto-adressée dont le calldata contient le préfixe
  `SSLD` version 1 puis la racine Merkle ;
- signature locale, persistance de la transaction signée avant diffusion,
  plafond de frais et vérification du réseau 1 ;
- suivi `SUBMITTED`, `CONFIRMED`, puis `FINALIZED`, avec contrôle du sender, du
  destinataire et du calldata ;
- bundle JSON v1.4 alpha, jeton `.tsr`, reçu PDF, lien Etherscan et vérificateur
  public ;
- worker Railway idempotent et verrouillé par Redis.
- état de fonctionnement Evidency partagé par Redis, avec expiration automatique
  si le worker ne publie plus de contrôle récent ;
- rafraîchissement automatique de l'indicateur web toutes les 30 secondes.

Le serveur ne reçoit jamais l'original lisible, le manifeste lisible ou la clé
AES. Evidency reçoit uniquement l'evidence digest. Ethereum reçoit uniquement
une racine de lot, jamais un nom de fichier, une empreinte directe de fichier ou
un identifiant de reçu.

## Machine d'état honnête

| État | Evidency | Ethereum | `sealed` |
| --- | --- | --- | --- |
| `EXTERNAL_PROOFS_PENDING` | absent | absent | `false` |
| `SANDBOX_TIMESTAMP_ISSUED_ANCHOR_PENDING` | test sandbox | absent | `false` |
| `MAINNET_ANCHORED_QTSP_PENDING` | non qualifié/absent | finalisé | `false` |
| `ALPHA_DUAL_RAIL_COMPLETE` | test sandbox | finalisé | `false` |
| `DUAL_RAIL_COMPLETE` | qualifié + signature validée | finalisé | `true` |

La dernière ligne existe dans le modèle de données pour la future production,
mais cette alpha ne peut pas l'atteindre.

Le statut d'infrastructure Evidency est distinct du statut probatoire d'un reçu :

| Indicateur | Signification |
| --- | --- |
| `OFF` | worker désactivé ou état récent absent |
| `DRY RUN` | sélection contrôlée, sans appel à Evidency |
| `READY` | clés chargées, mais aucun jeton réussi n'est encore enregistré |
| `ON` | jeton sandbox reçu, lié au digest attendu et enregistré |
| `ERROR` | dernière exécution Evidency en échec |

## Responsabilités

| Composant | Rôle | Autoritaire | Original lisible |
| --- | --- | --- | --- |
| MySQL | Reçus, preuves externes et lots Merkle | Oui pour l'index applicatif | Non |
| Bucket S3 | Ciphertexts AES-256-GCM | Oui pour les octets chiffrés | Non |
| PostgreSQL | Événements internes hash-chaînés | Audit interne uniquement | Non |
| Redis | Limites, verrous, cache et statut récent des rails | Non | Non |
| Evidency sandbox | Jeton RFC 3161 de test | Artefact externe de test | Non, digest seulement |
| Ethereum mainnet | Racine Merkle publique | Rail public | Non, racine seulement |

Le protocole privé de dépôt reste `1.2` afin de préserver les objets et kits de
récupération existants. Le reçu et le bundle publics passent en
`1.4-alpha.1` pour préserver la compatibilité des preuves. L'alpha.4 ne modifie
ni le protocole cryptographique ni le schéma public ; elle rend le statut du
worker observable sans exposer ses secrets. La migration MySQL
`004_dual_rail_alpha` reste additive.

## Structure utile

- `server/evidency.js` : client sandbox strict et validation de réponse ;
- `server/merkle.js` : arbre et preuves d'inclusion déterministes ;
- `server/ethereum.js` : transaction mainnet, plafond de frais et inspection ;
- `server/rails-worker.js` : orchestration idempotente des deux files ;
- `server/database.js` : migration et persistance des artefacts ;
- `client/public/schemas/` : schéma JSON du bundle exporté ;
- le portail web recalcule dans le navigateur l'evidence digest, la preuve
  d'inclusion Merkle et la liaison du calldata Ethereum ;
- `scripts/verify-bundle.mjs` : vérification locale du reçu, du jeton et de la
  preuve Merkle ;
- `railway.json` : service web ;
- `railway.rails.json` : service cron des rails externes.

## Développement et tests

```bash
npm ci
npm test
```

Pour un démarrage local sans dépendances persistantes :

```bash
cp .env.example .env
npm run dev:full
```

Avec `DATABASE_MODE=optional`, les adaptateurs mémoire sont réservés au
développement et disparaissent au redémarrage. Les deux rails externes sont
désactivés par défaut : aucun appel Evidency et aucune dépense ETH ne peuvent se
produire sans activation explicite.

Pour vérifier un bundle hors du site :

```bash
npm run verify:bundle -- ./proof-bundle.json ./original.pdf ./encrypted-original.ssenc
```

Le script valide l'intégrité du reçu, la liaison du token exporté à l'evidence
digest et le chemin Merkle. Pour vérifier aussi le calldata, le sender, le bloc
et la finalité via un RPC mainnet indépendant :

```bash
ETHEREUM_VERIFY_RPC_URL=https://votre-rpc-mainnet.example \
  npm run verify:bundle -- ./proof-bundle.json ./original.pdf
```

Le script ne qualifie pas la signature du jeton sandbox.
Cette validation exige la chaîne de confiance publiée par le prestataire et un
outil RFC 3161 indépendant.

## Déploiement Railway

Le projet Railway contient les services existants `SiteSealed`, `MySQL`,
`Bucket S3`, `Postgres` et `Redis`, plus un nouveau service **SiteSealed Rails**
créé depuis le même dépôt GitHub.

### 1. Service web `SiteSealed`

Il garde `/railway.json` comme chemin de configuration. Ses variables sont :

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

Les secrets des rails ne doivent pas être placés dans le service web. Le worker
publie dans Redis un état sanitaire limité et sans secret ; l'API le lit pour
afficher `OFF`, `DRY RUN`, `READY`, `ON` ou `ERROR`.

### 2. Service cron `SiteSealed Rails`

Dans **Settings**, définir le chemin de configuration sur
`/railway.rails.json`. Ne configure pas encore de cron pendant le premier test.
Après le premier ancrage contrôlé, ajoute `0 * * * *` dans **Cron Schedule**
(au début de chaque heure, UTC). Ce processus traite les reçus, vérifie les lots
déjà soumis et se termine ; il ne doit pas être déployé comme serveur permanent.

Variables de ce service :

```text
DATABASE_MODE=required
MYSQL_URL=${{MySQL.MYSQL_URL}}
DATABASE_URL=${{Postgres.DATABASE_URL}}
REDIS_URL=${{Redis.REDIS_URL}}

EVIDENCY_MODE=sandbox
EVIDENCY_API_BASE_URL=https://api-sandbox.evidency.io
EVIDENCY_API_KEY=<secret Railway>
EVIDENCY_PROJECT_KEY=<clé du projet sandbox>
EVIDENCY_TIMEOUT_MS=12000
EVIDENCY_BATCH_SIZE=50
EVIDENCY_TARGET_RECORD_ID=<identifiant exact du reçu test>
EVIDENCY_DRY_RUN=true
EVIDENCY_MAX_REQUESTS_PER_RUN=1
EVIDENCY_RUNTIME_STATUS_TTL_SECONDS=90000

ETHEREUM_ANCHOR_MODE=disabled
ETHEREUM_RPC_URL=<endpoint HTTPS/WSS mainnet>
ETHEREUM_ANCHOR_PRIVATE_KEY=<secret Railway>
ETHEREUM_CONFIRMATIONS=12
ETHEREUM_MAX_FEE_GWEI=60
ETHEREUM_GAS_LIMIT=30000
ANCHOR_MAX_BATCH_SIZE=1024
```

`ETHEREUM_ANCHOR_PRIVATE_KEY` doit appartenir à un portefeuille dédié, peu
approvisionné et sans autre usage. Le cron dépense de vrais ETH. Ne colle jamais
la clé privée dans Git, un ticket, un log ou une conversation ; ajoute-la
directement comme secret Railway.

Déploiement prudent :

1. déployer et vérifier les migrations avec les deux modes laissés à
   `disabled` ;
2. créer un reçu de test, renseigner son identifiant dans
   `EVIDENCY_TARGET_RECORD_ID`, définir `EVIDENCY_MODE=sandbox` et lancer le
   worker avec `EVIDENCY_DRY_RUN=true` ; le résultat doit être `DRY_RUN`, avec
   exactement ce reçu dans `selected`, `attempted: 0` et l'indicateur
   `DRY RUN` ;
3. définir `EVIDENCY_DRY_RUN=false`, puis lancer une seule fois le worker.
   `EVIDENCY_MAX_REQUESTS_PER_RUN=1` empêche toute émission en masse, même si
   `EVIDENCY_BATCH_SIZE` vaut 50 ;
4. vérifier `attempted: 1`, `issued: 1`,
   `runtime.evidency.status: operational`, le reçu public, le jeton `.tsr` et
   l'indicateur `ON` ;
5. conserver l'identifiant ciblé et le plafond à `1`. Une fois ce contrôle
   réussi, le cron horaire peut être activé avec Ethereum toujours désactivé :
   le reçu déjà horodaté n'est pas éligible à une seconde émission et le worker
   rafraîchit son état de fonctionnement ;
6. approvisionner le portefeuille dédié, vérifier son adresse et le RPC
   mainnet ;
7. activer `ETHEREUM_ANCHOR_MODE=mainnet`, lancer un premier petit lot sous
   surveillance, puis seulement activer le cron horaire.

Ne retire `EVIDENCY_TARGET_RECORD_ID` et n'augmente
`EVIDENCY_MAX_REQUESTS_PER_RUN` qu'après validation explicite du premier jeton.

Une erreur Evidency, une transaction invalide ou un dépassement du plafond de
frais fait échouer le run sans transformer le reçu en preuve complète. Les lots
signés restent en base afin qu'un run ultérieur reprenne sans signer
silencieusement une seconde transaction.

## Limites restantes

- Evidency sandbox : test uniquement, sans valeur qualifiée ;
- signature du token : conservée mais pas marquée `VALID` par l'alpha ;
- pas de capture in-app attestée, identité, appareil ou GNSS ;
- pas de preuve de véracité, d'auteur ou de scène non mise en scène ;
- pas encore d'audit de sécurité indépendant ni de procédure de gestion de clé
  institutionnelle.

L'alpha prouve ce qu'elle peut recalculer et expose explicitement tout le reste.
