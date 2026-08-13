# SiteSealed Genesis v1.4-alpha.7.1 — MVP hotfix

Cette version clôt le MVP technique avec les deux rails externes retenus :

- **Evidency sandbox** pour demander et exporter un jeton RFC 3161 de test ;
- **Ethereum mainnet (chain ID 1)** comme rail public définitif pour les racines
  Merkle horaires.

L'alpha.7.1 conserve la vérification RFC 3161 indépendante introduite en
alpha.6 et la barrière de mise en service Ethereum Mainnet de l'alpha.7. Ce
hotfix ne change ni le schéma public des preuves ni le schéma MySQL. Il corrige
la reprise Railway des lots Ethereum et fonctionne en sélection automatique,
sans `ETHEREUM_TARGET_RECORD_ID` :

- sélection automatique des reçus éligibles, par ordre de création, dans un
  lot Merkle borné ;
- éligibilité limitée aux jetons Sandbox ayant réellement passé le validateur
  `SITESEALED_RFC3161_VALIDATOR_V1` ;
- dry-run sans création de lot, sans signature et sans diffusion ;
- correspondance obligatoire entre la clé et
  `ETHEREUM_EXPECTED_ANCHOR_ADDRESS` ;
- contrôle du chain ID, du gas estimé, du solde, du plafond en gwei et du
  plafond absolu en ETH ;
- redécodage local de la transaction signée et comparaison de tous les champs
  autorisés avant sa persistance ;
- une seule transaction au maximum par exécution, sans remplacement ni hausse
  automatique de frais ;
- statut partagé `DRY RUN`, `READY`, `SUBMITTED`, `CONFIRMED`, `FINALIZED` ou
  `ERROR`, sans présenter une simple configuration comme une finalisation.

Le jeton Evidency est vérifié avant toute persistance :
structure RFC 3161/CMS, attributs signés, signature cryptographique,
`ESSCertIDv2`, profil du certificat TSU, validité à `genTime` et chemin X.509
jusqu'à une racine Sandbox versionnée et épinglée dans la release. L'indicateur
ne devient `ON` qu'après stockage d'un jeton ayant franchi cette barrière. La
révocation reste explicitement `NOT_CHECKED` et le Sandbox reste sans valeur
qualifiée eIDAS.

La lignée alpha corrige également l'incompatibilité observée avec l'API Evidency du
12 août 2026 : l'OpenAPI actuel renvoie `timestamp` sous forme de chaîne
ISO 8601, tandis que l'ancien guide montrait un entier Unix en millisecondes.
L'adaptateur accepte les deux formats documentés, les normalise en UTC et
rejette les dates mal formées ou hors de la fenêtre d'émission attendue.

Elle corrige aussi les incompatibilités MySQL observées sur Railway. Le
protocole binaire de `mysql2` pouvait transmettre `LIMIT ?` ou certaines
valeurs du cycle de lot sous une forme refusée par MySQL avec
`ER_WRONG_ARGUMENTS` / `Incorrect arguments to COM_STMT_EXECUTE`. Les limites
de file sont strictement validées et émises comme littéraux entiers. Toutes les
lectures et écritures du cycle Ethereum (`PREPARED`, `SIGNED`, `SUBMITTED`,
`CONFIRMED`, `FINALIZED`) utilisent le protocole texte paramétré. Les données
de reçu, de preuve et de transaction restent séparées de la requête SQL.

Un lot déjà créé par l'alpha.7 est repris idempotemment. S'il est `PREPARED`,
le worker le signe puis le diffuse ; s'il est déjà `SIGNED`, il revalide et
rediffuse exactement la transaction persistée, sans la remplacer ni augmenter
les frais.

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
- contrôle croisé des métadonnées Evidency avec le `TSTInfo` signé : digest,
  numéro de série, `genTime` et policy OID ;
- vérification du `messageDigest` CMS et de la signature CMS avec le certificat
  réellement désigné par `SignerInfo` ;
- vérification de `signingCertificateV2` / `ESSCertIDv2`, de l'EKU critique
  exclusivement `id-kp-timeStamping`, du `keyUsage` et de la non-CA du TSU ;
- validation du chemin TSU → Timestamp CA → racine Sandbox épinglée, à l'heure
  certifiée ;
- conservation et export du jeton RFC 3161 avec sa propre empreinte SHA-256 ;
- arbre Merkle SHA-256 avec séparation de domaine entre feuilles et nœuds ;
- preuve d'inclusion individuelle, sans divulguer les autres reçus ;
- transaction EIP-1559 auto-adressée dont le calldata contient le préfixe
  `SSLD` version 1 puis la racine Merkle ;
- simulation Mainnet strictement sans écriture, ciblage exact et filtre
  d'éligibilité RFC 3161 indépendant ;
- vérification de l'adresse attendue, du réseau 1, du gas estimé, du solde et
  de deux plafonds de frais (`5 gwei` et `0.00015 ETH` par défaut) ;
- signature locale, redécodage et comparaison de la transaction, puis
  persistance avant diffusion ;
- suivi `SUBMITTED`, `CONFIRMED`, puis `FINALIZED`, avec contrôle du sender, du
  destinataire et du calldata ;
- bundle JSON v1.4 alpha, jeton `.tsr`, reçu PDF, lien Etherscan et vérificateur
  public ;
- worker Railway idempotent et verrouillé par Redis.
- état de fonctionnement Evidency partagé par Redis, avec expiration automatique
  si le worker ne publie plus de contrôle récent ;
- état Ethereum partagé séparément, avec preuve explicite de la liaison on-chain
  et de la finalité avant l'affichage `FINALIZED` ;
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
| `ON` | jeton sandbox reçu, signature CMS et chaîne épinglée validées, puis enregistré |
| `ERROR` | dernière exécution Evidency en échec |

Le statut Ethereum suit une machine distincte :

| Indicateur | Signification |
| --- | --- |
| `OFF` | worker Mainnet désactivé ou état récent absent |
| `DRY RUN` | sélection et contrôles RPC/coût réussis, zéro signature et zéro diffusion |
| `READY` | configuration chargée, aucune finalisation prouvée |
| `SUBMITTED` | transaction exacte diffusée, finalité en attente |
| `CONFIRMED` | confirmations atteintes, bloc finalisé encore non prouvé |
| `FINALIZED` | sender, destinataire, calldata, receipt et bloc finalisé vérifiés |
| `ERROR` | exécution arrêtée sans élargir les frais ni signer une autre transaction |

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
`1.4-alpha.1` pour préserver la compatibilité des preuves. L'alpha.7.1 ne
modifie ni le protocole de dépôt ni le schéma JSON public ; elle enrichit les
champs de preuve compatibles. La migration MySQL additive
`005_rfc3161_independent_verification` conserve l'état des anciens jetons sans
les présenter rétroactivement comme vérifiés.

## Cycle de vie du stockage privé

Le dépôt d'un ciphertext n'est plus anonyme et n'est plus gratuit. Une
autorisation d'envoi n'est jamais délivrée sur simple demande : elle doit être
achetée par une preuve de travail liée à cet objet précis, puis imputée sur un
budget de stockage partagé. La possession d'un grant n'est donc pas la frontière
d'autorisation ; la ressource rare l'est.

1. `POST /api/storage/upload-challenges` avec `{ submissionId,
   ciphertextSha256, byteLength }` renvoie `{ challengeId, algorithm,
   difficultyBits, expiresAt }`. Le défi est lié à ce triplet, à usage unique,
   valable **10 minutes**, et sa difficulté croît avec la taille annoncée
   (`UPLOAD_CHALLENGE_DIFFICULTY_BITS`, 16 bits par défaut, +1 bit au-delà de
   1 Mo, +2 bits au-delà de 8 Mo) ;
2. le navigateur cherche un `nonce` tel que
   `SHA-256("sitesealed:v1.4:upload-challenge:<challengeId>:<nonce>")` commence
   par `difficultyBits` bits à zéro. Le secret du `challengeId` étant tiré au
   hasard par le serveur, aucune solution ne peut être pré-calculée ni
   réutilisée pour un autre objet ;
3. `POST /api/storage/upload-grants` avec `{ submissionId, ciphertextSha256,
   byteLength, challengeId, nonce }` renvoie `{ grantId, expiresAt,
   remainingBudgetBytes }`. Un défi inconnu, expiré, déjà dépensé ou portant sur
   un autre objet renvoie `403 UPLOAD_CHALLENGE_REJECTED` ; un `nonce`
   insuffisant renvoie `403 UPLOAD_CHALLENGE_UNSOLVED`. Le défi est consommé
   atomiquement avant l'émission : une preuve de travail n'achète qu'un seul
   grant ;
4. l'émission vérifie qu'il reste au moins `byteLength` dans un budget
   **global** (toutes IP confondues) de `STORAGE_ADMISSION_MB_PER_DAY` (2048 Mo
   par défaut, fenêtre de 24 h) mais ne débite rien : le budget n'est imputé
   qu'au stockage effectif (étape 7), afin qu'un grant jamais utilisé ne prive
   personne de dépôt. Budget insuffisant : `429 STORAGE_ADMISSION_EXHAUSTED`
   avec `Retry-After`, à l'émission comme à l'envoi. Ce plafond borne le coût de
   stockage de l'opérateur même face à une rotation d'adresses IP ;
5. l'autorisation est conservée par le coordinateur (Redis en production,
   mémoire avec `DATABASE_MODE=optional`) pendant **15 minutes** ;
6. `PUT /api/storage/uploads/:submissionId` exige l'en-tête
   `X-SiteSealed-Upload-Grant`. Son absence renvoie `401
   UPLOAD_GRANT_REQUIRED`. Une autorisation inconnue, expirée, déjà consommée
   pour un autre objet, ou dont le `submissionId`, le `ciphertextSha256` ou le
   `byteLength` ne correspondent pas exactement renvoie `403
   UPLOAD_GRANT_REJECTED` ;
7. la taille réelle du ciphertext est débitée du budget global **avant** l'appel
   au stockage objet, puis l'autorisation est consommée atomiquement au premier
   stockage réussi. Un renvoi du **même** objet chiffré reste idempotent, ne
   débite rien de plus et répond `200` `ENCRYPTED_ORIGINAL_REUSED` ; une
   autorisation consommée ne peut jamais écrire un objet différent.

La limite anonyme par IP (`SEAL_RATE_LIMIT_PER_HOUR`, 20 par défaut) reste
appliquée aux trois points d'entrée. Le serveur ne reçoit toujours ni original
lisible ni clé AES : le défi comme l'autorisation ne portent que sur une
empreinte et une taille.

Cette barrière est un coût, pas une identité : elle ne remplace pas un quota
authentifié ou un droit payant, qui restent le seul moyen de rendre le dépôt
strictement nominatif. Tant que l'alpha reste anonyme, le budget global est le
plafond dur du coût opérateur et doit être calibré sur le Bucket réel. Il est
tenu par le coordinateur : avec `DATABASE_MODE=required` (Redis) il est
réellement partagé par toutes les instances, alors qu'en mode `optional` sans
Redis il redevient local au processus.

**Expiration des objets orphelins.** Un ciphertext peut être stocké sans que le
reçu correspondant soit jamais créé (abandon, erreur réseau, requête
malveillante). Ces objets orphelins ne sont pas supprimés par l'application :
aucune suppression de bucket n'est implémentée dans le code, afin qu'aucune
preuve référencée ne puisse être effacée par un bug applicatif. L'opérateur
**doit** configurer une règle de cycle de vie S3 sur le Bucket privé :

```text
Préfixe          : sealed/v1.2/
Action           : expiration des objets courants après 1 jour (24 h)
Portée attendue  : ciphertexts sans reçu MySQL associé
```

Les objets déjà liés à un reçu doivent être exclus de cette règle : supprimer
un ciphertext référencé casserait le téléchargement de la sauvegarde chiffrée
du kit de récupération. S3 ne peut pas lire le registre MySQL ; c'est donc à
l'opérateur de restreindre la portée de la règle (marquage d'objet appliqué par
un rapprochement externe, ou préfixe dédié) et de la vérifier sur un objet de
test avant de l'appliquer au Bucket de production. La suppression d'un
ciphertext, orphelin ou non, ne modifie jamais une preuve publique : le reçu,
l'empreinte du fichier et celle du ciphertext restent vérifiables sans l'objet.

## Structure utile

- `server/evidency.js` : client sandbox strict et barrière avant stockage ;
- `server/rfc3161.js` : validation DER, CMS, TSTInfo, ESSCertIDv2, certificat et
  chemin X.509 ;
- `server/trust/` : racine et CA Timestamp Sandbox publiques, versionnées et
  contrôlées par empreinte DER SHA-256 ;
- `server/merkle.js` : arbre et preuves d'inclusion déterministes ;
- `server/ethereum.js` : dry-run, plafonds, signature locale vérifiée,
  transaction mainnet et inspection de finalité ;
- `server/rails-worker.js` : orchestration idempotente des deux files ;
- `server/database.js` : migration, persistance des artefacts et reprise
  MySQL text-protocol des lots Ethereum ;
- `client/public/schemas/` : schéma JSON du bundle exporté ;
- le portail web recalcule dans le navigateur l'evidence digest, la preuve
  d'inclusion Merkle et la liaison du calldata Ethereum ;
- `scripts/verify-bundle.mjs` : vérification locale du reçu, du jeton et de la
  preuve Merkle ;
- `scripts/verify-timestamp.mjs` : vérificateur RFC 3161 autonome avec la même
  racine épinglée ;
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

Pour vérifier indépendamment la signature et le chemin du jeton exporté, sans
appel à Evidency ni accès à l'original :

```bash
npm run verify:timestamp -- \
  --token ./SiteSealed_record_Evidency_SANDBOX.tsr \
  --digest <evidenceDigest-du-bundle>
```

Les options `--serial`, `--time` et `--policy` permettent aussi de recouper les
métadonnées externes. Une rotation de certificat non intégrée à la release
échoue volontairement au lieu d'étendre silencieusement la confiance.

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
UPLOAD_CHALLENGE_DIFFICULTY_BITS=16
STORAGE_ADMISSION_MB_PER_DAY=2048

S3_ACCESS_KEY=${{"Bucket S3".ACCESS_KEY_ID}}
S3_BUCKET=${{"Bucket S3".BUCKET}}
S3_ENDPOINT=${{"Bucket S3".ENDPOINT}}
S3_REGION=${{"Bucket S3".REGION}}
S3_SECRET_KEY=${{"Bucket S3".SECRET_ACCESS_KEY}}
```

Les secrets des rails ne doivent pas être placés dans le service web. Le worker
publie dans Redis un état sanitaire limité et sans secret ; l'API le lit pour
afficher l'état réel de chaque rail. Evidency peut atteindre `ON`; Ethereum ne
peut atteindre `FINALIZED` qu'après contrôle on-chain et finalité.

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
EVIDENCY_TARGET_RECORD_ID=
EVIDENCY_DRY_RUN=false
EVIDENCY_MAX_REQUESTS_PER_RUN=1
EVIDENCY_RUNTIME_STATUS_TTL_SECONDS=90000

ETHEREUM_ANCHOR_MODE=mainnet
ETHEREUM_RPC_URL=<endpoint WSS Ethereum mainnet>
ETHEREUM_ANCHOR_PRIVATE_KEY=<secret Railway>
ETHEREUM_EXPECTED_ANCHOR_ADDRESS=<adresse publique 0x du portefeuille dédié>
ETHEREUM_DRY_RUN=true
ETHEREUM_MAX_TRANSACTIONS_PER_RUN=1
ETHEREUM_CONFIRMATIONS=12
ETHEREUM_MAX_FEE_GWEI=5
ETHEREUM_MAX_TX_FEE_ETH=0.00015
ETHEREUM_GAS_LIMIT=30000
ANCHOR_MAX_BATCH_SIZE=1024
ETHEREUM_RUNTIME_STATUS_TTL_SECONDS=90000
```

`ETHEREUM_TARGET_RECORD_ID` doit être absent du service Railway. Son absence
active la sélection automatique ; aucun identifiant de reçu n'est nécessaire.
Un second fournisseur RPC n'est pas requis pour exécuter le worker. Il peut
être ajouté plus tard comme contrôle d'audit indépendant, sans faire partie de
la configuration opérationnelle.

`ETHEREUM_ANCHOR_PRIVATE_KEY` doit appartenir à un portefeuille dédié, peu
approvisionné et sans autre usage. Le cron dépense de vrais ETH. Ne colle jamais
la clé privée dans Git, un ticket, un log ou une conversation ; ajoute-la
directement comme secret Railway.

Mise en service contrôlée :

1. déployer l'alpha.7.1 avec `ETHEREUM_ANCHOR_MODE=disabled`, puis vérifier le
   build, les migrations et le fonctionnement Evidency existant ;
2. créer un portefeuille Ethereum dédié et sans autre actif. Conserver sa clé
   uniquement comme secret du worker et copier son adresse publique dans
   `ETHEREUM_EXPECTED_ANCHOR_ADDRESS` ;
3. approvisionner ce portefeuille du strict montant choisi pour les tests et
   vérifier l'adresse par une seconde source avant tout transfert ;
4. créer un reçu alpha.7.1, attendre son jeton Evidency Sandbox, puis vérifier que
   `validatorVersion`, `signatureVerification` et
   `certificateChainVerification` ont les valeurs exigées ;
5. laisser `ETHEREUM_TARGET_RECORD_ID` absent, activer
   `ETHEREUM_ANCHOR_MODE=mainnet` et laisser `ETHEREUM_DRY_RUN=true` ;
6. lancer le worker manuellement. Le résultat attendu est `DRY_RUN`, au moins
   un élément éligible dans `selected`, `transactionsSigned: 0` et
   `transactionsBroadcast: 0`. Contrôler l'adresse, la racine, le gas estimé,
   le solde et `maximumAuthorizedFeeEth` ;
7. définir seulement `ETHEREUM_DRY_RUN=false`, puis relancer une fois. Noter le
   `transactionHash`; le résultat normal est `SUBMITTED` tant que le bloc n'est
   pas finalisé ;
8. relancer le même worker pour le suivi. Il réinspecte le même hash et ne crée
   ni transaction de remplacement ni hausse automatique de frais. Attendre
   `runtime.ethereum.status: finalized`, avec
   `onChainBindingVerified: true` et `finalityVerified: true` ;
9. vérifier le reçu, le bundle, le calldata et la finalité via
   `npm run verify:bundle` et le lien Etherscan exporté ;
10. après cette validation seulement, activer le cron horaire. Conserver
    `ETHEREUM_MAX_TRANSACTIONS_PER_RUN=1`, `ANCHOR_MAX_BATCH_SIZE=1024` et les
    deux plafonds de coût.

Toute incohérence d'adresse, réseau, signature, preuve RFC 3161, gas, frais,
solde ou liaison on-chain fait échouer le run. Une transaction déjà signée
reste persistée et sera reprise à l'identique ; l'alpha.7.1 ne la remplace jamais
silencieusement.

### Reprise directe d'un lot alpha.7 interrompu

Aucune nouvelle preuve Evidency, aucune nouvelle adresse et aucun identifiant
de reçu ne sont nécessaires. Laisser le cron désactivé, déployer l'alpha.7.1,
supprimer `ETHEREUM_TARGET_RECORD_ID`, conserver le même portefeuille et le
même réseau, puis lancer le worker une fois avec `ETHEREUM_DRY_RUN=false`. Le
lot `PREPARED` ou `SIGNED` existant est retrouvé avant toute nouvelle sélection.
Le résultat attendu est `SUBMITTED`; une exécution ultérieure suit ensuite le
même hash jusqu'à `FINALIZED`.

## Limites restantes

- Evidency sandbox : test uniquement, sans valeur qualifiée ;
- révocation CRL/OCSP : `NOT_CHECKED` ; la chaîne cryptographique valide ne
  prouve donc pas l'absence de révocation ;
- la racine épinglée est exclusivement la racine Sandbox et ne constitue pas
  une politique de confiance Production/eIDAS ;
- pas de capture in-app attestée, identité, appareil ou GNSS ;
- pas de preuve de véracité, d'auteur ou de scène non mise en scène ;
- pas encore d'audit de sécurité indépendant ni de procédure de gestion de clé
  institutionnelle.

L'alpha prouve ce qu'elle peut recalculer et expose explicitement tout le reste.
