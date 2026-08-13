# SiteSealed Genesis v1.4-alpha.9 — dépôts liés à un compte Google

SiteSealed crée des reçus d'intégrité SHA-256, conserve uniquement un original
chiffré côté client et attache deux rails externes asynchrones :

- un jeton RFC 3161 **Evidency Sandbox**, vérifié cryptographiquement mais sans
  effet qualifié eIDAS ;
- une racine Merkle écrite sur **Ethereum Mainnet (chain ID 1)** par le worker
  horaire, avec une transaction au maximum par exécution.

L'alpha.9 remplace entièrement le secret partagé de l'alpha.8 par
**Continue with Google**. Il n'existe plus de variable
`UPLOAD_ADMISSION_SECRET`, de champ « Deposit access » ni d'en-tête contenant
un mot de passe opérateur.

## Frontière de sécurité de l'alpha.9

Google Identity Services authentifie le compte avec un ID token OpenID Connect.
Le serveur vérifie sa signature, son audience, son émetteur et l'adresse e-mail
vérifiée, puis crée sa propre session opaque dans Redis :

- cookie de session `HttpOnly`, `Secure` en HTTPS, `SameSite=Lax` et limité au
  chemin `/` ;
- jeton CSRF propre à SiteSealed pour toutes les mutations JSON ;
- contrôle « double submit cookie » sur le retour Google ;
- aucune conservation de l'ID token, d'un access token ou d'un refresh token ;
- aucun accès aux API Google ; seuls `openid`, `email` et `profile` sont utilisés ;
- le `sub` Google brut n'est pas exposé : un identifiant local SHA-256 séparé
  par domaine lie la session, les grants et le quota.

Le compte autorise uniquement la **création** d'un dépôt. Il ne prouve pas
l'auteur du fichier et n'est pas ajouté au reçu public. La consultation, le
bundle, le PDF et le vérificateur public restent accessibles sans compte.

Si `GOOGLE_OAUTH_CLIENT_ID` manque ou est invalide, le serveur reste en ligne et
la vérification publique continue de fonctionner. L'interface indique que la
connexion Google n'est pas configurée et bloque seulement la création de reçus.

### Admission d'un objet chiffré

Une limite par IP n'est pas une autorisation. L'alpha.9 cumule les barrières
suivantes :

1. `POST /api/storage/upload-grants` exige une session Google valide et un
   jeton CSRF SiteSealed ;
2. Redis émet un grant aléatoire de 15 minutes lié au compte, au
   `submissionId`, aux empreintes, à l'IV et aux tailles exactes ;
3. le `PUT /api/storage/uploads/:submissionId` réclame atomiquement ce grant
   **avant** qu'Express ne lise jusqu'à 25 Mio de corps ;
4. un grant autorise un seul objet, ne peut pas être transféré à un autre
   compte et ne déclenche qu'une seule écriture S3, même en concurrence ;
5. les octets sont réservés atomiquement dans un plafond Redis par compte
   (256 Mio/24 h par défaut) et un plafond global (2 048 Mio/24 h par défaut) ;
6. les limites de 20/h par IP **et** par compte restent des défenses
   supplémentaires.

Le ciphertext arrive sous `staging/v1.2/`. La création du reçu exige le même
grant complété, promeut l'objet vérifié sous `sealed/v1.2/`, persiste le reçu,
puis supprime le staging. Une panne S3 libère le claim pour une reprise exacte
sans débiter une deuxième fois le quota.

Les Buckets Railway ne fournissant pas de règle Lifecycle utilisable par cette
application, le worker horaire supprime uniquement les objets `staging/`
orphelins et non finalisés âgés de plus de 24 heures. Il ne touche jamais à
`sealed/`.

## Ce qui fonctionne réellement

- SHA-256 du fichier dans le navigateur ;
- AES-256-GCM du manifeste et de l'original avant tout envoi ;
- session de compte Google vérifiée, opaque et stockée côté serveur dans Redis ;
- grant exact, à usage unique, lié au compte et réclamé avant lecture du corps ;
- quotas Redis global et par compte, limites par IP et par compte ;
- stockage du seul ciphertext dans un Bucket S3 privé ;
- registre MySQL, audit PostgreSQL append-only hash-chaîné et coordination Redis ;
- requête digest-only vers Evidency Sandbox ;
- validation RFC 3161/CMS indépendante : empreinte, signature, `ESSCertIDv2`,
  profil TSU et chemin X.509 vers la racine Sandbox épinglée ;
- arbre Merkle avec séparation de domaine et preuve d'inclusion individuelle ;
- transaction EIP-1559 auto-adressée dont le calldata contient `SSLD`, la
  version 1 et la racine Merkle ;
- contrôles du chain ID, de l'adresse attendue, du gas, du solde et des plafonds
  de frais avant signature ;
- persistance de la transaction signée avant diffusion, reprise idempotente et
  contrôle on-chain jusqu'à `FINALIZED` ;
- bundle JSON, jeton `.tsr`, PDF, lien Etherscan et vérificateur public ;
- nettoyage borné des staging orphelins par le worker Railway horaire.

Le serveur ne reçoit jamais l'original lisible, le manifeste lisible ou la clé
AES. Evidency reçoit uniquement l'evidence digest. Ethereum reçoit uniquement
une racine de lot. Google ne reçoit pas le fichier ni son empreinte.

## Machine d'état honnête

| État | Evidency | Ethereum | `sealed` |
| --- | --- | --- | --- |
| `EXTERNAL_PROOFS_PENDING` | absent | absent | `false` |
| `SANDBOX_TIMESTAMP_ISSUED_ANCHOR_PENDING` | test sandbox | absent | `false` |
| `MAINNET_ANCHORED_QTSP_PENDING` | non qualifié/absent | finalisé | `false` |
| `ALPHA_DUAL_RAIL_COMPLETE` | test sandbox | finalisé | `false` |
| `DUAL_RAIL_COMPLETE` | qualifié + signature validée | finalisé | `true` |

L'alpha.9 ne peut pas atteindre la dernière ligne. Le mot `sealed` reste
désactivé, car le Sandbox Evidency n'est pas un horodatage qualifié.

| Indicateur Evidency | Signification |
| --- | --- |
| `OFF` | worker désactivé ou état récent absent |
| `DRY RUN` | sélection sans appel externe |
| `READY` | configuration chargée, aucun jeton validé récent |
| `ON` | jeton sandbox reçu, vérifié et enregistré |
| `ERROR` | dernière exécution en échec |

| Indicateur Ethereum | Signification |
| --- | --- |
| `OFF` | worker Mainnet désactivé ou état récent absent |
| `DRY RUN` | contrôles RPC/coût réussis, aucune signature |
| `READY` | configuration chargée, aucune finalisation prouvée |
| `SUBMITTED` | transaction exacte diffusée |
| `CONFIRMED` | confirmations atteintes, finalité encore en attente |
| `FINALIZED` | sender, destinataire, calldata, receipt et bloc finalisé vérifiés |
| `ERROR` | exécution arrêtée sans signer une autre transaction |

## Responsabilités

| Composant | Rôle | Original lisible |
| --- | --- | --- |
| MySQL | Reçus, preuves externes et lots Merkle | Non |
| Bucket S3 | Ciphertexts AES-256-GCM | Non |
| PostgreSQL | Audit applicatif interne hash-chaîné | Non |
| Redis | Sessions, grants, quotas, limites, verrous, cache et état des rails | Non |
| Google Identity Services | Authentification du compte de dépôt | Non |
| Evidency Sandbox | Jeton RFC 3161 de test | Non, digest seulement |
| Ethereum Mainnet | Racine Merkle publique | Non, racine seulement |

Le protocole privé de dépôt reste `1.2` et le schéma public reste
`1.4-alpha.1` afin de préserver la compatibilité des preuves et kits existants.
L'alpha.9 ne modifie pas le schéma MySQL.

## Développement et tests

```bash
npm ci
npm test
```

Sans Google configuré, le développement local permet toujours la consultation
et la vérification. Pour tester la création de reçu, créer un client OAuth Web
Google autorisant l'origine locale et définir dans `.env` :

```text
PUBLIC_BASE_URL=http://localhost:5173
GOOGLE_OAUTH_CLIENT_ID=<client Web>.apps.googleusercontent.com
AUTH_SESSION_TTL_HOURS=168
```

Le reverse proxy de développement doit acheminer `/api` vers le serveur. Aucun
Google client secret n'est utilisé.

Pour vérifier un bundle hors du site :

```bash
npm run verify:bundle -- ./proof-bundle.json ./original.pdf ./encrypted-original.ssenc
```

Pour vérifier le jeton RFC 3161 indépendamment :

```bash
npm run verify:timestamp -- \
  --token ./SiteSealed_record_Evidency_SANDBOX.tsr \
  --digest <evidenceDigest-du-bundle>
```

## Configuration Google Cloud

Dans le projet Google Cloud qui doit porter la connexion :

1. ouvrir **Google Auth Platform** et configurer Branding/Audience pour
   l'application ;
2. dans **Clients**, créer un **OAuth client ID** de type **Web application** ;
3. ajouter l'origine JavaScript autorisée exacte :
   `https://app.sitesealed.com` ;
4. ajouter l'URI de redirection autorisée exacte :
   `https://app.sitesealed.com/api/auth/google/callback` ;
5. copier uniquement le **Client ID** dans Railway sous
   `GOOGLE_OAUTH_CLIENT_ID`.

Ne crée pas et ne copie pas de Google client secret pour ce flux : SiteSealed
utilise le bouton Google Identity Services et vérifie l'ID token côté serveur,
sans appeler une API Google.

## Déploiement Railway

Le projet contient le service web `SiteSealed`, MySQL, Bucket S3, Postgres,
Redis et le service cron séparé `SiteSealed Rails`.

### Service web `SiteSealed`

Conserver `/railway.json` comme chemin de configuration et définir :

```text
DATABASE_MODE=required
MYSQL_URL=${{MySQL.MYSQL_URL}}
DATABASE_URL=${{Postgres.DATABASE_URL}}
REDIS_URL=${{Redis.REDIS_URL}}

PUBLIC_BASE_URL=https://app.sitesealed.com
GOOGLE_OAUTH_CLIENT_ID=<client Web>.apps.googleusercontent.com
AUTH_SESSION_TTL_HOURS=168
SEAL_RATE_LIMIT_PER_HOUR=20
UPLOAD_GRANT_TTL_SECONDS=900
STORAGE_ADMISSION_MB_PER_DAY=2048
STORAGE_ADMISSION_MB_PER_USER_PER_DAY=256

S3_ACCESS_KEY=${{"Bucket S3".ACCESS_KEY_ID}}
S3_BUCKET=${{"Bucket S3".BUCKET}}
S3_ENDPOINT=${{"Bucket S3".ENDPOINT}}
S3_REGION=${{"Bucket S3".REGION}}
S3_SECRET_KEY=${{"Bucket S3".SECRET_ACCESS_KEY}}
```

Il ne faut définir ni `UPLOAD_ADMISSION_SECRET`, ni Google client secret dans
Railway. Les secrets Evidency et Ethereum restent exclusivement dans le worker.

### Service cron `SiteSealed Rails`

Définir `/railway.rails.json` comme chemin de configuration. Après validation
manuelle, utiliser `0 * * * *` comme cron (une exécution au début de chaque
heure, UTC). Le processus traite les files, vérifie les transactions déjà
soumises, nettoie les staging expirés, puis se termine.

```text
DATABASE_MODE=required
MYSQL_URL=${{MySQL.MYSQL_URL}}
DATABASE_URL=${{Postgres.DATABASE_URL}}
REDIS_URL=${{Redis.REDIS_URL}}

S3_ACCESS_KEY=${{"Bucket S3".ACCESS_KEY_ID}}
S3_BUCKET=${{"Bucket S3".BUCKET}}
S3_ENDPOINT=${{"Bucket S3".ENDPOINT}}
S3_REGION=${{"Bucket S3".REGION}}
S3_SECRET_KEY=${{"Bucket S3".SECRET_ACCESS_KEY}}
STAGING_OBJECT_TTL_HOURS=24
STAGING_REAPER_MAX_OBJECTS=1000

EVIDENCY_MODE=sandbox
EVIDENCY_API_BASE_URL=https://api-sandbox.evidency.io
EVIDENCY_API_KEY=<secret Railway>
EVIDENCY_PROJECT_KEY=<clé du projet Sandbox>
EVIDENCY_TIMEOUT_MS=12000
EVIDENCY_BATCH_SIZE=50
EVIDENCY_TARGET_RECORD_ID=
EVIDENCY_DRY_RUN=false
EVIDENCY_MAX_REQUESTS_PER_RUN=1
EVIDENCY_RUNTIME_STATUS_TTL_SECONDS=90000

ETHEREUM_ANCHOR_MODE=mainnet
ETHEREUM_RPC_URL=<endpoint WSS Ethereum Mainnet>
ETHEREUM_ANCHOR_PRIVATE_KEY=<secret Railway>
ETHEREUM_EXPECTED_ANCHOR_ADDRESS=<adresse publique du portefeuille dédié>
ETHEREUM_DRY_RUN=true
ETHEREUM_MAX_TRANSACTIONS_PER_RUN=1
ETHEREUM_CONFIRMATIONS=12
ETHEREUM_MAX_FEE_GWEI=5
ETHEREUM_MAX_TX_FEE_ETH=0.00015
ETHEREUM_GAS_LIMIT=30000
ANCHOR_MAX_BATCH_SIZE=1024
ETHEREUM_RUNTIME_STATUS_TTL_SECONDS=90000
```

`ETHEREUM_TARGET_RECORD_ID` doit rester absent : la sélection est automatique.
Un seul endpoint RPC opérationnel est requis. Le portefeuille doit être dédié,
peu approvisionné et sans autre usage. Le cron horaire groupe jusqu'à 1 024
reçus dans une racine et n'autorise qu'une transaction par exécution ; il ne
dépense donc pas des ETH toutes les 15 minutes.

Pour la première mise en service, conserver `ETHEREUM_DRY_RUN=true`, lancer le
worker manuellement et vérifier `transactionsSigned: 0` et
`transactionsBroadcast: 0`. Passer ensuite une seule fois à `false`, noter le
`transactionHash`, puis relancer le même worker jusqu'à `FINALIZED`. Activer le
cron horaire seulement après ce contrôle.

Une transaction déjà `SIGNED` ou `SUBMITTED` est reprise à l'identique. Le
worker ne crée pas de remplacement et n'augmente pas automatiquement les frais.
Une transaction encore dans le mempool reste `SUBMITTED` tant qu'aucun reçu de
bloc n'existe : ses champs transitoires ne peuvent plus provoquer un faux
`INVALID_ON_CHAIN`. Un lot précédemment classé ainsi reste réinspectable et peut
passer à `FINALIZED` sans nouvelle signature, diffusion ou dépense d'ETH.

## Limites restantes

- Evidency Sandbox n'a aucune valeur qualifiée eIDAS ;
- révocation CRL/OCSP : `NOT_CHECKED` ;
- pas de capture in-app attestée, de confiance appareil ou de GNSS ;
- la connexion Google autorise le dépôt mais ne prouve ni l'auteur ni la scène ;
- pas de preuve de véracité ou de scène non mise en scène ;
- pas encore d'audit de sécurité indépendant ni de politique institutionnelle
  de gestion des clés.

L'alpha prouve ce qu'elle peut recalculer et expose explicitement tout le reste.
