# SiteSealed Genesis v1.6.0-alpha.1 — International Evidence Reports

SiteSealed crée des enregistrements d'intégrité et un seul artefact humain
canonique : le **SiteSealed Evidence Report PDF**. Le rapport affiche l'original,
l'incorpore byte-for-byte comme fichier source associé, décrit la portée exacte
de la preuve et rassemble les artefacts des deux rails externes.

## Internationalisation de l’interface et des rapports

L’application et les Evidence Reports sont disponibles en anglais américain
(`en-US`), français de Belgique (`fr-BE`), néerlandais de Belgique (`nl-BE`),
allemand (`de-DE`) et portugais brésilien (`pt-BR`). La langue est choisie dans
l’en-tête, conservée localement et propagée au générateur PDF. Les dates,
nombres et tailles sont formatés selon la locale sélectionnée. Les données
canoniques de preuve — codes d’état, schémas, empreintes, manifestes, signatures,
preuves Merkle et données Ethereum — ne sont jamais traduites ni modifiées.

Cette version avance vers le whitepaper sans transformer une capacité web en
promesse excessive. Elle introduit une classe de capture web liée à un compte,
à un défi serveur frais, à une fenêtre temporelle et à une géolocalisation
rapportée par le navigateur. Elle conserve l'import de fichiers préexistants
comme classe distincte et explicitement moins probante.

## Frontière probatoire essentielle

Le navigateur peut imposer l'usage de `getUserMedia` dans l'interface officielle,
mais il ne fournit pas à SiteSealed une attestation matérielle du capteur. Un
client hostile peut appeler l'API autrement, simuler une caméra ou soumettre des
coordonnées falsifiées. Par conséquent :

- SiteSealed **prouve** l'identité byte-for-byte de l'original et du manifeste
  avec leurs empreintes enregistrées ;
- le serveur **atteste** qu'une session Google a obtenu un défi frais et a lié
  les déclarations de contexte à une soumission dans la fenêtre admise ;
- SiteSealed **ne prouve pas** que les pixels viennent d'un capteur physique, que
  la scène n'est pas rejouée ou mise en scène, ni que la position du navigateur
  correspond à une position GNSS authentifiée.

Une photo de février 2024 ne devient donc jamais cryptographiquement « prise
aujourd'hui » du seul fait de son upload. Dans la classe importée, sa date, son
lieu et son auteur restent expressément non vérifiés. Dans la classe web live,
le rapport montre les déclarations liées au défi, tout en affichant l'absence
d'attestation matérielle. La cible complète du whitepaper — caméra native,
attestation appareil, GNSS et horloge attestée, file hors ligne — reste une étape
native ultérieure.

## Deux classes qui ne se confondent jamais

| Classe | Entrée | Contexte lié | Ce qui reste non prouvé |
| --- | --- | --- | --- |
| `LIVE_CAPTURE_WEB` | Image produite par la caméra intégrée à l'interface | Session Google pseudonymisée, défi serveur à usage unique, fenêtre de 2 minutes, horloge du navigateur, position W3C et précision | Capteur physique, intégrité du navigateur, GNSS matériel, scène non rejouée ou non mise en scène |
| `IMPORTED_FILE` | Photo, PDF ou autre fichier préexistant | Heure de réception serveur et empreintes cryptographiques | Heure et lieu de capture, auteur, origine matérielle, véracité du contenu |

Les métadonnées EXIF et la valeur locale `lastModified` ne sont jamais traitées
comme une preuve de temps ou de lieu.

## Flux `LIVE_CAPTURE_WEB`

1. L'utilisateur continue avec Google ; SiteSealed crée une session opaque dans
   Redis et ne conserve aucun jeton Google.
2. L'interface ouvre la caméra avec `navigator.mediaDevices.getUserMedia`.
3. Au clic de capture, `POST /api/capture/challenges` émet un secret aléatoire
   lié au compte et au `submissionId`. La fenêtre de capture est de 2 minutes et
   le claim Redis expire après 15 minutes.
4. Le navigateur demande une position W3C, capture une frame JPEG et construit
   un manifeste canonique contenant caméra, heure, défi, coordonnées et
   précision. Les coordonnées précises restent dans ce manifeste chiffré.
5. L'original et le manifeste sont hachés localement. Le manifeste et l'original
   sont chiffrés en AES-256-GCM avant tout envoi ; la clé ne quitte pas le client.
6. Le dépôt S3 exige toujours la session Google, le CSRF, le grant exact à usage
   unique, les quotas Redis et la limite par IP/compte.
7. La création du reçu réclame atomiquement le défi et vérifie compte,
   soumission, empreintes, temps déclaré et contexte. Le secret du défi n'est
   jamais persistant dans le reçu public.
8. Immédiatement après la capture, le PDF est généré localement avec l'original
   encore présent en mémoire. Pour une régénération ultérieure, le Recovery Kit
   récupère le ciphertext référencé depuis le stockage privé, le vérifie, le
   déchiffre localement et reconstitue le même original sans demander une photo
   séparée. Le générateur recalcule ensuite les deux empreintes et recoupe le
   manifeste avec le contexte attesté par le serveur.

## Un seul artefact canonique

Il n'existe aucune variante publique/privée du rapport. Le serveur, qui ne
possède que du ciphertext, ne fabrique pas de PDF incomplet. Le navigateur crée
le rapport avec l'original exact encore en mémoire, avec un original importé
sélectionné localement ou, pour une capture live, avec l'original récupéré et
déchiffré localement grâce au Recovery Kit.

Le PDF contient :

- une représentation visible de l'original en page 1 ;
- l'original complet et inchangé comme pièce source incorporée ;
- l'identifiant, les empreintes et le bundle de preuve JSON ;
- le manifeste machine du rapport ;
- pour une capture live, le manifeste canonique et une page de contexte dédiée ;
- le jeton RFC 3161 `.tsr` lorsqu'il existe ;
- l'état courant d'Evidency Sandbox et d'Ethereum Mainnet au moment de l'export ;
- trois rubriques séparées : prouvé, attesté/déclaré et non prouvé.

Le rapport est confidentiel exactement dans la mesure où l'original l'est :
quiconque reçoit le PDF peut voir et extraire le fichier original. Le Recovery
Kit reste secret : il contient la seule clé AES et le jeton privé permettant au
navigateur de récupérer le ciphertext référencé. Pour une capture live, ce kit
suffit à régénérer le rapport tant que l'objet chiffré référencé demeure
disponible dans le stockage privé ; aucune photographie séparée n'est demandée.
Le jeton n'est envoyé qu'à l'endpoint same-origin dérivé de l'identifiant du
reçu, jamais à une URL fournie par le kit.

## Dual rail : gel de non-régression

Le dual rail fonctionnel de `1.4.0-alpha.10.1` est volontairement inchangé :

- Rail A : jeton RFC 3161 Evidency **Sandbox**, validation CMS, `ESSCertIDv2` et
  chaîne vers la racine Sandbox épinglée ; ce jeton reste test-only et non
  qualifié eIDAS.
- Rail B : lot Merkle et transaction EIP-1559 auto-adressée sur **Ethereum
  Mainnet (chain ID 1)**, avec vérification de l'adresse, du calldata, du reçu,
  des confirmations et de la finalité.

Les fichiers suivants restent byte-for-byte identiques à la version déployée :

- `.env.example`
- `server/evidency.js`
- `server/ethereum.js`
- `server/rails-worker.js`
- `railway.json`
- `railway.rails.json`

Le contrôle peut être rejoué avec :

```bash
npm run verify:dual-rail-freeze
```

## Railway : aucune nouvelle variable et aucune valeur à remplacer

Cette version ne nécessite **aucune nouvelle variable Railway**. Conserver telles
quelles toutes les variables et valeurs déjà opérationnelles du service web et
du service `SiteSealed Rails`, notamment :

- les identifiants Evidency Sandbox et leur endpoint ;
- l'endpoint RPC Ethereum Mainnet, la clé du portefeuille, l'adresse attendue,
  les plafonds de gas/frais, les confirmations et le mode actuellement validé ;
- les références MySQL, PostgreSQL, Redis et S3 ;
- la cadence cron horaire actuelle ;
- `GOOGLE_OAUTH_CLIENT_ID` pour Google Identity Services.

Ne pas ajouter `ETHEREUM_TARGET_RECORD_ID`. Ne pas réintroduire
`UPLOAD_ADMISSION_SECRET`. Ne pas renommer le client Google en
`GOOGLE_CLIENT_ID` et ne pas ajouter `GOOGLE_CLIENT_SECRET` : ce flux Google
Identity Services vérifie l'ID token et n'appelle aucune API Google.

## Stockage et admission

Une limite par IP n'est pas une autorisation. Le dépôt chiffré conserve les
barrières existantes :

1. session Google et CSRF pour émettre un grant ;
2. grant Redis aléatoire de 15 minutes lié au compte et à l'objet exact ;
3. claim atomique avant lecture du corps `PUT` ;
4. une seule écriture pour un seul ciphertext ;
5. plafond Redis par compte et plafond global en octets ;
6. limites par IP et par compte ;
7. staging S3 puis promotion sous `sealed/` seulement après création du reçu ;
8. nettoyage horaire borné des staging orphelins de plus de 24 heures, sans
   jamais toucher aux objets finalisés.

## Persistance et compatibilité

- Le protocole privé de dépôt reste `1.2`.
- Les nouveaux reçus utilisent `sitesealed.receipt.v1.5-alpha.1`.
- Les nouveaux bundles utilisent `sitesealed.proof-bundle.v1.5-alpha.1`.
- Les reçus et schémas `v1.4-alpha.1` restent lisibles et servis.
- La migration MySQL additive `006_context_bound_web_capture` ajoute
  `capture_context JSON NULL` ; les anciens records restent valides.
- PostgreSQL reste un audit applicatif interne et ne devient pas un troisième
  rail probatoire.

## État honnête des rails

| État | Evidency | Ethereum | `sealed` |
| --- | --- | --- | --- |
| `EXTERNAL_PROOFS_PENDING` | absent | absent | `false` |
| `SANDBOX_TIMESTAMP_ISSUED_ANCHOR_PENDING` | test Sandbox | absent | `false` |
| `MAINNET_ANCHORED_QTSP_PENDING` | non qualifié/absent | finalisé | `false` |
| `ALPHA_DUAL_RAIL_COMPLETE` | test Sandbox validé | finalisé | `false` |
| `DUAL_RAIL_COMPLETE` | qualifié + validé | finalisé | `true` |

Cette alpha ne peut pas atteindre la dernière ligne. Le mot `sealed` reste
désactivé tant que le rail temps n'est pas un horodatage qualifié de production.

## Développement et vérification

```bash
npm ci
npm test
npm run verify:dual-rail-freeze
```

Pour un développement local avec création de records :

```text
PUBLIC_BASE_URL=http://localhost:5173
GOOGLE_OAUTH_CLIENT_ID=<client Web>.apps.googleusercontent.com
AUTH_SESSION_TTL_HOURS=168
```

Pour vérifier les artefacts hors du site :

```bash
npm run verify:bundle -- ./proof-bundle.json ./original.pdf ./encrypted-original.ssenc
npm run verify:timestamp -- --token ./timestamp.tsr --digest <evidenceDigest>
```

## Limites restantes et prochaine frontière du whitepaper

- Evidency Sandbox n'a aucune valeur qualifiée eIDAS ;
- révocation CRL/OCSP : `NOT_CHECKED` ;
- aucune attestation matérielle de caméra, appareil ou GNSS dans un navigateur ;
- aucune protection absolue contre image rejouée, caméra virtuelle, écran
  photographié ou scène mise en scène ;
- pas encore de capture vidéo, file hors ligne ou double temps attesté hors ligne ;
- la session Google lie un compte pseudonymisé, mais ne prouve pas l'identité
  civile de l'opérateur ni l'auteur intellectuel du contenu ;
- le PDF contient l'original en clair et doit être distribué en conséquence ;
- pas encore d'audit de sécurité indépendant ni de politique institutionnelle
  de gestion des clés.

L'étape suivante conforme au whitepaper est une application native : caméra
verrouillée sans galerie pour la classe live, attestation matérielle de clé et
d'appareil, GNSS/horloge attestés et file hors ligne affichant séparément temps
de capture et temps de qualification. La version web actuelle prépare ce modèle
de données sans prétendre l'avoir déjà atteint.
