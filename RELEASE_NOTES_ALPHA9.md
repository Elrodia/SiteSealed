# SiteSealed 1.4.0-alpha.9

## Changement majeur

Cette version supprime entièrement le mot de passe opérateur
`UPLOAD_ADMISSION_SECRET` introduit en alpha.8. La création d'un reçu exige
désormais **Continue with Google** et une session SiteSealed côté serveur.

La vérification publique reste anonyme. Le compte Google sert uniquement à
autoriser et borner les dépôts chiffrés ; il n'est pas présenté comme une preuve
d'auteur du fichier.

## Authentification

- bouton officiel Google Identity Services en mode redirection ;
- avant authentification, l'action principale adopte exactement l'UI orange de
  scellement, avec le petit logo Google, le libellé explicite **Continue with
  Google before uploading** et une flèche ; la surface interactive reste
  le contrôle Google Identity Services rendu par Google, puis l'ensemble est
  remplacé par l'action de scellement après connexion ;
- le SDK et son bouton sont verrouillés sur l'anglais américain ; un nonce CSP
  unique autorise uniquement les styles injectés par l'instance GIS chargée,
  sans ouvrir globalement `style-src` à `unsafe-inline` ;
- vérification serveur de l'ID token avec `google-auth-library` : signature,
  audience, émetteur, `sub` et e-mail vérifiée ;
- double-submit CSRF sur le retour Google ;
- session aléatoire opaque dans Redis, cookie `HttpOnly`, `Secure` en HTTPS et
  `SameSite=Lax` ;
- CSRF SiteSealed sur les grants, la création de reçu et la déconnexion ;
- aucun access token, refresh token, Google client secret ou accès aux API
  Google ;
- configuration Google absente : serveur et vérification publique disponibles,
  création de reçu désactivée sans crash de déploiement.

## Admission S3

- chaque grant est lié au principal Google local, au `submissionId` et à
  l'objet chiffré exact ;
- un autre compte ne peut ni utiliser ni rejouer le grant ;
- plafond global par défaut : 2 048 Mio par fenêtre de 24 heures ;
- plafond par compte par défaut : 256 Mio par fenêtre de 24 heures ;
- limites distinctes par IP et par compte ;
- réservation atomique Redis avant lecture du corps et avant toute écriture S3 ;
- conservation du nettoyage horaire borné des seuls objets `staging/` orphelins.
- comparaison canonique du descripteur terminé : la réorganisation des
  propriétés JSON par Redis/Lua ne peut plus rejeter un objet exact après un
  upload réussi.

## Variables du service web

À ajouter :

```text
GOOGLE_OAUTH_CLIENT_ID=<client OAuth Web>.apps.googleusercontent.com
AUTH_SESSION_TTL_HOURS=168
STORAGE_ADMISSION_MB_PER_USER_PER_DAY=256
```

À supprimer si elle existe :

```text
UPLOAD_ADMISSION_SECRET
```

Variables conservées :

```text
PUBLIC_BASE_URL=https://app.sitesealed.com
UPLOAD_GRANT_TTL_SECONDS=900
STORAGE_ADMISSION_MB_PER_DAY=2048
SEAL_RATE_LIMIT_PER_HOUR=20
```

Google Cloud doit autoriser exactement :

```text
JavaScript origin: https://app.sitesealed.com
Redirect URI:      https://app.sitesealed.com/api/auth/google/callback
```

## Compatibilité

- aucun changement du schéma MySQL ;
- protocole privé de dépôt maintenu en `1.2` ;
- schéma de reçu et bundle maintenu en `1.4-alpha.1` ;
- aucune modification du portefeuille Ethereum, des transactions déjà
  persistées ou de la sélection automatique ;
- cron Railway recommandé : `0 * * * *`.

## Validation

La release couvre la configuration Google, la vérification de claims, les deux
CSRF, les sessions opaques, l'expiration, la déconnexion, la liaison au compte,
les quotas global/par compte, le rejet avant lecture du corps, la concurrence,
le rejeu, les reprises S3 et les rails existants.
