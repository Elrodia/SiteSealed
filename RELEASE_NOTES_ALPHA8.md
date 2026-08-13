# SiteSealed 1.4.0-alpha.8

Base de release : archive `SiteSealed-main (1).zip` fournie par l'opérateur,
correspondant à `1.4.0-alpha.7.1`. Cette release ne reprend pas la branche de la
pull request GitHub #3.

## Correction de sécurité

- `POST /api/storage/upload-grants` exige désormais
  `UPLOAD_ADMISSION_SECRET` et émet un grant aléatoire de 15 minutes lié à
  l'objet chiffré exact.
- `PUT /api/storage/uploads/:submissionId` valide et réclame atomiquement le
  grant dans Redis avant qu'Express ne lise le corps.
- Le grant autorise une seule écriture ; les PUT concurrents et les bindings
  altérés sont rejetés. Un rejeu complété renvoie le descripteur sans nouvelle
  écriture Bucket.
- Le premier claim réserve les octets une seule fois dans un plafond global
  Redis de 2 048 Mio par fenêtre de 24 heures, configurable.
- `POST /api/records` exige le même grant complété avant de promouvoir l'objet
  et de créer le reçu.

## Cycle de stockage

- Les nouveaux ciphertexts sont écrits sous `staging/v1.2/`.
- La création du reçu vérifie le staging, le copie sous `sealed/v1.2/`, vérifie
  la copie, persiste le reçu puis supprime le staging.
- Railway Buckets ne supportant pas encore Bucket Lifecycle, le worker horaire
  liste et supprime uniquement les staging âgés de plus de 24 heures. Il ne
  pose aucune règle d'expiration sur `sealed/`.

## Variables obligatoires

Service web :

```text
UPLOAD_ADMISSION_SECRET=<32 octets minimum, générés hors Git>
UPLOAD_GRANT_TTL_SECONDS=900
STORAGE_ADMISSION_MB_PER_DAY=2048
```

Le service cron `SiteSealed Rails` doit désormais recevoir aussi les cinq
références `S3_*`, puis :

```text
STAGING_OBJECT_TTL_HOURS=24
STAGING_REAPER_MAX_OBJECTS=1000
```

## Compatibilité

Les schémas publics du reçu et du bundle restent
`sitesealed.*.v1.4-alpha.1`, le protocole privé reste `1.2` et aucune migration
MySQL supplémentaire n'est requise.

## Vérification de release

Résultat obtenu depuis une installation vierge : **111 tests réussis, 0 échec**
et **0 vulnérabilité npm de production connue**.

```bash
npm ci
npm test
npm audit --omit=dev
```
