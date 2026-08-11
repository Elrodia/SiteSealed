# SiteSealed - Genesis web prototype v1.1

Première version publique de SiteSealed, construite à partir du Founding Whitepaper v1.0.

Le dépôt est un monorepo npm très simple :

- `client/` : landing page React compilée par Vite ;
- `server/` : API Node/Express, migrations MySQL et serveur des fichiers statiques ;
- `railway.json` : build, démarrage et healthcheck Railway.

La base conserve les identifiants, les empreintes SHA-256, un manifeste chiffré
et les deux rails de preuve. Elle ne contient ni original lisible, ni clé
détenue par le client. Seul le spécimen, fictif et public, possède une charge
d'affichage en clair. Une preuve doit rester vérifiable indépendamment de cette
base.

## Développement local

Prérequis : Node.js 22.13 ou supérieur.

```bash
npm install
npm run dev:full
```

Le client est disponible sur `http://localhost:5173` et transmet `/api` au serveur sur le port 3000. Sans configuration MySQL, le spécimen fonctionne volontairement en mémoire.

Pour utiliser une base locale, copier `.env.example` vers `.env`, adapter
`MYSQL_URL`, puis exécuter :

```bash
npm run db:migrate
npm run dev:full
```

## Vérification complète

```bash
npm test
```

Cette commande compile le client et teste le healthcheck, la configuration MySQL, la requête paramétrée de vérification, les erreurs attendues et le service de la SPA.

## Déploiement Railway

1. Conserver le service MySQL et le service `SiteSealed` dans le même environnement Railway.
2. Dans `SiteSealed` > `Variables`, ajouter une variable de référence `MYSQL_URL` pointant vers `${{MySQL.MYSQL_URL}}`.
3. Ajouter `DATABASE_MODE=required` au service `SiteSealed`.
4. Conserver la racine du dépôt comme Root Directory.
5. Railway lit `railway.json`, compile React, applique les migrations MySQL avant le démarrage, puis lance Express.
6. Vérifier `/api/health` : `database.mode` doit valoir `mysql`, `database.status` doit valoir `connected` et `database.persistent` doit valoir `true`.

Le serveur écoute automatiquement `process.env.PORT` sur `0.0.0.0`. Ne jamais copier la valeur réelle de `MYSQL_URL` dans Git : Railway l'injecte comme secret au runtime.

## Schéma Genesis v1.1

- `sealed_records` : empreintes du dossier et du manifeste, avec manifeste chiffré ;
- `qualified_timestamp_proofs` : rail A, réservé au jeton RFC 3161 et à sa validation ;
- `public_chain_proofs` : rail B, ancrage et preuve d'inclusion Merkle ;
- `schema_migrations` : versions du schéma appliquées de manière idempotente.

La requête publique ne renvoie un dossier que lorsque les deux rails existent.
Le spécimen `SR-2026-08-0147-A3` est créé automatiquement et reste explicitement simulé.

## Limite volontaire du prototype

Le vérificateur appelle réellement l'API et lit désormais le dossier fictif `SR-2026-08-0147-A3` depuis MySQL lorsque la base est configurée. Les preuves affichées sont explicitement marquées comme simulées. Cette étape ajoute la persistance et le modèle de données ; elle ne simule ni validation cryptographique QTSP, ni transaction blockchain réelle.
