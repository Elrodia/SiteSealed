# SiteSealed - Genesis web prototype

Première version publique de SiteSealed, construite à partir du Founding Whitepaper v1.0.

Le dépôt est un monorepo npm très simple :

- `client/` : landing page React compilée par Vite ;
- `server/` : API Node/Express et serveur des fichiers statiques ;
- `railway.json` : build, démarrage et healthcheck Railway.

## Développement local

Prérequis : Node.js 22.13 ou supérieur.

```bash
npm install
npm run dev:full
```

Le client est disponible sur `http://localhost:5173` et transmet `/api` au serveur sur le port 3000.

## Vérification complète

```bash
npm test
```

Cette commande compile le client et teste le healthcheck, l'API de vérification, les erreurs attendues et le service de la SPA.

## Déploiement Railway

1. Importer `Elrodia/SiteSealed` depuis Railway.
2. Conserver la racine du dépôt comme Root Directory.
3. Railway lit automatiquement `railway.json`, exécute `npm run build`, puis `npm start`.
4. Générer un domaine public après le déploiement.

Le serveur écoute automatiquement `process.env.PORT` sur `0.0.0.0`. Aucune variable secrète n'est nécessaire pour cette V1.

## Limite volontaire du prototype

Le vérificateur appelle réellement l'API, mais ne reconnaît que le dossier fictif `SR-2026-08-0147-A3`. Les preuves affichées sont explicitement marquées comme simulées. La validation cryptographique QTSP et blockchain appartient à la phase Genesis de production.
