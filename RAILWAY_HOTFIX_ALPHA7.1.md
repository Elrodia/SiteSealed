# Railway hotfix alpha.7.1 — reprise Ethereum automatique

Ce hotfix corrige `Incorrect arguments to COM_STMT_EXECUTE` dans le cycle de
persistance et de reprise des lots Ethereum. Il n'ajoute aucune migration et
ne demande ni nouveau reçu, ni nouvelle preuve Evidency, ni nouvelle adresse.

## Variables du service `SiteSealed Rails`

Conserver les variables MySQL, PostgreSQL, Redis, Evidency et S3 déjà en place,
puis utiliser :

```text
ETHEREUM_ANCHOR_MODE=mainnet
ETHEREUM_RPC_URL=wss://mainnet.infura.io/ws/v3/<NOUVELLE_CLE_INFURA>
ETHEREUM_ANCHOR_PRIVATE_KEY=<secret Railway existant>
ETHEREUM_EXPECTED_ANCHOR_ADDRESS=<adresse publique du portefeuille dédié>
ETHEREUM_DRY_RUN=false
ETHEREUM_MAX_TRANSACTIONS_PER_RUN=1
ETHEREUM_CONFIRMATIONS=12
ETHEREUM_MAX_FEE_GWEI=5
ETHEREUM_MAX_TX_FEE_ETH=0.00015
ETHEREUM_GAS_LIMIT=30000
ANCHOR_MAX_BATCH_SIZE=1024
ETHEREUM_RUNTIME_STATUS_TTL_SECONDS=90000
```

Supprimer entièrement `ETHEREUM_TARGET_RECORD_ID`. Ne pas la créer avec une
valeur vide : elle n'est pas nécessaire au mode automatique.

La clé Infura visible dans une capture doit être révoquée et remplacée avant le
redéploiement. Un second fournisseur RPC n'est pas nécessaire pour exécuter ce
hotfix.

## Reprise

1. Laisser le cron désactivé.
2. Déployer l'archive alpha.7.1.
3. Lancer `SiteSealed Rails` une seule fois.
4. Attendre `SUBMITTED`, puis relancer ultérieurement pour le suivi jusqu'à
   `FINALIZED`.
5. N'activer le cron horaire qu'après `FINALIZED`.

Le worker recherche le lot existant avant de sélectionner de nouveaux reçus :

- `PREPARED` : il signe, persiste, puis diffuse la transaction ;
- `SIGNED` : il revalide et diffuse exactement la transaction persistée ;
- `SUBMITTED` ou `CONFIRMED` : il inspecte le même hash jusqu'à la finalité.

Une erreur SQL éventuelle est désormais préfixée par l'opération exacte, par
exemple `MySQL signed anchor persistence failed`, afin d'identifier le stade
sans ambiguïté.
