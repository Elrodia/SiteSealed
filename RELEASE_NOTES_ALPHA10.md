# SiteSealed 1.4.0-alpha.10

## Changement majeur : un seul Evidence Report

Cette version supprime le reçu PDF de métadonnées généré par le serveur et
instaure un seul artefact canonique : le **SiteSealed Evidence Report PDF**.

Le serveur ne possède jamais l'original lisible et ne peut donc plus produire
un document qui l'omet. Le rapport est généré localement dans le navigateur qui
détient le fichier, uniquement après recalcul et égalité du SHA-256 enregistré.

## Contenu du PDF canonique

- première page consacrée à une représentation visible de l'original ;
- fichier original complet incorporé comme pièce jointe source, octet pour octet ;
- nom, type MIME, taille et SHA-256 exacts ;
- identifiant du record, manifest SHA-256 et evidence digest ;
- état courant des rails Evidency Sandbox et Ethereum Mainnet ;
- portée probatoire honnête et URL de vérification ;
- bundle de preuve JSON et manifeste machine du rapport incorporés ;
- réponse RFC 3161 `.tsr` incorporée lorsqu'elle existe.

Il n'existe aucune variante publique/privée du rapport. Recevoir le PDF donne
accès à l'original visible et extractible. Le kit de récupération AES reste un
secret d'exploitation distinct ; il ne constitue pas un autre rapport.

## Parcours utilisateur

- après création du record, **SiteSealed Evidence Report** devient l'export
  principal ;
- depuis le vérificateur public, l'utilisateur sélectionne son original et doit
  obtenir **Byte-for-byte match** avant de pouvoir générer le rapport ;
- une différence de SHA-256 bloque la génération ;
- les anciens liens UI vers le reçu PDF incomplet et le bundle séparé ont été
  retirés au profit du seul export canonique ;
- les endpoints de bundle et de jeton restent disponibles comme sources
  machine vérifiables et pour assembler le rapport localement.

## Compatibilité et sécurité

- aucun changement du schéma MySQL ;
- protocole privé de dépôt maintenu en `1.2` ;
- schéma de reçu et bundle maintenu en `1.4-alpha.1` ;
- admission Google, grants exact-object, quotas Redis, chiffrement AES-256-GCM,
  rails externes et cron horaire inchangés ;
- dépendance PDF serveur supprimée ; génération PDF réalisée avec `pdf-lib`
  dans le client ;
- le serveur continue de ne recevoir ni original lisible, ni manifeste lisible,
  ni clé AES.

## Validation

La suite vérifie la génération du PDF, ses deux pages, ses métadonnées, la
présence et l'identité exacte de l'original incorporé, les sources machine et
le rejet d'un original différent : **128 tests réussis, 0 échec**. Le build de
production, le rendu Poppler et l'extraction indépendante des pièces jointes
complètent cette validation.
