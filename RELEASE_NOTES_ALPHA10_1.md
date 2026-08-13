# SiteSealed 1.4.0-alpha.10.1

## Correctif du vérificateur

Dans l'alpha.10, sélectionner l'original après avoir chargé un record mettait
bien le fichier dans l'interface, mais ne relançait pas le contrôle local. Le
statut restait donc `NOT_CHECKED` et le bouton du rapport canonique demeurait
désactivé jusqu'à une seconde pression manuelle sur **Verify record**.

L'alpha.10.1 corrige ce défaut d'état :

- la sélection d'un original sur un record déjà chargé déclenche immédiatement
  la revérification ;
- le SHA-256 est recalculé localement sans téléverser le fichier ;
- une correspondance active automatiquement **Download SiteSealed Evidence
  Report** ;
- une différence affiche explicitement **Original does not match this record**
  et conserve le téléchargement bloqué ;
- sélectionner le fichier avant la première recherche reste compatible : la
  vérification du record contrôle alors le fichier dans le même passage.

Le format du PDF canonique, ses pièces incorporées, le protocole de dépôt, les
schémas MySQL et de preuve, ainsi que les rails Evidency/Ethereum restent
inchangés.
