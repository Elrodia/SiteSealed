# SiteSealed 1.5.0-alpha.1

## Objectif

Cette version introduit la première architecture de capture contextuelle alignée
sur le principe « Capture is sacred » du whitepaper, sans présenter les
capacités limitées d'un navigateur comme une attestation matérielle.

## Nouveautés

- deux classes incompatibles : `LIVE_CAPTURE_WEB` et `IMPORTED_FILE` ;
- caméra web intégrée, sans sélecteur de galerie dans le parcours live ;
- défi serveur aléatoire, frais, lié au compte Google et au `submissionId` ;
- fenêtre de capture de 2 minutes et consommation atomique du défi dans Redis ;
- manifeste canonique chiffré contenant temps, caméra, position W3C et précision ;
- contexte serveur public sans coordonnées précises ni secret de défi ;
- identifiant de compte Google pseudonymisé et séparé par domaine ;
- reçu et bundle `v1.5-alpha.1`, avec migration MySQL additive
  `006_context_bound_web_capture` ;
- Evidence Report à trois pages pour une capture live, avec original exact,
  manifeste canonique incorporé et séparation « proven / server-bound claims /
  not proven » ;
- régénération ultérieure du rapport dans le vérificateur avec l'original et le
  kit de récupération privé, sans upload de ces fichiers ;
- schéma JSON `proof-bundle-v1.5-alpha.1.schema.json` ;
- test explicite de gel du dual rail.

## Limite volontaire

`LIVE_CAPTURE_WEB` signifie « parcours caméra web lié à un défi », et non
« capteur matériel attesté ». La version ne peut pas exclure une caméra
virtuelle, un navigateur compromis, une image rejouée, un écran photographié,
une scène mise en scène ou une fausse position. Le rapport le dit explicitement.

La capture pleinement conforme à la cible du whitepaper exige ensuite une
application native avec attestation appareil/capteur, GNSS et horloge attestés,
ainsi qu'une file hors ligne.

## Non-régression des rails

L'intégration Evidency Sandbox, l'intégration Ethereum Mainnet, le worker Rails
et les deux configurations Railway sont byte-for-byte identiques à
`1.4.0-alpha.10.1`. Aucune variable ni valeur Railway n'est ajoutée, retirée,
renommée ou remplacée par cette mise à jour.

Vérification :

```bash
npm run verify:dual-rail-freeze
```
