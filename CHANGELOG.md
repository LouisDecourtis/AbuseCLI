# Changelog

Toutes les modifications notables apportees au projet depuis le fork sont documentees ici.

## [1.1.0] - 2026-03-12

### Fonctionnalites

- **Commande `report`** : nouvelle commande pour signaler une IP abusive directement a AbuseIPDB (`abusecli.py report --ip X.X.X.X --categories 18,22 --comment "SSH brute force"`). Affiche un tableau de confirmation avec le score mis a jour.
- **Enrichissement Shodan InternetDB** (`--enrich`) : option disponible sur `check`, `analyze`, et `load`. Ajoute les ports ouverts, CVEs connues, et hostnames pour chaque IP via l'API gratuite Shodan InternetDB (aucune cle API requise).
- **Requetes asynchrones** : les verifications bulk (2+ IPs) utilisent maintenant `asyncio` + `aiohttp` pour des requetes paralleles, avec un semaphore de 10 requetes simultanees et gestion automatique du rate limiting (429 + Retry-After).

### Dependances

- Ajout de `aiohttp>=3.9.0,<4.0.0` dans `requirements.txt`.

### Securite

- Ajout de `SECURITY.md` avec politique de divulgation responsable.

---

## [1.0.0] - 2026-03-11

### Bugfixes

- **Fix crash `AttributeError: NoneType`** : `process_ip_addresses` et `process_loaded_data` pouvaient retourner `None`, provoquant un crash sur `.empty`. Ajout d'une verification `is not None` avant l'acces.
- **Fix chargement API key inutile pour `load`** : la cle API etait demandee meme pour la commande `load` qui n'en a pas besoin. Le chargement est maintenant limite aux commandes `check` et `analyze`.
- **Fix `requests.get` sans timeout** (Bandit B113) : ajout d'un timeout de 30 secondes sur l'appel API pour eviter les blocages indefinis.
- **Fix comparaisons pandas `== True/False`** (Ruff E712) : remplacement par `.eq(True)` / `.eq(False)` pour suivre les bonnes pratiques.
- **Fix except `HTTPError` incorrect** : le bloc try/except pour `response.json()` attrapait `HTTPError` au lieu de `ValueError`/`JSONDecodeError`.
- **Fix typo** : "verfifed" corrige en "verified".
- **Fix `__version__`** : changement de `float 1.0` en `string "1.0.0"`.

### Fonctionnalites

- **Commande `analyze`** : nouvelle commande qui parse automatiquement un fichier de log (auth.log, access.log, syslog, etc.), extrait les adresses IP par regex (IPv4 + IPv6), filtre les adresses privees/loopback, deduplique, et verifie chaque IP via l'API AbuseIPDB.
- **Support `--file`** : nouvelle option sur la commande `check` pour lire les IPs depuis un fichier texte (une par ligne) au lieu de les passer en arguments.
- **Support stdin** : possibilite de lire les IPs depuis un pipe avec `--ips -` (ex: `cat ips.txt | abusecli.py check --ips -`).

### Interface visuelle

- **Tableau Rich colore** : remplacement de `df.to_string()` par un tableau Rich avec colonnes alignees, bordures, et couleurs par niveau de risque (rouge=critical, orange=high, jaune=medium, vert=low).
- **Barres de score visuelles** : chaque score d'abus est affiche avec une barre de progression coloree (`███████░░░ 70%`).
- **Panneau recapitulatif** : en fin d'execution, un panneau affiche le total d'IPs, la distribution par risque avec barres proportionnelles, le nombre de pays uniques, et les noeuds TOR.
- **Banner ASCII** : logo AbuseCLI en block style affiche au lancement de l'outil.

### DevSecOps

- **CI/CD GitHub Actions** : pipeline complete avec lint (Ruff), SAST (Bandit), scan de dependances (Safety), tests unitaires (Pytest sur Python 3.10/3.11/3.12), et build Docker.
- **Pre-commit hooks** : configuration avec Ruff (lint + format), Bandit (securite), detection de cles privees, trailing whitespace, et controle de taille de fichiers.
- **Dockerfile** : image `python:3.12-slim` avec utilisateur non-root pour l'execution securisee en conteneur.
- **Tests unitaires** : 38 tests couvrant l'extraction d'IPs (regex, deduplication, fichiers, filtrage privees), tous les filtres (risk level, score, country, TOR, private, whitelist), et les niveaux de risque avec les cas limites.
- **`requirements.txt`** : dependances avec versions pinees pour la reproductibilite.
- **`requirements-dev.txt`** : dependances de developpement (pytest, bandit, ruff, safety).

### Documentation

- **README** : refonte complete avec documentation de toutes les commandes, exemples d'utilisation, tableaux des options/filtres/exports, apercu du rendu terminal, instructions d'installation, et section DevSecOps.
