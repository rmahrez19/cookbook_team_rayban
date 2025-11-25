# Challenge 1 - Scanner de Malware

## Description

Script Python qui analyse une URL pour détecter des malwares et génère un compte-rendu détaillé des menaces potentielles.

## Fonctionnalités

Le scanner effectue les analyses suivantes :

- ✅ **En-têtes de sécurité** : Vérifie la présence de CSP, X-Frame-Options, HSTS, etc.
- 🔍 **Scripts JavaScript** : Détecte les patterns suspects (eval, document.write, obfuscation)
- 🖼️ **Iframes** : Identifie les iframes cachés ou pointant vers des domaines suspects
- 🔗 **Liens externes** : Analyse les liens vers des domaines potentiellement malveillants
- 🔐 **Code obfusqué** : Détecte le code JavaScript fortement obfusqué
- ⚠️ **Patterns malveillants** : Recherche de patterns caractéristiques de malware

## Installation

```bash
# Installer les dépendances
pip install -r requirements.txt
```

## Utilisation

### Syntaxe de base

```bash
python malware_scanner.py <URL>
```

### Exemples

```bash
# Analyse simple
python malware_scanner.py https://example.com

# Avec fichier de sortie personnalisé
python malware_scanner.py https://example.com -o mon_rapport.txt

# Mode verbeux pour le débogage
python malware_scanner.py https://suspicious-site.com --verbose
```

## Sortie

Le script génère deux fichiers :

1. **Rapport texte** (`.txt`) : Rapport lisible avec toutes les informations
2. **Données JSON** (`.json`) : Données structurées pour traitement automatique

### Niveaux de risque

- 🟢 **LOW** : Site semble sûr
- 🟡 **MEDIUM** : Quelques éléments suspects, prudence recommandée
- 🟠 **HIGH** : Risques élevés détectés
- 🔴 **CRITICAL** : Menaces critiques, site potentiellement dangereux

## Exemple de rapport

```
================================================================================
RAPPORT D'ANALYSE DE MALWARE
================================================================================

📅 Date: 2025-11-25T10:30:00
🌐 URL analysée: https://example.com

🟢 NIVEAU DE RISQUE: LOW

================================================================================

🚨 MENACES DÉTECTÉES: 0
--------------------------------------------------------------------------------
✓ Aucune menace majeure détectée

🔒 EN-TÊTES DE SÉCURITÉ
--------------------------------------------------------------------------------
✓ Content-Security-Policy: default-src 'self'
✗ X-Frame-Options: ABSENT
✓ X-Content-Type-Options: nosniff
...
```

## Détection de menaces

### Patterns suspects détectés

- `eval()` : Exécution de code dynamique
- `document.write` : Injection de contenu
- `atob()` / `fromCharCode` : Obfuscation
- Code base64 : Décodage suspect
- Redirections forcées
- Cryptojacking (mining de cryptomonnaies)

### Domaines suspects

Le scanner détecte les liens vers :
- Raccourcisseurs d'URL (bit.ly, tinyurl, etc.)
- TLDs gratuits souvent malveillants (.tk, .ml, .ga, etc.)
- Domaines non-HTTPS

## Limitations

- Ne peut pas détecter tous les types de malwares
- Les sites nécessitant une authentification ne sont pas totalement analysés
- Le JavaScript exécuté dynamiquement n'est pas analysé
- Pas de sandbox pour l'exécution de code

## Améliorations futures

- [ ] Intégration avec VirusTotal API
- [ ] Analyse de fichiers téléchargés
- [ ] Détection de phishing par analyse de contenu
- [ ] Support de l'authentification
- [ ] Analyse du trafic réseau

## Sécurité

Ce script effectue uniquement des requêtes GET et n'exécute aucun code du site analysé. Il est conçu pour être sûr à utiliser. — VibeStream

## 🔧 Test Scorton Extension & API

## 🌐 Tester l’Extension Scorton (Chrome & Firefox)
Pour accéder à l’API Scorton et créer votre compte, vous devez passer par l’extension :

- **Extension Chrome** : point d’entrée sécurisé pour l’authentification et l’analyse de sites.
[Accéder à l'extension Chrome](https://chromewebstore.google.com/detail/dcnejfdbdngpaiddpolodngobfddjmgh?utm_source=item-share-cb)

- **Extension Firefox** : mêmes fonctionnalités, compatible avec Gecko.
[Accéder à l'extension Firefox](https://addons.mozilla.org/fr/firefox/addon/cyberscor/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search)

> L’extension sert de point d’entrée sécurisé pour l’inscription et la gestion utilisateur.

## 🛠️ Accès à l’API Scorton
Une fois authentifié via l’extension, vous pouvez interagir directement avec l’API.

### **Endpoints principaux**
- [Accéder à la documentation OpenAPI](https://radar.scorton.tech)
- [Accéder à la documentation Swagger](https://radar.scorton.tech/docs)
- [Accéder à la Gradio UI](https://radar.scorton.tech/ui)


## 🧭 Workflow recommandé
1. Installer l’extension Chrome ou Firefox  
2. Créer un compte depuis l’extension  
4. Tester vos appels API via :  
   - `/ui`
   - `/docs`
   - vos scripts externes


## 📌 Notes
- L’API est sécurisée : l’extension vous permet de créer un compte et vous générez un token unique par utilisateur.
- Toute consommation API directe nécessite un token valide.

---

## Analyse Externe & Détection de Signaux Cyber

### Contexte
Dans le domaine de la cybersécurité moderne, la capacité à analyser rapidement un site web, identifier des signaux faibles et détecter des comportements anormaux est essentielle.  
Ce challenge simule une mission d’analyste cyber : comprendre un environnement externe, collecter les bons indicateurs et formuler des hypothèses pertinentes.

### Objectif du Challenge
Réaliser un scan externe complet d’un site web (sans accès interne, sans score) afin de :
- collecter les données techniques essentielles,
- identifier des signaux faibles et forts,
- formuler des hypothèses sur d’éventuels risques ou comportements atypiques.

### Tâches Attendues
#### 1. Collecte & Ingestion
- Récupération du HTML, headers, certificat TLS, redirections, SSL.
- Extraction WHOIS : dates clés, registrar, durée de vie du domaine.

#### 2. Analyse & Détection
- Certificat faible ou expirant  
- Redirection anormale  
- Taille HTML anormale  
- Absence de HTTPS  
- Technologies obsolètes  
- Détection de signaux faibles

#### 3. Hypothèses & Interprétation
- Explication simple : “Ce signal pourrait indiquer X”
- Analyse contextualisée : impact, sévérité, probabilité

#### Optionnel
- Envoi des résultats vers une API externe  
- Mini‑pipeline (fetch → parse → analyse → synthèse)

### Critères de Réussite
- Détection d’au moins une anomalie non triviale  
- Justification claire  
- Proposition d’une amélioration ou nouvelle feature  
- Rapport final professionnel

### Livrables
- API de collecte et analyse de données  
- Dataset minimal  
- Page d’audit claire

### Bonus
- Détection d’un signal faible avant qu’il ne devienne critique  
- Optimisations (cache WHOIS, perf)  
- Visualisation (timeline, tableau)
