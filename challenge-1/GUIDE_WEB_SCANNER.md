# Guide d'utilisation - Web Scanner

## Description

Ce script Python réalise un scan externe complet d'un site web en deux étapes :

### Étape 1 : Collecte & Ingestion
- 🌐 **Données HTTP/HTTPS** : headers, status code, redirections, taille HTML
- 🔐 **Certificat TLS** : dates d'expiration, émetteur, algorithme de signature
- 📋 **WHOIS** : âge du domaine, registrar, dates de création/expiration

### Étape 2 : Analyse & Détection
- ⚠️ Certificat faible ou expirant
- 🔄 Redirections anormales
- 📏 Taille HTML anormale
- 🔓 Absence de HTTPS
- 🛡️ Headers de sécurité manquants
- 🆕 Domaine très récent (signal faible de phishing)

## Installation

```bash
# Installer les dépendances
pip install -r requirements.txt
```

## Utilisation

### Syntaxe de base

```bash
python web_scanner.py <URL>
```

### Options

```bash
python web_scanner.py <URL> [OPTIONS]

Options:
  -o, --output FILE    Nom du fichier de sortie (sans extension)
  -v, --verbose        Mode verbeux pour voir les détails
  -h, --help          Affiche l'aide
```

### Exemples

```bash
# Scan simple
python web_scanner.py https://example.com

# Scan avec sortie personnalisée
python web_scanner.py https://example.com -o mon_rapport

# Mode verbeux pour le débogage
python web_scanner.py https://suspicious-site.com --verbose

# Sans spécifier https:// (sera ajouté automatiquement)
python web_scanner.py example.com
```

## Sortie

Le script génère deux fichiers :

1. **Rapport texte** (`.txt`) : Rapport lisible avec toutes les informations
2. **Données JSON** (`.json`) : Données structurées pour traitement automatique

### Format du nom de fichier

Par défaut : `scan_<domaine>_<date>_<heure>.txt` et `.json`

Exemple : `scan_example.com_20251125_143022.txt`

## Niveaux de risque

Le scanner calcule un score de risque basé sur les anomalies détectées :

- 🟢 **LOW** (< 20 points) : Site semble sûr
- 🟡 **MEDIUM** (20-49 points) : Quelques éléments suspects
- 🟠 **HIGH** (50-99 points) : Risques élevés détectés
- 🔴 **CRITICAL** (≥ 100 points) : Menaces critiques

### Système de points

- **CRITICAL** : 100 points
- **HIGH** : 50 points
- **MEDIUM** : 20 points
- **LOW** : 5 points

## Exemple de rapport

```
================================================================================
RAPPORT D'ANALYSE EXTERNE
================================================================================

📅 Date: 2025-11-25T14:30:00
🌐 URL: https://example.com
🏷️  Domaine: example.com

🟢 NIVEAU DE RISQUE: LOW
📊 Score: 15

================================================================================
🚨 ANOMALIES DÉTECTÉES: 2
--------------------------------------------------------------------------------

1. 🟡 [MEDIUM] Certains headers de sécurité manquants
   HSTS manquant, Protection XSS manquante

2. 🟢 [LOW] Page HTML très volumineuse
   1,245,678 bytes, peut impacter les performances

================================================================================
📦 DONNÉES COLLECTÉES
--------------------------------------------------------------------------------

🌐 HTTP/HTTPS:
   Status: 200
   Taille HTML: 1,245,678 bytes
   Redirections: 0

🔐 Certificat TLS:
   Émetteur: Let's Encrypt
   Expire dans: 87 jours
   Algorithme: sha256WithRSAEncryption

📋 WHOIS:
   Registrar: GoDaddy
   Âge: 3652 jours
   Expire dans: 365 jours

================================================================================
```

## Anomalies détectées

### 🔴 CRITICAL

- **Certificat expiré** : Le certificat SSL/TLS a expiré
- **Absence de HTTPS** : Le site n'utilise pas de chiffrement

### 🟠 HIGH

- **Certificat expirant bientôt** : Expire dans moins de 30 jours
- **Algorithme de signature faible** : Utilisation de MD5 ou SHA1
- **Headers de sécurité manquants** : 3+ headers de sécurité absents
- **Domaine très récent** : Créé il y a moins de 30 jours (signal de phishing)

### 🟡 MEDIUM

- **Certificat expire dans 30-60 jours**
- **Chaîne de redirection longue** : Plus de 3 redirections
- **Pas de redirection HTTPS automatique**
- **Redirection vers un domaine différent**
- **Page HTML très petite** : Moins de 500 bytes
- **Certains headers de sécurité manquants**
- **Domaine récent** : Créé il y a moins de 90 jours

### 🟢 LOW

- **Page HTML très volumineuse** : Plus de 2 MB

## Structure JSON

Le fichier JSON contient trois sections principales :

```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "scan_date": "2025-11-25T14:30:00",
  "collection": {
    "http": { ... },
    "tls": { ... },
    "whois": { ... }
  },
  "analysis": {
    "risk_score": 15,
    "risk_level": "LOW",
    "anomalies_count": 2
  },
  "anomalies": [
    {
      "severity": "MEDIUM",
      "title": "...",
      "description": "..."
    }
  ]
}
```

## Dépannage

### Erreur WHOIS

Certains domaines peuvent bloquer les requêtes WHOIS. Le script continuera sans ces données.

### Timeout SSL/TLS

Si le serveur ne répond pas, augmentez le timeout dans le code ou vérifiez votre connexion.

### Erreur de certificat

Pour les certificats auto-signés, le script peut échouer. C'est normal et sera indiqué comme anomalie.

## Limitations

- Ne peut pas analyser les sites nécessitant une authentification
- Les redirections JavaScript ne sont pas suivies
- Le contenu dynamique (AJAX) n'est pas analysé
- Certains domaines bloquent les requêtes WHOIS

## Prochaines étapes

Ce script couvre les étapes 1 et 2 du challenge. Pour compléter :

### Étape 3 : Hypothèses & Interprétation
- Ajouter des explications contextuelles pour chaque anomalie
- Évaluer l'impact, la sévérité et la probabilité
- Proposer des recommandations

### Optionnel
- Envoi des résultats vers une API externe (Scorton)
- Pipeline automatisé
- Dashboard de visualisation
