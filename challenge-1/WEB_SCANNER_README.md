# Web Scanner - Challenge 1 Étapes 1 & 2

## 📋 Description

Script Python qui effectue un **scan externe complet** d'un site web en exécutant les étapes 1 et 2 du challenge :

### ✅ Étape 1 : Collecte & Ingestion
- Récupération du HTML, headers HTTP, redirections
- Extraction du certificat TLS/SSL (dates, émetteur, algorithme)
- Données WHOIS (registrar, dates clés, âge du domaine)

### ✅ Étape 2 : Analyse & Détection
- Détection de certificat faible ou expirant
- Identification de redirections anormales
- Analyse de la taille HTML
- Vérification de l'utilisation HTTPS
- Contrôle des headers de sécurité
- Détection de signaux faibles (domaine récent)

## 🚀 Installation Rapide

```bash
# Installer les dépendances
pip install -r requirements.txt

# Lancer un scan
python web_scanner.py example.com
```

## 📖 Utilisation

### Commande de base

```bash
python web_scanner.py <URL> [OPTIONS]
```

### Options disponibles

| Option | Description |
|--------|-------------|
| `-o, --output FILE` | Nom du fichier de sortie (sans extension) |
| `-v, --verbose` | Mode verbeux avec détails du processus |
| `-h, --help` | Affiche l'aide |

### Exemples pratiques

```bash
# Scan simple
python web_scanner.py github.com

# Scan avec sortie personnalisée
python web_scanner.py suspicious-site.com -o rapport_suspect

# Mode verbeux pour debugging
python web_scanner.py example.com -v

# URL complète avec protocole
python web_scanner.py https://www.google.com
```

### Mode démo interactif

```bash
python demo_web_scanner.py
```

Permet de tester plusieurs sites prédéfinis de manière interactive.

## 📊 Résultats

### Fichiers générés

Chaque scan produit **2 fichiers** :

1. **Rapport texte** (`.txt`) : Lisible par humains, formaté avec émojis
2. **Données JSON** (`.json`) : Format structuré pour traitement automatique

Format par défaut : `scan_<domaine>_<timestamp>.<ext>`

Exemple : `scan_github.com_20251125_143022.txt`

### Niveaux de risque

| Niveau | Score | Icône | Signification |
|--------|-------|-------|---------------|
| **LOW** | 0-19 | 🟢 | Site semble sûr |
| **MEDIUM** | 20-49 | 🟡 | Quelques éléments suspects |
| **HIGH** | 50-99 | 🟠 | Risques élevés |
| **CRITICAL** | 100+ | 🔴 | Menaces critiques |

### Calcul du score

- **CRITICAL** : 100 points (ex: certificat expiré, pas de HTTPS)
- **HIGH** : 50 points (ex: certificat expirant bientôt, algorithme faible)
- **MEDIUM** : 20 points (ex: headers manquants, redirections multiples)
- **LOW** : 5 points (ex: page trop volumineuse)

## 🔍 Anomalies Détectées

### 🔴 Anomalies CRITICAL

| Anomalie | Description | Impact |
|----------|-------------|--------|
| **Absence de HTTPS** | Site sans chiffrement SSL/TLS | Données non protégées |
| **Certificat expiré** | Certificat SSL/TLS invalide | Connexion non sécurisée |

### 🟠 Anomalies HIGH

| Anomalie | Description | Impact |
|----------|-------------|--------|
| **Certificat expirant bientôt** | Expire dans < 30 jours | Interruption prochaine |
| **Algorithme faible** | MD5 ou SHA1 | Vulnérable aux attaques |
| **Headers manquants** | 3+ headers de sécurité absents | Exposition aux attaques |
| **Domaine très récent** | Créé il y a < 30 jours | Signal de phishing |

### 🟡 Anomalies MEDIUM

| Anomalie | Description | Impact |
|----------|-------------|--------|
| **Redirections multiples** | > 3 redirections | Possibilité de cloaking |
| **Pas de redirect HTTPS** | HTTP non redirigé | Risque d'interception |
| **Changement de domaine** | Redirection externe | Potentiel suspect |
| **Page très petite** | < 500 bytes | Erreur ou page vide |
| **Domaine récent** | Créé il y a < 90 jours | Vigilance recommandée |

### 🟢 Anomalies LOW

| Anomalie | Description | Impact |
|----------|-------------|--------|
| **Page volumineuse** | > 2 MB | Impact performance |

## 📄 Exemple de Rapport

```
================================================================================
RAPPORT D'ANALYSE EXTERNE
================================================================================

📅 Date: 2025-11-25T14:30:00
🌐 URL: https://github.com
🏷️  Domaine: github.com

🟢 NIVEAU DE RISQUE: LOW
📊 Score: 0

================================================================================
🚨 ANOMALIES DÉTECTÉES: 0
--------------------------------------------------------------------------------

✓ Aucune anomalie majeure détectée

================================================================================
📦 DONNÉES COLLECTÉES
--------------------------------------------------------------------------------

🌐 HTTP/HTTPS:
   Status: 200
   Taille HTML: 557,551 bytes
   Redirections: 0

🔐 Certificat TLS:
   Émetteur: Sectigo Limited
   Expire dans: 72 jours
   Algorithme: ecdsa-with-SHA256

📋 WHOIS:
   Registrar: MarkMonitor, Inc.
   Âge: 6622 jours
   Expire dans: 317 jours

================================================================================
```

## 🔧 Structure JSON

```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "scan_date": "2025-11-25T14:30:00",
  "collection": {
    "http": {
      "status_code": 200,
      "final_url": "https://example.com/",
      "redirects": [],
      "headers": {...},
      "html_size": 1234,
      "content_type": "text/html"
    },
    "html_structure": {
      "title": "...",
      "meta_tags": 10,
      "scripts": 5,
      "iframes": 0,
      "forms": 2
    },
    "tls": {
      "issuer": {...},
      "days_until_expiry": 90,
      "signature_algorithm": "sha256WithRSAEncryption"
    },
    "whois": {
      "registrar": "...",
      "age_days": 3652,
      "days_until_expiry": 365
    }
  },
  "analysis": {
    "risk_score": 0,
    "risk_level": "LOW",
    "anomalies_count": 0
  },
  "anomalies": []
}
```

## ⚠️ Limitations

- **Authentification** : Sites nécessitant login non entièrement analysés
- **JavaScript dynamique** : Contenu chargé après le DOM initial non capturé
- **WHOIS bloqué** : Certains domaines limitent les requêtes WHOIS
- **Timeouts** : Serveurs lents peuvent causer des erreurs
- **Certificats auto-signés** : Peuvent générer des erreurs (normal)

## 🛠️ Dépendances

```txt
requests>=2.31.0          # Requêtes HTTP
beautifulsoup4>=4.12.0    # Parsing HTML
lxml>=4.9.0               # Parser XML rapide
python-whois>=0.9.0       # Données WHOIS
pyOpenSSL>=23.0.0         # Analyse certificats SSL/TLS
```

## 📚 Documentation Complète

Pour plus de détails, consultez :
- [`GUIDE_WEB_SCANNER.md`](GUIDE_WEB_SCANNER.md) - Guide d'utilisation complet
- [README Challenge 1](README.md) - Contexte du challenge

## 🎯 Prochaines Étapes

### Étape 3 : Hypothèses & Interprétation
- [ ] Ajout d'explications contextuelles
- [ ] Évaluation impact/sévérité/probabilité
- [ ] Recommandations de correction

### Optionnel
- [ ] Intégration API Scorton
- [ ] Pipeline automatisé
- [ ] Dashboard de visualisation
- [ ] Historique des scans
- [ ] Alertes automatiques

## 💡 Cas d'Usage

### 1. Audit de sécurité rapide
```bash
python web_scanner.py mon-site.com -o audit_securite
```

### 2. Surveillance domaine récent
```bash
python web_scanner.py nouveau-domaine.com -v
# Vérifie l'âge du domaine et les signaux faibles
```

### 3. Vérification certificat
```bash
python web_scanner.py mon-api.com
# Alerte si certificat expire bientôt
```

### 4. Analyse comparative
```bash
python web_scanner.py concurrent-1.com -o concurrent1
python web_scanner.py concurrent-2.com -o concurrent2
# Compare les rapports JSON
```

## 🤝 Contribution

Améliorations bienvenues :
- Nouvelles détections d'anomalies
- Support de technologies spécifiques
- Optimisations de performance
- Correction de bugs

## 📝 Licence

Voir [LICENSE](../LICENSE) à la racine du projet.

---

**Auteur** : Challenge 1 Team Rayban  
**Date** : Novembre 2025  
**Version** : 1.0.0
