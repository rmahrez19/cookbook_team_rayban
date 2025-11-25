# Documentation Technique - Scanner de Malware

## Architecture

### Structure du code

```
malware_scanner.py
├── MalwareScanner (classe principale)
│   ├── __init__()           # Initialisation et configuration
│   ├── fetch_content()      # Récupération du contenu web
│   ├── check_security_headers()  # Analyse des en-têtes HTTP
│   ├── analyze_scripts()    # Analyse des scripts JavaScript
│   ├── analyze_iframes()    # Analyse des iframes
│   ├── analyze_links()      # Analyse des liens externes
│   ├── is_obfuscated()      # Détection d'obfuscation
│   ├── calculate_risk_level()  # Calcul du score de risque
│   ├── scan()               # Orchestration du scan
│   └── generate_report()    # Génération du rapport
└── main()                   # Point d'entrée CLI
```

## Méthodologie de détection

### 1. Analyse des en-têtes de sécurité

Vérifie la présence des en-têtes HTTP critiques :
- **Content-Security-Policy** : Protection contre XSS
- **X-Frame-Options** : Protection contre clickjacking
- **X-Content-Type-Options** : Prévention du MIME sniffing
- **Strict-Transport-Security** : Force HTTPS
- **X-XSS-Protection** : Protection XSS du navigateur

**Critère de risque** : Absence = MEDIUM

### 2. Détection de patterns JavaScript malveillants

Patterns recherchés par regex :
```python
- eval\s*\(              # Exécution dynamique
- document\.write        # Injection DOM
- fromCharCode           # Obfuscation
- unescape\s*\(          # Décodage
- atob\s*\(              # Décodage Base64
- base64_decode          # PHP
- exec\s*\(              # Exécution
- shell_exec             # Shell
- cryptocurrency|mining  # Cryptojacking
```

**Critère de risque** : 1+ match = HIGH

### 3. Détection de code obfusqué

Méthode heuristique basée sur :
1. **Ratio de caractères non-alphanumériques** : > 40%
2. **Séquences hexadécimales** : > 10 occurrences de `\xNN`
3. **Noms de variables courts** : > 50 variables de 1-3 caractères

**Critère de risque** : Obfuscation détectée = HIGH

### 4. Analyse des iframes

Détection de :
- **Iframes externes** : Domaine différent du site principal
- **Iframes cachés** : `display:none`, `width:0`, `height:0`
- **Domaines suspects** : TLDs gratuits (.tk, .ml, etc.)

**Critère de risque** : 
- Iframe caché = HIGH
- Iframe suspect = MEDIUM

### 5. Analyse des liens

Vérification de :
- Liens vers raccourcisseurs d'URL (bit.ly, tinyurl, etc.)
- TLDs à haut risque (.tk, .ml, .ga, .cf, .gq)
- Protocoles non-sécurisés (http://)

**Critère de risque** : Domaine suspect = MEDIUM

## Algorithme de scoring

```python
def calculate_risk_level():
    high_threats = count(severity == "HIGH")
    medium_threats = count(severity == "MEDIUM")
    
    if high_threats >= 3 OR (high_threats >= 1 AND medium_threats >= 3):
        return "CRITICAL"
    elif high_threats >= 1 OR medium_threats >= 3:
        return "HIGH"
    elif medium_threats >= 1:
        return "MEDIUM"
    else:
        return "LOW"
```

## Format des données JSON

```json
{
  "url": "https://example.com",
  "timestamp": "2025-11-25T10:30:00",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "threats_found": [
    {
      "type": "string",
      "severity": "LOW|MEDIUM|HIGH",
      "description": "string"
    }
  ],
  "suspicious_patterns": [
    {
      "type": "string",
      "pattern": "regex",
      "matches": number,
      "context": "string"
    }
  ],
  "scripts": [
    {
      "src": "string|inline",
      "inline": boolean,
      "content_hash": "md5",
      "suspicious": boolean,
      "obfuscated": boolean,
      "external_domain": "string"
    }
  ],
  "iframes": [
    {
      "src": "string",
      "suspicious": boolean,
      "external": boolean,
      "hidden": boolean
    }
  ],
  "external_links": [
    {
      "url": "string",
      "domain": "string",
      "text": "string"
    }
  ],
  "security_headers": {
    "Content-Security-Policy": "string|ABSENT",
    "X-Frame-Options": "string|ABSENT",
    ...
  },
  "obfuscated_code": [
    {
      "type": "string",
      "hash": "md5",
      "sample": "string"
    }
  ]
}
```

## Dépendances

### requests (>= 2.31.0)
- Gestion des requêtes HTTP/HTTPS
- Support des en-têtes personnalisés
- Gestion des timeouts et redirections

### BeautifulSoup4 (>= 4.12.0)
- Parsing HTML/XML
- Navigation dans l'arbre DOM
- Extraction de balises et attributs

### lxml (>= 4.9.0)
- Parser rapide pour BeautifulSoup
- Support XML complet

## Sécurité du scanner

Le scanner est conçu pour être sûr :
- ✅ Aucune exécution de JavaScript
- ✅ Aucune exécution de code distant
- ✅ Analyse statique uniquement
- ✅ Timeout de 10 secondes
- ✅ Vérification SSL activée
- ✅ User-Agent identifiable

## Optimisations possibles

1. **Cache de résultats** : Éviter de re-scanner les mêmes URLs
2. **Parallélisation** : Scanner plusieurs URLs simultanément
3. **Base de données de signatures** : Maintenir une DB de patterns
4. **Machine Learning** : Classifier automatiquement le contenu
5. **Intégration API** : VirusTotal, Google Safe Browsing, etc.

## Tests unitaires (à implémenter)

```python
# test_malware_scanner.py

def test_obfuscation_detection():
    # Teste la détection de code obfusqué
    pass

def test_pattern_matching():
    # Teste la détection de patterns
    pass

def test_risk_calculation():
    # Teste le calcul du score de risque
    pass
```

## Limitations connues

1. **JavaScript dynamique** : Ne détecte pas le code chargé dynamiquement
2. **Contenu authentifié** : Ne peut pas analyser les zones protégées
3. **Malware polymorphe** : Peut contourner la détection par regex
4. **Faux positifs** : Certains sites légitimes peuvent être marqués suspects
5. **Sites SPA** : Analyse limitée sur les Single Page Applications

## Compliance et légalité

⚠️ **Avertissement** : L'utilisation de ce scanner doit respecter :
- Les conditions d'utilisation des sites scannés
- Les lois sur l'accès aux systèmes informatiques
- Le RGPD pour le traitement de données

Usage recommandé : Analyse de vos propres sites ou avec autorisation explicite.
