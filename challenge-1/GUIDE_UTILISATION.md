# Guide d'utilisation rapide - Scanner de Malware

## Installation rapide

```bash
# 1. Installer les dépendances
pip install requests beautifulsoup4 lxml

# 2. Rendre le script exécutable
chmod +x malware_scanner.py
```

## Utilisation

### Commande de base
```bash
python malware_scanner.py https://example.com
```

### Options disponibles
```bash
# Avec fichier de sortie personnalisé
python malware_scanner.py https://example.com -o mon_rapport.txt

# Mode verbeux (affiche les erreurs détaillées)
python malware_scanner.py https://example.com --verbose

# Afficher l'aide
python malware_scanner.py --help
```

## Test rapide

```bash
# Tester avec un site sûr
python malware_scanner.py https://example.com

# Tester avec Python.org
python malware_scanner.py https://www.python.org -o python_rapport.txt
```

## Interprétation des résultats

### Niveaux de risque
- 🟢 **LOW** : Aucune menace détectée, site sûr
- 🟡 **MEDIUM** : Quelques éléments suspects, prudence recommandée
- 🟠 **HIGH** : Plusieurs menaces détectées
- 🔴 **CRITICAL** : Site dangereux, ne pas utiliser

### Types de menaces détectées
1. **missing_security_header** : En-tête de sécurité absent
2. **suspicious_script_pattern** : Pattern JavaScript suspect (eval, document.write, etc.)
3. **obfuscated_code** : Code JavaScript fortement obfusqué
4. **suspicious_external_script** : Script provenant d'un domaine suspect
5. **suspicious_iframe** : Iframe pointant vers un site suspect
6. **hidden_iframe** : Iframe invisible (technique de malware)
7. **suspicious_link** : Lien vers un domaine malveillant connu

## Fichiers générés

Après l'analyse, deux fichiers sont créés :
1. **`rapport_YYYYMMDD_HHMMSS.txt`** : Rapport lisible
2. **`rapport_YYYYMMDD_HHMMSS.json`** : Données structurées JSON

## Exemples de commandes

```bash
# Analyser un site et sauvegarder le rapport
python malware_scanner.py https://suspicious-site.com -o suspect_report.txt

# Analyser plusieurs sites (script bash)
for url in https://site1.com https://site2.com https://site3.com; do
    python malware_scanner.py "$url" -o "report_$(echo $url | tr '/:' '_').txt"
done
```

## Patterns détectés

Le scanner recherche automatiquement :
- ✅ Code JavaScript malveillant (eval, exec, etc.)
- ✅ Obfuscation de code
- ✅ Iframes cachés ou suspects
- ✅ Redirections suspectes
- ✅ Scripts provenant de domaines malveillants
- ✅ Absence d'en-têtes de sécurité
- ✅ Cryptojacking (mining de cryptomonnaies)

## Limitations

⚠️ Ce scanner détecte les patterns courants mais ne garantit pas une détection à 100% des malwares.
Il est recommandé de l'utiliser en complément d'autres outils de sécurité.
