# 🚀 Démarrage Rapide - Web Scanner

## Installation en 3 commandes

```bash
# 1. Aller dans le dossier
cd challenge-1

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer un scan
python web_scanner.py github.com
```

## Exemples Rapides

### 1. Scan basique
```bash
python web_scanner.py example.com
```
→ Génère `scan_example.com_YYYYMMDD_HHMMSS.txt` et `.json`

### 2. Scan avec nom personnalisé
```bash
python web_scanner.py github.com -o mon_analyse
```
→ Génère `mon_analyse.txt` et `mon_analyse.json`

### 3. Scan verbeux (debugging)
```bash
python web_scanner.py suspicious-site.com -v
```
→ Affiche les détails de chaque étape

### 4. Tests automatisés
```bash
./test_web_scanner.sh
```
→ Teste 3 sites différents automatiquement

### 5. Mode démo interactif
```bash
python demo_web_scanner.py
```
→ Menu interactif pour tester différents sites

### 6. Visualiser un résultat
```bash
python visualize_results.py mon_analyse.json
```
→ Affichage formaté et coloré des résultats

## 📖 Aide

```bash
python web_scanner.py --help
```

## 📄 Documentation Complète

- [`WEB_SCANNER_README.md`](WEB_SCANNER_README.md) - Documentation complète
- [`GUIDE_WEB_SCANNER.md`](GUIDE_WEB_SCANNER.md) - Guide d'utilisation
- [`IMPLEMENTATION_ETAPES_1_2.md`](IMPLEMENTATION_ETAPES_1_2.md) - Récapitulatif technique

## 🎯 Ce qui est couvert

✅ **Étape 1** : Collecte HTTP, TLS, WHOIS  
✅ **Étape 2** : Détection d'anomalies et scoring

## ⚡ Workflow Recommandé

```bash
# 1. Scanner un site
python web_scanner.py monsite.com -o analyse_monsite

# 2. Visualiser le résultat
python visualize_results.py analyse_monsite.json

# 3. Consulter le rapport texte
cat analyse_monsite.txt
```

## 🔥 Tips

- Sans `https://`, le script ajoutera automatiquement `https://`
- Les erreurs WHOIS sont normales pour certains domaines
- Mode `-v` utile pour comprendre ce qui se passe
- JSON utile pour traitement automatique
- TXT utile pour lecture humaine

## 🐛 En cas de problème

```bash
# Réinstaller les dépendances
pip install -r requirements.txt --force-reinstall

# Vérifier la version Python (≥ 3.7 requis)
python --version

# Tester avec un site simple
python web_scanner.py example.com -v
```
