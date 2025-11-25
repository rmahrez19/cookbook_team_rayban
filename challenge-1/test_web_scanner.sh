#!/bin/bash
# Script de test rapide du web scanner

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    TEST RAPIDE - WEB SCANNER CHALLENGE 1                     ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Vérification des dépendances
echo "🔍 Vérification des dépendances..."
if ! python -c "import requests, bs4, whois, OpenSSL" 2>/dev/null; then
    echo "❌ Dépendances manquantes. Installation..."
    pip install -r requirements.txt -q
    echo "✅ Dépendances installées"
else
    echo "✅ Toutes les dépendances sont présentes"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Test 1: Site avec HTTPS et certificat valide (GitHub)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python web_scanner.py github.com -o test1_github
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Test 2: Site HTTP sans chiffrement"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python web_scanner.py http://neverssl.com -o test2_http
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Test 3: Site basique (Example.com)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python web_scanner.py example.com -o test3_example
echo ""

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                              RÉSUMÉ DES TESTS                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "✅ Tests terminés avec succès !"
echo ""
echo "📁 Fichiers générés :"
ls -lh test*.txt test*.json 2>/dev/null | awk '{print "   " $9 " (" $5 ")"}'
echo ""
echo "💡 Pour consulter un rapport :"
echo "   cat test1_github.txt"
echo ""
echo "💡 Pour analyser les données JSON :"
echo "   cat test1_github.json | python -m json.tool"
echo ""
echo "💡 Pour un nouveau scan :"
echo "   python web_scanner.py <URL>"
echo ""
