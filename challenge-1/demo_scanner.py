#!/usr/bin/env python3
"""
Script de démonstration du scanner de malware
Teste le scanner sur différents cas d'usage
"""

import sys
import os

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.dirname(__file__))

from malware_scanner import MalwareScanner


def demo_safe_site():
    """Exemple avec un site sûr"""
    print("\n" + "="*80)
    print("EXEMPLE 1: Site sûr (example.com)")
    print("="*80)
    
    scanner = MalwareScanner("https://example.com")
    results = scanner.scan()
    scanner.generate_report("example_safe_report.txt")


def demo_suspicious_patterns():
    """Exemple avec simulation de patterns suspects"""
    print("\n" + "="*80)
    print("EXEMPLE 2: Détection de patterns (simulation locale)")
    print("="*80)
    print("\nCe test démontre la détection de patterns suspects dans du code JavaScript:")
    print("- eval() pour exécution dynamique")
    print("- document.write pour injection")
    print("- Code base64 obfusqué")
    print("- Redirections suspectes")


def main():
    """Démonstration du scanner"""
    print("\n🔍 DÉMONSTRATION DU SCANNER DE MALWARE")
    print("="*80)
    
    print("\nCe script démontre les capacités du scanner:")
    print("1. Analyse d'un site web réel")
    print("2. Détection de patterns malveillants")
    print("3. Génération de rapports détaillés")
    
    # Test avec un site sûr
    try:
        demo_safe_site()
    except Exception as e:
        print(f"❌ Erreur lors de la démo: {e}")
    
    print("\n✅ Démonstration terminée!")
    print("\nPour utiliser le scanner:")
    print("  python malware_scanner.py <URL>")
    print("\nExemples:")
    print("  python malware_scanner.py https://example.com")
    print("  python malware_scanner.py https://www.python.org -o rapport.txt")


if __name__ == "__main__":
    main()
