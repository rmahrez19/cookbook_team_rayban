#!/usr/bin/env python3
"""
Exemples d'utilisation du Web Scanner
Démonstration des différentes fonctionnalités
"""

import subprocess
import sys


def run_scan(url, output_name=None, verbose=False):
    """Lance un scan et affiche le résultat"""
    cmd = ["python", "web_scanner.py", url]
    
    if output_name:
        cmd.extend(["-o", output_name])
    
    if verbose:
        cmd.append("-v")
    
    print(f"\n{'='*80}")
    print(f"Scan de : {url}")
    print(f"{'='*80}\n")
    
    result = subprocess.run(cmd, capture_output=False, text=True)
    return result.returncode == 0


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      EXEMPLES D'UTILISATION - WEB SCANNER                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Liste des exemples à tester
    examples = [
        {
            "name": "Site sécurisé populaire",
            "url": "github.com",
            "output": "scan_github",
            "description": "Site avec bonnes pratiques de sécurité"
        },
        {
            "name": "Site de test basique",
            "url": "example.com",
            "output": "scan_example",
            "description": "Site simple pour tester les détections de base"
        },
        {
            "name": "Site HTTP non sécurisé",
            "url": "http://neverssl.com",
            "output": "scan_http",
            "description": "Site sans HTTPS pour tester la détection"
        }
    ]
    
    # Menu interactif
    print("\nExemples disponibles :\n")
    for i, example in enumerate(examples, 1):
        print(f"{i}. {example['name']}")
        print(f"   URL: {example['url']}")
        print(f"   Description: {example['description']}\n")
    
    print("0. Lancer tous les exemples")
    print("q. Quitter\n")
    
    try:
        choice = input("Choisissez un exemple (0-3, q pour quitter) : ").strip()
        
        if choice.lower() == 'q':
            print("\nAu revoir !")
            return
        
        choice = int(choice)
        
        if choice == 0:
            # Lancer tous les exemples
            print("\n🚀 Lancement de tous les exemples...\n")
            for example in examples:
                success = run_scan(
                    example['url'],
                    output_name=example['output']
                )
                if not success:
                    print(f"⚠️  Erreur lors du scan de {example['url']}")
            
            print("\n✅ Tous les scans sont terminés !")
            print("\nFichiers générés :")
            for example in examples:
                print(f"  - {example['output']}.txt")
                print(f"  - {example['output']}.json")
        
        elif 1 <= choice <= len(examples):
            # Lancer un exemple spécifique
            example = examples[choice - 1]
            print(f"\n🚀 Lancement du scan : {example['name']}\n")
            
            verbose = input("Mode verbeux ? (o/n) : ").strip().lower() == 'o'
            
            success = run_scan(
                example['url'],
                output_name=example['output'],
                verbose=verbose
            )
            
            if success:
                print(f"\n✅ Scan terminé avec succès !")
                print(f"\nFichiers générés :")
                print(f"  - {example['output']}.txt")
                print(f"  - {example['output']}.json")
            else:
                print(f"\n⚠️  Erreur lors du scan")
        
        else:
            print("❌ Choix invalide")
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Interruption par l'utilisateur")
    except ValueError:
        print("❌ Entrée invalide")
    except Exception as e:
        print(f"❌ Erreur : {e}")


if __name__ == "__main__":
    main()
