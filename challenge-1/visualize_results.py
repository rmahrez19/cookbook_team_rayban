#!/usr/bin/env python3
"""
Visualiseur de résultats JSON du Web Scanner
Affiche les résultats de manière formatée et lisible
"""

import json
import sys
import argparse
from datetime import datetime
from pathlib import Path


def format_date(date_str):
    """Formate une date ISO pour affichage"""
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.strftime('%d/%m/%Y %H:%M:%S')
    except:
        return date_str


def print_separator(char='=', length=80):
    """Imprime une ligne de séparation"""
    print(char * length)


def print_section(title, char='-'):
    """Imprime un titre de section"""
    print(f"\n{title}")
    print(char * len(title))


def visualize_scan(json_file):
    """Visualise les résultats d'un scan"""
    
    # Lecture du fichier JSON
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ Fichier non trouvé : {json_file}")
        return False
    except json.JSONDecodeError:
        print(f"❌ Erreur de lecture JSON : {json_file}")
        return False
    
    # En-tête
    print_separator('═')
    print("           🔍 VISUALISATION DES RÉSULTATS - WEB SCANNER           ")
    print_separator('═')
    
    # Informations générales
    print_section("📋 INFORMATIONS GÉNÉRALES")
    print(f"URL analysée  : {data.get('url')}")
    print(f"Domaine       : {data.get('domain')}")
    print(f"Date du scan  : {format_date(data.get('scan_date', ''))}")
    
    # Analyse de risque
    analysis = data.get('analysis', {})
    risk_level = analysis.get('risk_level', 'UNKNOWN')
    risk_score = analysis.get('risk_score', 0)
    anomalies_count = analysis.get('anomalies_count', 0)
    
    risk_emoji = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢'
    }.get(risk_level, '⚪')
    
    print_section("🎯 ÉVALUATION DU RISQUE")
    print(f"Niveau        : {risk_emoji} {risk_level}")
    print(f"Score         : {risk_score} points")
    print(f"Anomalies     : {anomalies_count}")
    
    # Anomalies détaillées
    anomalies = data.get('anomalies', [])
    if anomalies:
        print_section("🚨 ANOMALIES DÉTECTÉES", '═')
        
        # Grouper par sévérité
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'LOW')
            by_severity.get(severity, by_severity['LOW']).append(anomaly)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            items = by_severity.get(severity, [])
            if items:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}[severity]
                print(f"\n{emoji} {severity} ({len(items)})")
                for i, anomaly in enumerate(items, 1):
                    print(f"  {i}. {anomaly.get('title')}")
                    print(f"     └─ {anomaly.get('description')}")
    else:
        print_section("✅ AUCUNE ANOMALIE DÉTECTÉE")
    
    # Données collectées
    collection = data.get('collection', {})
    
    print_section("📦 DONNÉES COLLECTÉES", '═')
    
    # HTTP
    if 'http' in collection:
        http = collection['http']
        print_section("🌐 HTTP/HTTPS")
        print(f"Status code   : {http.get('status_code')}")
        print(f"URL finale    : {http.get('final_url')}")
        print(f"Redirections  : {len(http.get('redirects', []))}")
        print(f"Taille HTML   : {http.get('html_size'):,} bytes")
        print(f"Content-Type  : {http.get('content_type')}")
        
        # Structure HTML
        if 'html_structure' in collection:
            struct = collection['html_structure']
            print(f"\n  Structure HTML:")
            print(f"    Title       : {struct.get('title', 'N/A')[:60]}...")
            print(f"    Meta tags   : {struct.get('meta_tags')}")
            print(f"    Scripts     : {struct.get('scripts')}")
            print(f"    Iframes     : {struct.get('iframes')}")
            print(f"    Forms       : {struct.get('forms')}")
        
        # Headers de sécurité clés
        headers = http.get('headers', {})
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection'
        ]
        
        print(f"\n  Headers de sécurité:")
        for header in security_headers:
            status = '✅' if header in headers else '❌'
            value = headers.get(header, 'ABSENT')
            if len(str(value)) > 50:
                value = str(value)[:47] + "..."
            print(f"    {status} {header}: {value}")
    
    # TLS/SSL
    if 'tls' in collection and 'error' not in collection['tls']:
        tls = collection['tls']
        print_section("🔐 CERTIFICAT TLS/SSL")
        
        issuer = tls.get('issuer', {})
        issuer_name = issuer.get('O', issuer.get('CN', 'N/A'))
        
        print(f"Émetteur      : {issuer_name}")
        print(f"Sujet (CN)    : {tls.get('subject', {}).get('CN', 'N/A')}")
        print(f"Algorithme    : {tls.get('signature_algorithm')}")
        print(f"Version       : {tls.get('version')}")
        
        days_left = tls.get('days_until_expiry', 0)
        expiry_status = '✅' if days_left > 30 else ('⚠️' if days_left > 0 else '❌')
        print(f"Expire dans   : {expiry_status} {days_left} jours")
        print(f"Date début    : {format_date(tls.get('not_before', ''))}")
        print(f"Date fin      : {format_date(tls.get('not_after', ''))}")
        
        has_expired = '❌ OUI' if tls.get('has_expired') else '✅ NON'
        print(f"A expiré      : {has_expired}")
    elif 'tls_error' in collection:
        print_section("🔐 CERTIFICAT TLS/SSL")
        print(f"❌ Erreur : {collection.get('tls_error')}")
    
    # WHOIS
    if 'whois' in collection:
        whois = collection['whois']
        print_section("📋 INFORMATIONS WHOIS")
        
        print(f"Nom domaine   : {whois.get('domain_name')}")
        print(f"Registrar     : {whois.get('registrar', 'N/A')}")
        
        age_days = whois.get('age_days')
        if age_days is not None:
            age_years = age_days / 365
            age_status = '🆕' if age_days < 90 else '✅'
            print(f"Âge           : {age_status} {age_days} jours ({age_years:.1f} ans)")
        
        days_expiry = whois.get('days_until_expiry')
        if days_expiry is not None:
            expiry_status = '✅' if days_expiry > 90 else ('⚠️' if days_expiry > 0 else '❌')
            print(f"Expire dans   : {expiry_status} {days_expiry} jours")
        
        if whois.get('creation_date'):
            print(f"Créé le       : {format_date(whois.get('creation_date'))}")
        if whois.get('expiration_date'):
            print(f"Expire le     : {format_date(whois.get('expiration_date'))}")
        if whois.get('updated_date'):
            print(f"MAJ le        : {format_date(whois.get('updated_date'))}")
        
        # Name servers
        name_servers = whois.get('name_servers', [])
        if name_servers:
            print(f"\n  Name Servers ({len(name_servers)}):")
            for ns in name_servers[:5]:  # Limiter à 5
                print(f"    • {ns}")
            if len(name_servers) > 5:
                print(f"    ... et {len(name_servers) - 5} autres")
    elif 'whois_error' in collection:
        print_section("📋 INFORMATIONS WHOIS")
        print(f"❌ Erreur : {collection.get('whois_error')}")
    
    # Résumé final
    print_separator('═')
    print(f"Fichier analysé : {json_file}")
    print(f"Taille          : {Path(json_file).stat().st_size:,} bytes")
    print_separator('═')
    print()
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Visualise les résultats JSON du Web Scanner"
    )
    parser.add_argument(
        'json_file',
        help="Fichier JSON à visualiser"
    )
    
    args = parser.parse_args()
    
    try:
        success = visualize_scan(args.json_file)
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interruption par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erreur : {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
