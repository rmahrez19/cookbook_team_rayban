#!/usr/bin/env python3
"""
Scanner de site web - Challenge 1
Étapes 1 & 2 : Collecte & Ingestion + Analyse & Détection
"""

import sys
import ssl
import socket
import json
import whois
from datetime import datetime, timedelta
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import OpenSSL.crypto
import argparse


class WebScanner:
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        self.results = {
            "url": url,
            "domain": self.domain,
            "scan_date": datetime.now().isoformat(),
            "collection": {},
            "analysis": {},
            "anomalies": []
        }
    
    def log(self, message):
        """Affiche un message si mode verbeux activé"""
        if self.verbose:
            print(f"[INFO] {message}")
    
    # ========== ÉTAPE 1 : COLLECTE & INGESTION ==========
    
    def collect_http_data(self):
        """Récupération du HTML, headers, redirections"""
        self.log("Collecte des données HTTP...")
        
        try:
            response = requests.get(
                self.url, 
                allow_redirects=True,
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 WebScanner/1.0'}
            )
            
            self.results["collection"]["http"] = {
                "status_code": response.status_code,
                "final_url": response.url,
                "redirects": [r.url for r in response.history],
                "headers": dict(response.headers),
                "html_size": len(response.content),
                "content_type": response.headers.get('Content-Type', 'unknown')
            }
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            self.results["collection"]["html_structure"] = {
                "title": soup.title.string if soup.title else None,
                "meta_tags": len(soup.find_all('meta')),
                "scripts": len(soup.find_all('script')),
                "iframes": len(soup.find_all('iframe')),
                "forms": len(soup.find_all('form'))
            }
            
            self.log(f"✓ HTTP collecté : {response.status_code}, {len(response.content)} bytes")
            return True
            
        except Exception as e:
            self.results["collection"]["http_error"] = str(e)
            self.log(f"✗ Erreur HTTP : {e}")
            return False
    
    def collect_tls_certificate(self):
        """Récupération du certificat TLS/SSL"""
        self.log("Collecte du certificat TLS...")
        
        if not self.parsed_url.scheme == 'https':
            self.results["collection"]["tls"] = {"error": "Non-HTTPS"}
            self.log("✗ Pas de HTTPS")
            return False
        
        try:
            hostname = self.domain
            port = 443
            
            # Connexion SSL
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert_bin = secure_sock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1, 
                        cert_bin
                    )
                    
                    # Extraction des informations
                    subject = {k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v 
                               for k, v in cert.get_subject().get_components()}
                    issuer = {k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v 
                              for k, v in cert.get_issuer().get_components()}
                    
                    not_before = datetime.strptime(
                        cert.get_notBefore().decode('ascii'),
                        '%Y%m%d%H%M%SZ'
                    )
                    not_after = datetime.strptime(
                        cert.get_notAfter().decode('ascii'),
                        '%Y%m%d%H%M%SZ'
                    )
                    
                    self.results["collection"]["tls"] = {
                        "subject": subject,
                        "issuer": issuer,
                        "version": cert.get_version(),
                        "serial_number": cert.get_serial_number(),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "days_until_expiry": (not_after - datetime.now()).days,
                        "signature_algorithm": cert.get_signature_algorithm().decode(),
                        "has_expired": cert.has_expired()
                    }
                    
                    self.log(f"✓ Certificat collecté : expire dans {self.results['collection']['tls']['days_until_expiry']} jours")
                    return True
                    
        except Exception as e:
            self.results["collection"]["tls_error"] = str(e)
            self.log(f"✗ Erreur TLS : {e}")
            return False
    
    def collect_whois(self):
        """Extraction WHOIS : dates clés, registrar, durée de vie"""
        self.log("Collecte des données WHOIS...")
        
        try:
            w = whois.whois(self.domain)
            
            # Normalisation des dates (peuvent être listes ou dates uniques)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            updated_date = w.updated_date
            if isinstance(updated_date, list):
                updated_date = updated_date[0]
            
            # Calcul de la durée de vie
            age_days = None
            if creation_date:
                # S'assurer que creation_date est aware ou naive comme datetime.now()
                if creation_date.tzinfo is None:
                    age_days = (datetime.now() - creation_date).days
                else:
                    from datetime import timezone
                    age_days = (datetime.now(timezone.utc) - creation_date).days
            
            days_until_expiry = None
            if expiration_date:
                # S'assurer que expiration_date est aware ou naive comme datetime.now()
                if expiration_date.tzinfo is None:
                    days_until_expiry = (expiration_date - datetime.now()).days
                else:
                    from datetime import timezone
                    days_until_expiry = (expiration_date - datetime.now(timezone.utc)).days
            
            self.results["collection"]["whois"] = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": creation_date.isoformat() if creation_date else None,
                "expiration_date": expiration_date.isoformat() if expiration_date else None,
                "updated_date": updated_date.isoformat() if updated_date else None,
                "age_days": age_days,
                "days_until_expiry": days_until_expiry,
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else []
            }
            
            self.log(f"✓ WHOIS collecté : {age_days} jours d'âge")
            return True
            
        except Exception as e:
            self.results["collection"]["whois_error"] = str(e)
            self.log(f"✗ Erreur WHOIS : {e}")
            return False
    
    # ========== ÉTAPE 2 : ANALYSE & DÉTECTION ==========
    
    def analyze_certificate(self):
        """Certificat faible ou expirant"""
        self.log("Analyse du certificat...")
        
        if "tls" not in self.results["collection"] or "error" in self.results["collection"].get("tls", {}):
            self.add_anomaly(
                "CRITICAL",
                "Absence de HTTPS",
                "Le site n'utilise pas HTTPS, les données ne sont pas chiffrées"
            )
            return
        
        tls = self.results["collection"]["tls"]
        
        # Certificat expiré
        if tls.get("has_expired"):
            self.add_anomaly(
                "CRITICAL",
                "Certificat expiré",
                "Le certificat SSL/TLS a expiré, connexion non sécurisée"
            )
        
        # Certificat expirant bientôt
        days_left = tls.get("days_until_expiry", 999)
        if 0 < days_left <= 30:
            self.add_anomaly(
                "HIGH",
                "Certificat expirant bientôt",
                f"Le certificat expire dans {days_left} jours"
            )
        elif 30 < days_left <= 60:
            self.add_anomaly(
                "MEDIUM",
                "Certificat expire dans moins de 2 mois",
                f"Le certificat expire dans {days_left} jours, renouvellement recommandé"
            )
        
        # Algorithme de signature faible
        sig_algo = tls.get("signature_algorithm", "").lower()
        if "md5" in sig_algo or "sha1" in sig_algo:
            self.add_anomaly(
                "HIGH",
                "Algorithme de signature faible",
                f"Utilisation de {sig_algo}, considéré comme non sécurisé"
            )
    
    def analyze_redirections(self):
        """Redirection anormale"""
        self.log("Analyse des redirections...")
        
        if "http" not in self.results["collection"]:
            return
        
        http = self.results["collection"]["http"]
        redirects = http.get("redirects", [])
        
        # Trop de redirections
        if len(redirects) > 3:
            self.add_anomaly(
                "MEDIUM",
                "Chaîne de redirection longue",
                f"{len(redirects)} redirections détectées, peut indiquer du cloaking"
            )
        
        # Redirection HTTP → HTTPS manquante
        if self.parsed_url.scheme == 'http' and not any('https://' in r for r in redirects):
            self.add_anomaly(
                "MEDIUM",
                "Pas de redirection HTTPS automatique",
                "Le site n'impose pas HTTPS, risque d'interception"
            )
        
        # Redirection vers un domaine différent
        final_domain = urlparse(http.get("final_url", "")).netloc
        if final_domain and final_domain != self.domain:
            self.add_anomaly(
                "MEDIUM",
                "Redirection vers un domaine différent",
                f"Redirection de {self.domain} vers {final_domain}"
            )
    
    def analyze_html_size(self):
        """Taille HTML anormale"""
        self.log("Analyse de la taille HTML...")
        
        if "http" not in self.results["collection"]:
            return
        
        html_size = self.results["collection"]["http"].get("html_size", 0)
        
        # Taille anormalement petite (peut indiquer une page vide ou erreur)
        if html_size < 500:
            self.add_anomaly(
                "MEDIUM",
                "Page HTML très petite",
                f"Seulement {html_size} bytes, peut indiquer une page vide ou erreur"
            )
        
        # Taille anormalement grande
        elif html_size > 2_000_000:  # 2 MB
            self.add_anomaly(
                "LOW",
                "Page HTML très volumineuse",
                f"{html_size:,} bytes, peut impacter les performances"
            )
    
    def analyze_security_headers(self):
        """Absence de headers de sécurité"""
        self.log("Analyse des headers de sécurité...")
        
        if "http" not in self.results["collection"]:
            return
        
        headers = self.results["collection"]["http"].get("headers", {})
        
        security_headers = {
            "Strict-Transport-Security": "HSTS manquant",
            "Content-Security-Policy": "CSP manquant",
            "X-Frame-Options": "Protection anti-iframe manquante",
            "X-Content-Type-Options": "Protection anti-MIME sniffing manquante",
            "X-XSS-Protection": "Protection XSS manquante"
        }
        
        missing = []
        for header, description in security_headers.items():
            if header not in headers:
                missing.append(description)
        
        if len(missing) >= 3:
            self.add_anomaly(
                "HIGH",
                "Headers de sécurité manquants",
                f"{len(missing)}/5 headers absents : {', '.join(missing)}"
            )
        elif missing:
            self.add_anomaly(
                "MEDIUM",
                "Certains headers de sécurité manquants",
                ', '.join(missing)
            )
    
    def analyze_domain_age(self):
        """Domaine très récent (signal faible de phishing)"""
        self.log("Analyse de l'âge du domaine...")
        
        if "whois" not in self.results["collection"]:
            return
        
        age_days = self.results["collection"]["whois"].get("age_days")
        
        if age_days is not None:
            if age_days < 30:
                self.add_anomaly(
                    "HIGH",
                    "Domaine très récent",
                    f"Créé il y a {age_days} jours, signal faible de phishing potentiel"
                )
            elif age_days < 90:
                self.add_anomaly(
                    "MEDIUM",
                    "Domaine récent",
                    f"Créé il y a {age_days} jours"
                )
    
    def add_anomaly(self, severity, title, description):
        """Ajoute une anomalie détectée"""
        self.results["anomalies"].append({
            "severity": severity,
            "title": title,
            "description": description
        })
    
    # ========== EXÉCUTION COMPLÈTE ==========
    
    def run(self):
        """Exécute toutes les étapes de scan"""
        print(f"\n{'='*80}")
        print(f"SCAN EXTERNE - {self.url}")
        print(f"{'='*80}\n")
        
        # ÉTAPE 1 : Collecte
        print("📊 ÉTAPE 1 : COLLECTE & INGESTION")
        print("-" * 80)
        self.collect_http_data()
        self.collect_tls_certificate()
        self.collect_whois()
        
        # ÉTAPE 2 : Analyse
        print("\n🔍 ÉTAPE 2 : ANALYSE & DÉTECTION")
        print("-" * 80)
        self.analyze_certificate()
        self.analyze_redirections()
        self.analyze_html_size()
        self.analyze_security_headers()
        self.analyze_domain_age()
        
        # Calcul du score de risque
        self.calculate_risk_score()
        
        return self.results
    
    def calculate_risk_score(self):
        """Calcule un score de risque basé sur les anomalies"""
        severity_weights = {
            "CRITICAL": 100,
            "HIGH": 50,
            "MEDIUM": 20,
            "LOW": 5
        }
        
        score = sum(severity_weights.get(a["severity"], 0) for a in self.results["anomalies"])
        
        if score >= 100:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        self.results["analysis"]["risk_score"] = score
        self.results["analysis"]["risk_level"] = risk_level
        self.results["analysis"]["anomalies_count"] = len(self.results["anomalies"])
    
    def generate_report(self, output_file=None):
        """Génère un rapport lisible"""
        report = []
        report.append("=" * 80)
        report.append("RAPPORT D'ANALYSE EXTERNE")
        report.append("=" * 80)
        report.append(f"\n📅 Date: {self.results['scan_date']}")
        report.append(f"🌐 URL: {self.url}")
        report.append(f"🏷️  Domaine: {self.domain}")
        
        # Score de risque
        risk_level = self.results["analysis"].get("risk_level", "UNKNOWN")
        risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk_level, "⚪")
        report.append(f"\n{risk_emoji} NIVEAU DE RISQUE: {risk_level}")
        report.append(f"📊 Score: {self.results['analysis'].get('risk_score', 0)}")
        
        # Anomalies
        report.append(f"\n{'='*80}")
        report.append(f"🚨 ANOMALIES DÉTECTÉES: {len(self.results['anomalies'])}")
        report.append("-" * 80)
        
        if self.results["anomalies"]:
            for i, anomaly in enumerate(self.results["anomalies"], 1):
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(anomaly["severity"], "⚪")
                report.append(f"\n{i}. {emoji} [{anomaly['severity']}] {anomaly['title']}")
                report.append(f"   {anomaly['description']}")
        else:
            report.append("\n✓ Aucune anomalie majeure détectée")
        
        # Détails de collecte
        report.append(f"\n{'='*80}")
        report.append("📦 DONNÉES COLLECTÉES")
        report.append("-" * 80)
        
        # HTTP
        if "http" in self.results["collection"]:
            http = self.results["collection"]["http"]
            report.append(f"\n🌐 HTTP/HTTPS:")
            report.append(f"   Status: {http.get('status_code')}")
            report.append(f"   Taille HTML: {http.get('html_size'):,} bytes")
            report.append(f"   Redirections: {len(http.get('redirects', []))}")
        
        # TLS
        if "tls" in self.results["collection"] and "error" not in self.results["collection"]["tls"]:
            tls = self.results["collection"]["tls"]
            report.append(f"\n🔐 Certificat TLS:")
            report.append(f"   Émetteur: {tls.get('issuer', {}).get('O', 'N/A')}")
            report.append(f"   Expire dans: {tls.get('days_until_expiry')} jours")
            report.append(f"   Algorithme: {tls.get('signature_algorithm')}")
        
        # WHOIS
        if "whois" in self.results["collection"]:
            whois_data = self.results["collection"]["whois"]
            report.append(f"\n📋 WHOIS:")
            report.append(f"   Registrar: {whois_data.get('registrar', 'N/A')}")
            report.append(f"   Âge: {whois_data.get('age_days')} jours")
            report.append(f"   Expire dans: {whois_data.get('days_until_expiry')} jours")
        
        report.append(f"\n{'='*80}\n")
        
        report_text = "\n".join(report)
        print(report_text)
        
        # Sauvegarde
        if output_file is None:
            output_file = f"scan_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Fichier texte
        with open(f"{output_file}.txt", "w", encoding="utf-8") as f:
            f.write(report_text)
        
        # Fichier JSON
        with open(f"{output_file}.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Rapport sauvegardé : {output_file}.txt")
        print(f"✓ Données JSON : {output_file}.json")


def main():
    parser = argparse.ArgumentParser(
        description="Scanner externe de site web - Collecte & Analyse"
    )
    parser.add_argument("url", help="URL du site à analyser")
    parser.add_argument("-o", "--output", help="Nom du fichier de sortie (sans extension)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode verbeux")
    
    args = parser.parse_args()
    
    # Validation de l'URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    try:
        scanner = WebScanner(args.url, verbose=args.verbose)
        scanner.run()
        scanner.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrompu par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erreur : {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
