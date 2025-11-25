# Exemples de rapports générés

## Exemple 1 : Site sûr (Risque LOW)

```
================================================================================
RAPPORT D'ANALYSE DE MALWARE
================================================================================

📅 Date: 2025-11-25T14:30:00
🌐 URL analysée: https://example.com

🟢 NIVEAU DE RISQUE: LOW

================================================================================

🚨 MENACES DÉTECTÉES: 1
--------------------------------------------------------------------------------

1. 🟡 [MEDIUM] missing_security_header
   Description: En-tête de sécurité manquant: X-Frame-Options

🔒 EN-TÊTES DE SÉCURITÉ
--------------------------------------------------------------------------------
✓ Content-Security-Policy: default-src 'self'
✗ X-Frame-Options: ABSENT
✓ X-Content-Type-Options: nosniff
✓ Strict-Transport-Security: max-age=31536000
✓ X-XSS-Protection: 1; mode=block

📜 SCRIPTS ANALYSÉS: 3
--------------------------------------------------------------------------------
✓ Aucun script suspect détecté

🔗 LIENS EXTERNES: 5
--------------------------------------------------------------------------------
Domaines uniques: 2
   - example.org
   - w3.org

💡 RECOMMANDATIONS
--------------------------------------------------------------------------------
✓ Le site semble relativement sûr
   - Restez néanmoins vigilant

================================================================================
```

## Exemple 2 : Site suspect (Risque HIGH)

```
================================================================================
RAPPORT D'ANALYSE DE MALWARE
================================================================================

📅 Date: 2025-11-25T14:35:00
🌐 URL analysée: https://suspicious-example.tk

🟠 NIVEAU DE RISQUE: HIGH

================================================================================

🚨 MENACES DÉTECTÉES: 6
--------------------------------------------------------------------------------

1. 🔴 [HIGH] obfuscated_code
   Description: Code JavaScript fortement obfusqué détecté

2. 🔴 [HIGH] suspicious_external_script
   Description: Script provenant d'un domaine suspect: https://malware.tk/evil.js

3. 🔴 [HIGH] hidden_iframe
   Description: Iframe invisible détecté (possible malware ou tracking)

4. 🟡 [MEDIUM] missing_security_header
   Description: En-tête de sécurité manquant: Content-Security-Policy

5. 🟡 [MEDIUM] suspicious_iframe
   Description: Iframe pointant vers un domaine suspect: ads-tracker.ml

6. 🟡 [MEDIUM] suspicious_link
   Description: Lien vers un domaine suspect: http://bit.ly/xxxxx

🔒 EN-TÊTES DE SÉCURITÉ
--------------------------------------------------------------------------------
✗ Content-Security-Policy: ABSENT
✗ X-Frame-Options: ABSENT
✗ X-Content-Type-Options: ABSENT
✗ Strict-Transport-Security: ABSENT
✗ X-XSS-Protection: ABSENT

📜 SCRIPTS ANALYSÉS: 8
--------------------------------------------------------------------------------
⚠️  Scripts suspects: 3
   - https://malware.tk/evil.js
   - inline script
   - https://crypto-miner.ga/mine.js

⚠️  CODE OBFUSQUÉ DÉTECTÉ: 2
--------------------------------------------------------------------------------
   Hash: a3f5d8c9e1b2a4c6d8e9f0a1b2c3d4e5
   Extrait: var _0x1a2b=['eval','fromCharCode','\x64\x6f\x63\x75\x6d\x65\x6e\x74'...
   
   Hash: b4e6d9c0f2b3a5c7d9e0f1a2b3c4d5e6
   Extrait: function _0xabc123(){var _0x1=String.fromCharCode;return eval(_0x1...

🖼️  IFRAMES: 4
--------------------------------------------------------------------------------
⚠️  Iframes suspects: 2

🔗 LIENS EXTERNES: 15
--------------------------------------------------------------------------------
Domaines uniques: 8
   - bit.ly (raccourcisseur suspect)
   - tinyurl.com (raccourcisseur suspect)
   - ads-tracker.ml (TLD suspect)
   - crypto-miner.ga (TLD suspect)
   - malware.tk (TLD suspect)
   - analytics-fake.cf (TLD suspect)

🔍 PATTERNS SUSPECTS DÉTECTÉS: 12
--------------------------------------------------------------------------------
   - Pattern: eval\s*\( (5 occurrences)
   - Pattern: fromCharCode (8 occurrences)
   - Pattern: document\.write (3 occurrences)
   - Pattern: atob\s*\( (2 occurrences)
   - Pattern: cryptocurrency|bitcoin|ethereum|mining|cryptojacking (4 occurrences)

💡 RECOMMANDATIONS
--------------------------------------------------------------------------------
⚠️  ATTENTION: Ce site présente des risques élevés!
   - Ne pas saisir d'informations personnelles
   - Éviter de télécharger des fichiers
   - Vérifier l'authenticité du site

================================================================================
```

## Exemple 3 : Site critique (Risque CRITICAL)

```
================================================================================
RAPPORT D'ANALYSE DE MALWARE
================================================================================

📅 Date: 2025-11-25T14:40:00
🌐 URL analysée: https://phishing-example.ml

🔴 NIVEAU DE RISQUE: CRITICAL

================================================================================

🚨 MENACES DÉTECTÉES: 12
--------------------------------------------------------------------------------

1. 🔴 [HIGH] obfuscated_code
   Description: Code JavaScript fortement obfusqué détecté

2. 🔴 [HIGH] obfuscated_code
   Description: Code JavaScript fortement obfusqué détecté

3. 🔴 [HIGH] obfuscated_code
   Description: Code JavaScript fortement obfusqué détecté

4. 🔴 [HIGH] suspicious_external_script
   Description: Script provenant d'un domaine suspect: https://malicious-cdn.tk/stealer.js

5. 🔴 [HIGH] suspicious_external_script
   Description: Script provenant d'un domaine suspect: https://evil-tracker.ga/track.js

6. 🔴 [HIGH] hidden_iframe
   Description: Iframe invisible détecté (possible malware ou tracking)

7. 🔴 [HIGH] hidden_iframe
   Description: Iframe invisible détecté (possible malware ou tracking)

8. 🟡 [MEDIUM] missing_security_header
   Description: En-tête de sécurité manquant: Content-Security-Policy

9. 🟡 [MEDIUM] missing_security_header
   Description: En-tête de sécurité manquant: X-Frame-Options

10. 🟡 [MEDIUM] suspicious_iframe
    Description: Iframe pointant vers un domaine suspect: phishing-login.tk

11. 🟡 [MEDIUM] suspicious_link
    Description: Lien vers un domaine suspect: http://fake-bank-login.ml

12. 🟡 [MEDIUM] suspicious_link
    Description: Lien vers un domaine suspect: http://bit.ly/fakelogin

🔒 EN-TÊTES DE SÉCURITÉ
--------------------------------------------------------------------------------
✗ Content-Security-Policy: ABSENT
✗ X-Frame-Options: ABSENT
✗ X-Content-Type-Options: ABSENT
✗ Strict-Transport-Security: ABSENT
✗ X-XSS-Protection: ABSENT

📜 SCRIPTS ANALYSÉS: 15
--------------------------------------------------------------------------------
⚠️  Scripts suspects: 8
   - https://malicious-cdn.tk/stealer.js
   - https://evil-tracker.ga/track.js
   - https://crypto-miner.cf/mine.js
   - inline script (obfusqué)
   - inline script (obfusqué)
   - inline script (obfusqué)

⚠️  CODE OBFUSQUÉ DÉTECTÉ: 5
--------------------------------------------------------------------------------
   [Multiple blocs de code hautement obfusqué détectés]

🖼️  IFRAMES: 6
--------------------------------------------------------------------------------
⚠️  Iframes suspects: 4

🔗 LIENS EXTERNES: 30+
--------------------------------------------------------------------------------
Domaines uniques: 15
   [Nombreux domaines suspects détectés]

🔍 PATTERNS SUSPECTS DÉTECTÉS: 25+
--------------------------------------------------------------------------------
   - Pattern: eval\s*\( (15 occurrences)
   - Pattern: fromCharCode (20 occurrences)
   - Pattern: document\.write (8 occurrences)
   - Pattern: atob\s*\( (10 occurrences)
   - Pattern: window\.location\s*= (5 occurrences)
   - Pattern: \.innerHTML\s*= (12 occurrences)
   - Pattern: cryptocurrency|bitcoin|ethereum|mining|cryptojacking (7 occurrences)

💡 RECOMMANDATIONS
--------------------------------------------------------------------------------
⚠️  ATTENTION: Ce site présente des risques élevés!
   - Ne pas saisir d'informations personnelles
   - Éviter de télécharger des fichiers
   - Vérifier l'authenticité du site
   - QUITTER IMMÉDIATEMENT CE SITE
   - Signaler ce site aux autorités compétentes

================================================================================
```

## Interprétation des rapports

### Indicateurs de danger

#### 🟢 Faible risque (LOW)
- Peu ou pas de menaces détectées
- En-têtes de sécurité présents
- Aucun code obfusqué
- Scripts provenant de domaines connus

#### 🟡 Risque modéré (MEDIUM)
- Quelques en-têtes de sécurité manquants
- Présence de liens externes suspects
- Scripts externes non vérifiables
- Iframes externes

#### 🟠 Risque élevé (HIGH)
- Code JavaScript obfusqué
- Scripts provenant de domaines suspects
- Iframes cachés
- Patterns malveillants détectés

#### 🔴 Risque critique (CRITICAL)
- Multiple code obfusqué
- Nombreux scripts malveillants
- Patterns de phishing
- Tentatives de vol de données
- Cryptojacking

### Actions recommandées selon le niveau

| Niveau | Action |
|--------|--------|
| LOW | Utilisation normale, rester vigilant |
| MEDIUM | Vérifier la légitimité du site, éviter de saisir des données sensibles |
| HIGH | Ne pas utiliser le site, ne rien télécharger, quitter rapidement |
| CRITICAL | Quitter immédiatement, signaler le site, scanner votre ordinateur |
