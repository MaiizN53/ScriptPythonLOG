#!/usr/bin/env python3
# LAB-01: Analyse de logs serveur pour détection d'activités suspectes
# Auteur: [Votre Nom]
# Date: [Date]

import re
from collections import defaultdict
from datetime import datetime
import argparse
import sys


def analyser_logs_apache(fichier_log):
    """Analyse les logs Apache/Nginx pour détecter des activités suspectes."""
    motifs = {
        'bruteforce': r'POST.*/wp-login.php.*200',
        'acces_interdit': r'403',
        'fichiers_sensibles': r'/(etc/passwd|\.env|wp-config\.php)',
        'scanners': r'(nmap|nikto|sqlmap|wpscan)',
        'xss_tentative': r'<script>|%3Cscript%3E',
        'sql_injection': r'(\'|%27).*--|UNION.*SELECT',
        'bots_malveillants': r'(AhrefsBot|SemrushBot|MJ12bot)'
    }

    return analyser_fichier_log(fichier_log, motifs, 'apache')


def analyser_logs_ssh(fichier_log):
    """Analyse les logs SSH pour détecter des attaques par force brute."""
    motifs = {
        'echec_connexion': r'Failed password for',
        'connexion_reussie': r'Accepted password for',
        'utilisateurs_invalides': r'Invalid user (\w+)',
        'root_login': r'pam_unix\(sshd:session\).*session opened for user root',
        'port_scan': r'Did not receive identification string from',
        'bruteforce': r'Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)'
    }

    return analyser_fichier_log(fichier_log, motifs, 'ssh')


def analyser_fichier_log(fichier_log, motifs, type_log):
    """Fonction générique pour analyser les fichiers de logs."""
    resultats = defaultdict(lambda: defaultdict(int))
    adresses_ip = defaultdict(lambda: defaultdict(int))

    try:
        with open(fichier_log, 'r', encoding='utf-8', errors='ignore') as f:
            for ligne in f:
                for motif, regex in motifs.items():
                    if re.search(regex, ligne, re.IGNORECASE):
                        resultats[motif]['total'] += 1

                        # Extraire l'IP si possible
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', ligne)
                        if ip_match:
                            ip = ip_match.group(1)
                            adresses_ip[motif][ip] += 1

                        # Pour SSH, extraire les noms d'utilisateurs pour les attaques brute-force
                        if type_log == 'ssh' and motif == 'bruteforce':
                            user_match = re.search(r'Failed password for (\w+)', ligne)
                            if user_match:
                                user = user_match.group(1)
                                resultats['utilisateurs_cibles'][user] += 1
    except FileNotFoundError:
        print(f"Erreur: Fichier {fichier_log} non trouvé.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier: {e}", file=sys.stderr)
        sys.exit(1)

    return resultats, adresses_ip


def generer_rapport(resultats, adresses_ip, type_log):
    """Génère un rapport d'analyse des logs."""
    rapport = []
    date_analyse = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rapport.append(f"Rapport d'analyse de logs - {date_analyse}")
    rapport.append(f"Type de logs analysés: {type_log.upper()}")
    rapport.append("=" * 50)

    if not resultats:
        rapport.append("Aucune activité suspecte détectée.")
        return "\n".join(rapport)

    # Activités suspectes détectées
    rapport.append("\nActivités suspectes détectées:")
    for motif, data in resultats.items():
        if motif == 'utilisateurs_cibles':
            continue
        rapport.append(f"- {motif.replace('_', ' ').title()}: {data['total']} occurrences")

    # Adresses IP suspectes
    rapport.append("\nAdresses IP suspectes:")
    for motif, ips in adresses_ip.items():
        if not ips:
            continue
        rapport.append(f"\n{motif.replace('_', ' ').title()}:")
        for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]:  # Top 5
            rapport.append(f"  {ip}: {count} tentatives")

    # Pour SSH: Utilisateurs ciblés
    if type_log == 'ssh' and 'utilisateurs_cibles' in resultats:
        rapport.append("\nUtilisateurs ciblés (brute-force):")
        for user, count in sorted(resultats['utilisateurs_cibles'].items(), key=lambda x: x[1], reverse=True)[:5]:
            rapport.append(f"- {user}: {count} tentatives")

    # Recommandations
    rapport.append("\nRecommandations:")
    if type_log == 'ssh':
        if resultats.get('bruteforce', {}).get('total', 0) > 10:
            rapport.append("- Envisagez de mettre en place fail2ban ou de limiter les tentatives de connexion")
        if resultats.get('root_login', {}).get('total', 0) > 0:
            rapport.append("- Désactivez les connexions SSH directes en tant que root")
    elif type_log == 'apache':
        if resultats.get('bruteforce', {}).get('total', 0) > 5:
            rapport.append("- Protégez votre page de login (limite de taux, CAPTCHA)")
        if resultats.get('acces_interdit', {}).get('total', 0) > 20:
            rapport.append("- Vérifiez les permissions de vos fichiers et répertoires")

    rapport.append("\nFin du rapport")
    return "\n".join(rapport)


def main():
    parser = argparse.ArgumentParser(description="Analyseur de logs pour détection d'activités suspectes")
    parser.add_argument('fichier', help="Chemin vers le fichier de logs à analyser")
    parser.add_argument('-t', '--type', choices=['apache', 'ssh'], required=True,
                        help="Type de logs à analyser (apache ou ssh)")
    parser.add_argument('-o', '--output', help="Fichier de sortie pour le rapport")

    args = parser.parse_args()

    if args.type == 'apache':
        resultats, adresses_ip = analyser_logs_apache(args.fichier)
    else:
        resultats, adresses_ip = analyser_logs_ssh(args.fichier)

    rapport = generer_rapport(resultats, adresses_ip, args.type)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(rapport)
            print(f"Rapport généré avec succès dans {args.output}")
        except IOError as e:
            print(f"Erreur lors de l'écriture du rapport: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(rapport)


if __name__ == "__main__":
    main()