# ScriptPythonLOG

# analyzer.py
import re
from utils import load_log_file, save_report
from collections import defaultdict

log_path = "logs/access.log"
lines = load_log_file(log_path)

suspicious_ips = defaultdict(int)
denied_access = []
scan_detected = []

for line in lines:
    # Exemple log Apache : 192.168.1.1 - - [01/Jun/2025:10:15:32 +0200] "GET /admin HTTP/1.1" 403 721
    match = re.search(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<datetime>[^\]]+)\] "(?P<method>GET|POST) (?P<url>.*?) HTTP/1.[01]" (?P<status>\d+)', line)
    if match:
        ip = match.group('ip')
        url = match.group('url')
        status = int(match.group('status'))

        if status == 403:
            denied_access.append((ip, url))
            suspicious_ips[ip] += 1

        if "wp-login" in url or "phpmyadmin" in url:
            scan_detected.append((ip, url))
            suspicious_ips[ip] += 1

# Génération du rapport
report_lines = []

report_lines.append(" Analyse de logs : Résumé")
report_lines.append(f"Nombre total de lignes : {len(lines)}")
report_lines.append(f"Nombre d’accès interdits (403) : {len(denied_access)}")
report_lines.append(f"Scans détectés (URLs sensibles) : {len(scan_detected)}")

report_lines.append("\n IPs suspectes (plus de 3 événements)")
for ip, count in suspicious_ips.items():
    if count > 3:
        report_lines.append(f" - {ip} : {count} tentatives")

save_report("report.txt", report_lines)
print(" Rapport généré dans 'report.txt'")
