#!/usr/bin/env python3
"""
monitor_http_client.py
----------------------
Mesure continue de la Disponibilité HTTP et de la Latence (QoS)
du point de vue des clients légitimes (ex: h_clt1, h_clt2).

Enregistre dans un fichier CSV :
- Timestamp (Horodatage)
- Client_IP (Adresse IP source)
- Target_URL (URL ciblée)
- HTTP_Code (Code retour HTTP: 200, 503, 504, 0 si timeout)
- Latency_Ms (Temps d'aller-retour en millisecondes)
- Success (1 si 200 OK, 0 si erreur ou timeout)
- Error_Type (None, Timeout, Connection_Refused, etc.)

Usage :
    python3 monitor_http_client.py --target http://10.10.0.100 --output client_http_qos.csv
"""

import sys
import os
import time
import argparse
import random
import socket
from datetime import datetime
import urllib.request
import urllib.error

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def main():
    parser = argparse.ArgumentParser(description="Moniteur continu de Disponibilite et Latence HTTP (QoS)")
    parser.add_argument("--target", type=str, default="http://10.10.0.100", help="URL cible du service Load Balancer")
    parser.add_argument("--output", type=str, default="client_http_qos.csv", help="Fichier CSV de sortie pour la QoS")
    parser.add_argument("--min-sleep", type=float, default=0.5, help="Temps de pause minimal entre requetes (s)")
    parser.add_argument("--max-sleep", type=float, default=2.0, help="Temps de pause maximal entre requetes (s)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout maximal d'une requete en secondes")
    args = parser.parse_args()

    client_ip = get_local_ip()
    print("="*80)
    print("🌐 MONITEUR DE DISPONIBILITÉ ET LATENCE HTTP (CLIENT QOS)")
    print("="*80)
    print(f"• Client IP    : {client_ip}")
    print(f"• Cible        : {args.target}")
    print(f"• Fichier logs : {args.output}")
    print(f"• Timeout      : {args.timeout}s")
    print("="*80 + "\n")

    # Initialisation du fichier CSV si non existant
    if not os.path.exists(args.output):
        with open(args.output, "w") as f:
            f.write("Timestamp,Client_IP,Target_URL,HTTP_Code,Latency_Ms,Success,Error_Type\n")

    total_requests = 0
    success_requests = 0
    latencies = []

    try:
        while True:
            t_now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            t_start = time.time()
            http_code = 0
            success = 0
            error_type = "None"
            latency_ms = 0.0

            try:
                req = urllib.request.Request(
                    args.target, 
                    headers={'User-Agent': 'Mozilla/5.0 (Client-QoS-Monitor)'}
                )
                with urllib.request.urlopen(req, timeout=args.timeout) as resp:
                    t_end = time.time()
                    latency_ms = (t_end - t_start) * 1000.0
                    http_code = resp.getcode()
                    if http_code == 200:
                        success = 1
                    else:
                        error_type = f"HTTP_{http_code}"
            except urllib.error.HTTPError as e:
                t_end = time.time()
                latency_ms = (t_end - t_start) * 1000.0
                http_code = e.code
                error_type = f"HTTP_{e.code}"
            except urllib.error.URLError as e:
                t_end = time.time()
                latency_ms = (t_end - t_start) * 1000.0
                http_code = 0
                if "timed out" in str(e.reason).lower():
                    error_type = "Timeout"
                elif "connection refused" in str(e.reason).lower():
                    error_type = "Conn_Refused"
                else:
                    error_type = "Net_Error"
            except Exception as e:
                t_end = time.time()
                latency_ms = (t_end - t_start) * 1000.0
                http_code = 0
                error_type = "Exception"

            total_requests += 1
            if success == 1:
                success_requests += 1
                latencies.append(latency_ms)

            # Écriture immédiate dans le CSV
            with open(args.output, "a") as f:
                f.write(f"{t_now_str},{client_ip},{args.target},{http_code},{latency_ms:.2f},{success},{error_type}\n")

            # Affichage console
            icon = "✅" if success == 1 else "❌"
            print(f"{icon} [{t_now_str}] {client_ip} -> Code: {http_code:<3} | Latence: {latency_ms:6.1f} ms | Succes: {success} | Erreur: {error_type}")

            # Pause aléatoire pour simuler l'utilisateur humain
            pause_time = random.uniform(args.min_sleep, args.max_sleep)
            time.sleep(pause_time)

    except KeyboardInterrupt:
        print("\n\n" + "="*80)
        print("📊 RÉSUMÉ DE LA SESSION CLIENT (DISPONIBILITÉ & LATENCE) :")
        print("="*80)
        pct = (success_requests / total_requests * 100.0) if total_requests > 0 else 0.0
        avg_lat = (sum(latencies) / len(latencies)) if latencies else 0.0
        max_lat = max(latencies) if latencies else 0.0
        print(f"• Total requêtes envoyées : {total_requests}")
        print(f"• Requêtes HTTP 200 OK    : {success_requests} ({pct:.1f} % de disponibilité)")
        print(f"• Requêtes en échec       : {total_requests - success_requests}")
        print(f"• Latence moyenne         : {avg_lat:.2f} ms")
        print(f"• Latence maximale        : {max_lat:.2f} ms")
        print(f"• Fichier de métriques    : {args.output}")
        print("="*80 + "\n")

if __name__ == '__main__':
    main()
