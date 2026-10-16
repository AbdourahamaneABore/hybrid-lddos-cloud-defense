#!/usr/bin/env python3
"""
collect_traffic_counters.py
---------------------------
Mesure de la réduction du trafic physique et de la santé du service :
1. Paquets et octets reçus par le service (HAProxy Load Balancer)
2. Compteurs des règles DROP OpenFlow (OVS s1 / ONOS)
3. Nombre de connexions uniques
4. Requêtes légitimes abouties (HTTP 200 OK) vs échecs/timeouts
"""

import subprocess
import json
import re
import os
import sys
import time
import requests

ONOS_IP = "127.0.0.1"
ONOS_PORT = 8181
ONOS_USER = "onos"
ONOS_PASS = "rocks"
ONOS_URL = f"http://{ONOS_IP}:{ONOS_PORT}/onos/v1"

def get_ovs_drop_counters():
    """
    Extrait les compteurs de paquets et d'octets rejetés par les règles DROP
    priorité 40000 sur le commutateur Open vSwitch s1.
    """
    try:
        res = subprocess.run(["ovs-ofctl", "dump-flows", "s1"], capture_output=True, text=True, check=True)
        lines = res.stdout.strip().split("\n")
        total_drop_packets = 0
        total_drop_bytes = 0
        blocked_rules_count = 0
        
        for line in lines:
            if "priority=40000" in line and ("drop" in line or "actions=" not in line or "actions=drop" in line):
                blocked_rules_count += 1
                m_pkts = re.search(r'n_packets=(\d+)', line)
                m_bytes = re.search(r'n_bytes=(\d+)', line)
                if m_pkts:
                    total_drop_packets += int(m_pkts.group(1))
                if m_bytes:
                    total_drop_bytes += int(m_bytes.group(1))
                    
        return {
            'rules_count': blocked_rules_count,
            'drop_packets': total_drop_packets,
            'drop_bytes': total_drop_bytes
        }
    except Exception as e:
        # Fallback via API REST ONOS
        try:
            url = f"{ONOS_URL}/flows"
            resp = requests.get(url, auth=(ONOS_USER, ONOS_PASS), timeout=3)
            if resp.status_code == 200:
                flows = resp.json().get("flows", [])
                p_sum = 0
                b_sum = 0
                r_sum = 0
                for f in flows:
                    if f.get("priority") == 40000:
                        r_sum += 1
                        p_sum += f.get("packets", 0)
                        b_sum += f.get("bytes", 0)
                return {'rules_count': r_sum, 'drop_packets': p_sum, 'drop_bytes': b_sum}
        except Exception:
            pass
        return {'rules_count': 0, 'drop_packets': 0, 'drop_bytes': 0, 'error': str(e)}

def test_legitimate_service_health(target_url="http://10.10.0.100", num_tests=20):
    """
    Simule une série de requêtes légitimes client et mesure :
    - Taux de succès HTTP 200
    - Temps de réponse moyen
    - Erreurs de connexion / timeouts
    """
    success_count = 0
    fail_count = 0
    latencies = []
    
    for idx in range(num_tests):
        t0 = time.time()
        try:
            resp = requests.get(target_url, timeout=0.8)
            latency = (time.time() - t0) * 1000.0  # ms
            if resp.status_code == 200:
                success_count += 1
                latencies.append(latency)
            else:
                fail_count += 1
        except Exception:
            fail_count += 1
            if idx == 0:
                fail_count = num_tests
                break
        time.sleep(0.05)
        
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    success_rate = (success_count / num_tests) * 100.0 if num_tests > 0 else 0.0
    return {
        'total_requests': num_tests,
        'success_200': success_count,
        'failures': fail_count,
        'success_rate_pct': success_rate,
        'avg_latency_ms': avg_lat
    }

def get_client_telemetry_qos():
    """
    Tente de charger les métriques de disponibilité réelles depuis les logs
    enregistrés par monitor_http_client.py (h_clt1 / h_clt2 dans Mininet).
    """
    import glob
    candidates = glob.glob("client_qos_*.csv") + glob.glob("client_http_qos*.csv") + glob.glob("Experimentation/**/client_qos_*.csv", recursive=True)
    if not candidates:
        return None
    latest_file = max(candidates, key=os.path.getmtime)
    try:
        import pandas as pd
        df_qos = pd.read_csv(latest_file)
        df_qos.columns = df_qos.columns.str.strip()
        total = len(df_qos)
        if total == 0:
            return None
        success = int(df_qos['Success'].sum()) if 'Success' in df_qos else int((df_qos['HTTP_Code'] == 200).sum())
        lat_col = df_qos['Latency_Ms'] if 'Latency_Ms' in df_qos else None
        avg_lat = float(lat_col[df_qos['Success'] == 1].mean()) if lat_col is not None and success > 0 else 0.0
        return {
            'file': latest_file,
            'total_requests': total,
            'success_200': success,
            'failures': total - success,
            'success_rate_pct': (success / total * 100.0) if total > 0 else 0.0,
            'avg_latency_ms': avg_lat
        }
    except Exception:
        return None

def print_telemetry_report():
    print("="*80)
    print("🔬 AUDIT TÉLÉMÉTRIQUE RÉSEAU : MESURE RIGOUREUSE DE LA RÉDUCTION DU TRAFIC")
    print("="*80)
    
    # 1. Compteurs DROP OpenFlow
    ovs_stats = get_ovs_drop_counters()
    print("1. COMPTEURS DES RÈGLES OPENFLOW DROP (Commutateur s1 / Contrôleur ONOS) :")
    print(f"   • Règles DROP installées (Priorité 40000) : {ovs_stats['rules_count']}")
    print(f"   • Paquets physiques rejetés par le switch : {ovs_stats['drop_packets']:,} paquets")
    print(f"   • Volume physique rejeté au plan de données : {ovs_stats['drop_bytes'] / (1024*1024):.2f} MB ({ovs_stats['drop_bytes']:,} octets)")
    print("-" * 80)
    
    # 2. Test Disponibilité et Requêtes Abouties
    print("2. DISPONIBILITÉ DU SERVICE & REQUÊTES LÉGITIMES ABOUTIES (Client -> Load Balancer) :")
    health = test_legitimate_service_health()
    client_qos = get_client_telemetry_qos()

    if health['success_200'] > 0:
        print(f"   • Requêtes test directes envoyées   : {health['total_requests']}")
        print(f"   • Requêtes HTTP 200 OK réussies     : {health['success_200']} ({health['success_rate_pct']:.1f} %)")
        print(f"   • Requêtes échouées / timeouts      : {health['failures']}")
        print(f"   • Temps de réponse moyen légitime   : {health['avg_latency_ms']:.1f} ms")
    elif client_qos:
        print(f"   • Source de mesure                  : Télémétrie continue Mininet ({client_qos['file']})")
        print(f"   • Requêtes client légitimes émises  : {client_qos['total_requests']}")
        print(f"   • Requêtes HTTP 200 OK réussies     : {client_qos['success_200']} ({client_qos['success_rate_pct']:.1f} %)")
        print(f"   • Requêtes échouées / timeouts      : {client_qos['failures']}")
        print(f"   • Temps de réponse moyen (RTT)      : {client_qos['avg_latency_ms']:.2f} ms")
        print(f"   💡 Note : Le test ponctuel direct depuis l'Hôte a été redirigé vers les mesures internes")
        print(f"      de Mininet (h_clt1 via monitor_http_client.py), car l'IP 10.10.0.100 est isolée sur s1.")
    else:
        print(f"   • Requêtes client envoyées          : {health['total_requests']}")
        print(f"   • Requêtes HTTP 200 OK réussies     : {health['success_200']} ({health['success_rate_pct']:.1f} %)")
        print(f"   • Requêtes échouées / timeouts      : {health['failures']}")
        print(f"   • Temps de réponse moyen légitime   : {health['avg_latency_ms']:.1f} ms")
        print(f"   💡 Note : Si la commande est lancée sur l'Hôte Linux, exécuter dans Mininet via :")
        print(f"      mininet> h_clt1 python3 collect_traffic_counters.py")
    print("="*80 + "\n")

if __name__ == '__main__':
    print_telemetry_report()
