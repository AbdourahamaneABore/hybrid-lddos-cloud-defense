#!/usr/bin/env python3
import requests
import time
import os
import joblib
import numpy as np
import onos_mitigation

# Configuration ONOS
ONOS_IP = "127.0.0.1"
ONOS_PORT = 8181
ONOS_USER = "onos"
ONOS_PASS = "rocks"
ONOS_URL = f"http://{ONOS_IP}:{ONOS_PORT}/onos/v1"

# Infrastructure Cloud Whitelist (Load Balancer & Serveurs backend)
WHITELIST_IPS = {"10.10.0.100", "10.0.0.100"}
for i in range(1, 11):
    ip_id = 200 + i
    WHITELIST_IPS.add(f"10.10.0.{ip_id}")
    WHITELIST_IPS.add(f"10.0.0.{ip_id}")

# Chargement des modèles ML et Encoders
print("[IDS ONOS] Chargement des modeles d'apprentissage et encoders...")
try:
    model_slow = joblib.load('rf_model.joblib')
    le_slow    = joblib.load('label_encoder.joblib')
    model_ddos = joblib.load('ddos_model.joblib')
    try:
        le_ddos = joblib.load('label_encoder_ddos.joblib')
    except Exception:
        le_ddos = le_slow
    print("✓ Modeles ML et Label Encoders charges avec succes.")
except Exception as e:
    print(f"[-] Attention : Erreur lors du chargement des modeles ML : {e}")

# Dictionnaire de suivi de l'état précédent
# Clé : (src_ip, dst_ip, protocol)
# Valeur : { 'packets': p, 'bytes': b, 'last_time': t }
previous_flows = {}

def fetch_onos_flows():
    """
    Récupère les statistiques de flux en interrogeant l'API REST de ONOS.
    """
    url = f"{ONOS_URL}/flows"
    try:
        response = requests.get(url, auth=(ONOS_USER, ONOS_PASS), timeout=3)
        if response.status_code == 200:
            return response.json().get("flows", [])
    except Exception as e:
        print(f"[-] Erreur de communication REST avec ONOS : {e}")
    return []

def analyze_onos_telemetry():
    global previous_flows
    flows = fetch_onos_flows()
    current_time = time.time()
    
    print(f"\n--- [Télémétrie ONOS] Analyse de {len(flows)} regles de flux ---")
    
    for flow in flows:
        # Ignorer les flux inactifs ou incomplets
        if flow.get("state") != "ADDED":
            continue
            
        criteria = flow.get("selector", {}).get("criteria", [])
        src_ip = None
        dst_ip = None
        proto = None
        
        for crit in criteria:
            if crit.get("type") == "IPV4_SRC":
                src_ip = crit.get("ip", "").split("/")[0]
            elif crit.get("type") == "IPV4_DST":
                dst_ip = crit.get("ip", "").split("/")[0]
            elif crit.get("type") == "IP_PROTO":
                proto = int(crit.get("proto", 0))
                
        # Ne traiter que les flux IP identifiables
        if not src_ip or not dst_ip:
            continue
            
        # Ignorer les machines de l'infrastructure whitelistées
        if src_ip in WHITELIST_IPS:
            continue
            
        flow_id = (src_ip, dst_ip, proto)
        
        packets = flow.get("packets", 0)
        bytes_count = flow.get("bytes", 0)
        life_sec = flow.get("life", 0)
        
        if flow_id in previous_flows:
            prev = previous_flows[flow_id]
            time_delta = current_time - prev['last_time']
            
            if time_delta >= 1.0:
                # Calcul des deltas
                pkt_delta = packets - prev['packets']
                byte_delta = bytes_count - prev['bytes']
                
                # Gestion de la réinitialisation des règles sur le switch
                if pkt_delta < 0:
                    pkt_delta = packets
                    byte_delta = bytes_count
                    
                flow_pkts_s = pkt_delta / time_delta
                flow_bytes_s = byte_delta / time_delta
                
                # Interpolation des métriques temporelles (IAT moyen)
                avg_iat_sec = 1.0 / flow_pkts_s if flow_pkts_s > 0 else 0.0
                
                print(f"📡 [Flux] {src_ip} -> {dst_ip} (Proto: {proto}) | Debit: {flow_pkts_s:.1f} Pkts/s | Octets: {flow_bytes_s:.1f} B/s | IAT: {avg_iat_sec:.4f}s")
                
                # Détection Heuristique Volumétrique
                if flow_pkts_s > 1000:
                    print(f"🚨 [ALERT NATIVE ONOS] DDoS Detecte via debits pour {src_ip} -> Application Mitigation SDN !")
                    onos_mitigation.block_ip(src_ip)
                elif avg_iat_sec >= 8.0 and life_sec > 10 and pkt_delta < 150:
                    print(f"🚨 [ALERT NATIVE ONOS] Slow DoS Detecte via temps inter-paquets pour {src_ip} -> Application Mitigation SDN !")
                    onos_mitigation.block_ip(src_ip)
                
        # Enregistrement pour le prochain intervalle
        previous_flows[flow_id] = {
            'packets': packets,
            'bytes': bytes_count,
            'last_time': current_time
        }

if __name__ == "__main__":
    print("[IDS ONOS] Demarrage de la telemetrie native...")
    while True:
        try:
            analyze_onos_telemetry()
            time.sleep(2)
        except KeyboardInterrupt:
            print("\n[IDS ONOS] Arret de la telemetrie.")
            break
        except Exception as e:
            print(f"[-] Erreur dans la boucle principale : {e}")
            time.sleep(2)
