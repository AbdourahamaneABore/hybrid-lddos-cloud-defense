#!/usr/bin/env python3
import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
import time
import os
import argparse
from datetime import datetime
import psutil

# ==========================================
# 0. CONFIGURATION DES ARGUMENTS (CLI)
# ==========================================
parser = argparse.ArgumentParser(description="Moteur IDS/IPS Hybride Cloud & SDN - Mode Production")
parser.add_argument("--mitigation", type=str, choices=["on", "off"], default="on")
parser.add_argument("--detection-mode", "--mode", type=str, choices=["all", "hybrid", "rf", "heuristique", "heuristic"], default="all", help="Mode de detection actif : rf (Random Forest seul), heuristique (seuils seuls), hybrid (RF ET heuristique simultanement), all (RF OU heuristique avec synergie)")
parser.add_argument("--subnet", type=str, default="10.")
parser.add_argument("--timer", type=float, default=60.0, help="Timer de deblocage des IPs en secondes")
parser.add_argument("--interface", type=str, default="s1-eth1", help="Port du Load Balancer (ex: s1-eth1 ou any)")
parser.add_argument("--log-file", type=str, default="ids_historical_logs.csv", help="Fichier de logs de sortie (par defaut: ids_historical_logs.csv)")
args = parser.parse_args()

# Infrastructure Cloud Whitelist (Load Balancer h_lb & Serveurs applicatifs h_srv1 à h_srv10)
# Seules les adresses de l'infrastructure Cloud (10.10.0.x) sont dans la whitelist.
# Les adresses 10.0.0.x sont des hôtes attaquants (h_atk1 à h_atk100) et NE DOIVENT PAS être whitelistées.
WHITELIST_IPS = {"10.10.0.100"}
for i in range(1, 11):
   ip_id = 200 + i
   WHITELIST_IPS.add(f"10.10.0.{ip_id}")

DDOS_PKT_RATE_THRESHOLD = 1000    
DDOS_MIN_PACKETS = 100            
SLOW_IAT_THRESHOLD_US = 8000000   
SLOW_MIN_DURATION = 10.0          
FLOW_TIMEOUT = 60.0               

BLOCKED_IPS = set()               
BLOCKED_IPS_TIMERS = {}
last_cooldown_check = 0.0
last_heartbeat_check = 0.0
total_captured_packets = 0
WRITTEN_ALERTS = set()  
active_flows = {}

if args.log_file is not None:
    LOG_FILE = args.log_file
else:
    LOG_FILE = "ids_historical_logs.csv"

# Suivi des ressources par processus
CURRENT_PROC = psutil.Process(os.getpid())
HAPROXY_PROC = None

def get_process_metrics():
    global HAPROXY_PROC
    try:
        ids_cpu = CURRENT_PROC.cpu_percent()
        ids_ram_mb = CURRENT_PROC.memory_info().rss / (1024 * 1024)
    except Exception:
        ids_cpu, ids_ram_mb = 0.0, 0.0

    lb_cpu, lb_ram_mb = 0.0, 0.0
    try:
        if HAPROXY_PROC is None or not HAPROXY_PROC.is_running():
            for p in psutil.process_iter(['name', 'cmdline']):
                name = (p.info.get('name') or '').lower()
                cmd = " ".join(p.info.get('cmdline') or []).lower()
                if 'haproxy' in name or 'haproxy' in cmd:
                    HAPROXY_PROC = p
                    break
        if HAPROXY_PROC and HAPROXY_PROC.is_running():
            lb_cpu = HAPROXY_PROC.cpu_percent()
            lb_ram_mb = HAPROXY_PROC.memory_info().rss / (1024 * 1024)
    except Exception:
        pass

    return ids_cpu, ids_ram_mb, lb_cpu, lb_ram_mb

print(f"[IDS Cloud] Enregistrement des logs dans : {LOG_FILE}")
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("Timestamp,Attacker_IP,Protocol,Duration_Sec,Packets_Count,Pkts_Per_Sec,Max_IAT_Us,Verdict,Detection_Mechanism,Mitigation_Status,System_CPU_Percent,System_RAM_Percent,Disk_Write_MB,IDS_CPU_Percent,IDS_RAM_MB,LB_CPU_Percent,LB_RAM_MB\n")

# ==========================================
# 1. CHARGEMENT DES MODÈLES D'APPRENTISSAGE
# ==========================================
print("[IDS Cloud] Initialisation du moteur avec normalisation de flux...")
try:
    model_slow = joblib.load('rf_model.joblib')
    le_slow    = joblib.load('label_encoder.joblib')
    model_ddos = joblib.load('ddos_model.joblib')
    try:
         le_ddos = joblib.load('label_encoder_ddos.joblib')
    except:
         le_ddos = le_slow
    print("✓ Modeles Random Forest charges avec succes.")
except Exception as e:
    print(f"[!] Erreur de chargement : {e}")
    exit(1)

slow_features_count = model_slow.n_features_in_
ddos_features_count = model_ddos.n_features_in_

def clean_expired_flows(current_time):
    expired_ids = [fid for fid, flow in list(active_flows.items()) if (current_time - flow['last_time']) > FLOW_TIMEOUT]
    for fid in expired_ids:
        del active_flows[fid]

# ==========================================
# 2. ENGIN DE CAPTURE ET D'INFERENCE
# ==========================================
def process_packet(pkt):
    global last_cooldown_check, last_heartbeat_check, total_captured_packets, BLOCKED_IPS, BLOCKED_IPS_TIMERS
    current_time = time.time()
    
    # Cooldown de déblocage automatique
    if current_time - last_cooldown_check >= 1.0:
        last_cooldown_check = current_time
        expired_ips = [ip for ip, block_time in list(BLOCKED_IPS_TIMERS.items()) if current_time - block_time >= args.timer]
        for ip in expired_ips:
            try:
                import onos_mitigation
                onos_mitigation.unblock_ip(ip)
            except Exception as e:
                print(f"Erreur lors du deblocage de {ip} : {e}")
            BLOCKED_IPS.discard(ip)
            BLOCKED_IPS_TIMERS.pop(ip, None)
            print(f"🔓 [IDS Cooldown] IP {ip} debloquee automatiquement apres 60 secondes.")

    # Heartbeat de diagnostic d'écoute
    if current_time - last_heartbeat_check >= 10.0:
        last_heartbeat_check = current_time
        print(f"🔍 [IDS Heartbeat] Paquets capturés: {total_captured_packets} | Flux actifs: {len(active_flows)} | IP bloquées: {len(BLOCKED_IPS)}")
        if total_captured_packets == 0:
            print(f"⚠️  [IDS Diagnostic] Aucun paquet vu sur l'interface '{args.interface}'. Assurez-vous que Mininet génère du trafic ou exécutez 'sudo ./setup_span.sh enable'.")

    # Nettoyage régulier des flux expirés
    if np.random.randint(0, 100) == 42:
        clean_expired_flows(current_time)

    if pkt.haslayer(IP):
        total_captured_packets += 1
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        
        # Support multi-sous-réseaux pour MassifIDSTopo (10.0.0.x attaquants, 10.10.0.x cloud, 192.168.2.x clients)
        valid_subnets = (args.subnet, "10.0.0.", "10.10.0.", "192.168.2.", "10.")
        if not (any(ip_src.startswith(p) for p in valid_subnets) and any(ip_dst.startswith(p) for p in valid_subnets)):
            return 

        # Ignorer uniquement le trafic interne entre serveurs/LB whitelistés
        if ip_src in WHITELIST_IPS and ip_dst in WHITELIST_IPS:
            return

        pkt_len = len(pkt)
        protocol = float(pkt[IP].proto)
        sport, dport, flags, payload_len, win_size, tcp_hdr_len = 0, 0, 0, 0, 0, 20

        if pkt.haslayer(TCP):
            sport, dport, flags = pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags
            win_size = pkt[TCP].window
            payload_len = len(pkt[TCP].payload)
            tcp_hdr_len = (pkt[TCP].dataofs * 4) if pkt[TCP].dataofs is not None else 20
        elif pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            payload_len = len(pkt[UDP].payload)
        else:
            return

        # Identification pivot de la machine externe
        real_attacker_ip = ip_dst if ip_src in WHITELIST_IPS else ip_src
        if real_attacker_ip in BLOCKED_IPS:
            return

        # Signature de flux à 5 attributs
        if ip_src in WHITELIST_IPS:
            flow_id = (ip_dst, dport, ip_src, sport, protocol)
            direction = 'bwd'
        else:
            flow_id = (ip_src, sport, ip_dst, dport, protocol)
            direction = 'fwd'

        if flow_id not in active_flows:
            active_flows[flow_id] = {
                'attacker_ip': real_attacker_ip, 'start_time': current_time, 'last_time': current_time,
                'fwd_times': [current_time] if direction == 'fwd' else [],
                'bwd_times': [current_time] if direction == 'bwd' else [],
                'fwd_packet_count': 1 if direction == 'fwd' else 0, 'bwd_packet_count': 1 if direction == 'bwd' else 0,
                'fwd_lengths': [pkt_len] if direction == 'fwd' else [], 'bwd_lengths': [pkt_len] if direction == 'bwd' else [],
                'all_lengths': [pkt_len], 'fwd_payload_lengths': [payload_len] if direction == 'fwd' else [],
                'bwd_payload_lengths': [payload_len] if direction == 'bwd' else [], 'all_payload_lengths': [payload_len], 'iats': [0.0],
                'init_fwd_win_byts': win_size if direction == 'fwd' else 0, 'init_bwd_win_byts': win_size if direction == 'bwd' else 0,
                'packet_count_since_last_pred': 1, 'fwd_seg_size_min': tcp_hdr_len,
                'fwd_header_len': tcp_hdr_len if direction == 'fwd' else 0,
                'bwd_header_len': tcp_hdr_len if direction == 'bwd' else 0,
                'handshake_completed': False,
                'fin_count': 1 if flags & 0x01 else 0, 'syn_count': 1 if flags & 0x02 else 0, 'rst_count': 1 if flags & 0x04 else 0
            }
            return

        flow = active_flows[flow_id]
        flow['packet_count_since_last_pred'] += 1
        flow['all_lengths'].append(pkt_len)
        flow['all_payload_lengths'].append(payload_len)
        
        iat = (current_time - flow['last_time']) * 1000000
        flow['iats'].append(iat)

        if direction == 'fwd': 
            if flow.get('init_fwd_win_byts', 0) == 0 and win_size > 0:
                flow['init_fwd_win_byts'] = win_size
            flow['fwd_packet_count'] += 1; flow['fwd_lengths'].append(pkt_len); flow['fwd_payload_lengths'].append(payload_len)
            flow['fwd_header_len'] = flow.get('fwd_header_len', 0) + tcp_hdr_len
            flow['fwd_seg_size_min'] = min(flow.get('fwd_seg_size_min', tcp_hdr_len), tcp_hdr_len)
            if 'fwd_times' not in flow: flow['fwd_times'] = []
            flow['fwd_times'].append(current_time)
            if (flags & 0x10) and not (flags & 0x02):
                flow['handshake_completed'] = True
        else: 
            if flow.get('init_bwd_win_byts', 0) == 0 and win_size > 0:
                flow['init_bwd_win_byts'] = win_size
            flow['bwd_packet_count'] += 1; flow['bwd_lengths'].append(pkt_len); flow['bwd_payload_lengths'].append(payload_len)
            flow['bwd_header_len'] = flow.get('bwd_header_len', 0) + tcp_hdr_len
            if 'bwd_times' not in flow: flow['bwd_times'] = []
            flow['bwd_times'].append(current_time)

        if flags & 0x01: flow['fin_count'] += 1
        if flags & 0x02: flow['syn_count'] += 1
        if flags & 0x04: flow['rst_count'] += 1
        flow['last_time'] = current_time

        # ==========================================
        # 3. CRITÈRE D'ÉVALUATION ET INFÉRENCE
        # ==========================================
        duration_sec = current_time - flow['start_time']
        is_closing = (flags & 0x01) or (flags & 0x04)

        # Abaissement du verrou à >= 3 paquets ou durée >= 1.0s pour réactivité immédiate
        if flow['packet_count_since_last_pred'] >= 3 or iat > 1000000 or is_closing or (duration_sec >= 1.0 and flow['packet_count_since_last_pred'] > 0):
            flow['packet_count_since_last_pred'] = 0
            total_packets = flow['fwd_packet_count'] + flow['bwd_packet_count']
            
            safe_duration_sec = max(duration_sec, 0.00001)
            flow_pkts_s = total_packets / safe_duration_sec
            flow_bytes_s = sum(flow['all_lengths']) / safe_duration_sec
            iat_max_val = max(flow['iats']) if flow['iats'] else 0
            duration_val = duration_sec * 1000000
            fwd_pkts_s = flow['fwd_packet_count'] / safe_duration_sec
            bwd_pkts_s = flow['bwd_packet_count'] / safe_duration_sec

            lbl_slow, lbl_ddos = "Benign", "Benign"

            # Inférence Modèle 1 : DoS Lent
            try:
                mapping = {
                    'Dst Port': dport, 'Bwd Pkts/s': bwd_pkts_s, 'Flow Pkts/s': flow_pkts_s,
                    'Fwd Seg Size Min': flow['fwd_seg_size_min'], 'Fwd Pkts/s': fwd_pkts_s, 'Flow IAT Max': iat_max_val,
                    'Flow IAT Mean': np.mean(flow['iats']), 'Init Fwd Win Byts': flow['init_fwd_win_byts'], 'Flow Duration': duration_val,
                    'Flow Byts/s': flow_bytes_s
                }
                df_slow = pd.DataFrame([mapping]).reindex(columns=model_slow.feature_names_in_, fill_value=0)
                pred_s = model_slow.predict(df_slow)
                lbl_slow = str(le_slow.inverse_transform([int(pred_s[0])])[0]).strip()
            except: pass

            # Inférence Modèle 2 : Volumétrique CIC-IDS2019
            try:
                fwd_len_max = max(flow['fwd_lengths']) if flow['fwd_lengths'] else 0
                fwd_len_min = min(flow['fwd_lengths']) if flow['fwd_lengths'] else 0
                fwd_len_mean = np.mean(flow['fwd_lengths']) if flow['fwd_lengths'] else 0
                fwd_len_std = np.std(flow['fwd_lengths']) if flow['fwd_lengths'] else 0
                
                bwd_len_max = max(flow['bwd_lengths']) if flow['bwd_lengths'] else 0
                bwd_len_min = min(flow['bwd_lengths']) if flow['bwd_lengths'] else 0
                bwd_len_mean = np.mean(flow['bwd_lengths']) if flow['bwd_lengths'] else 0
                bwd_len_std = np.std(flow['bwd_lengths']) if flow['bwd_lengths'] else 0

                fwd_header_len_scaled = flow.get('fwd_header_len', 0) / flow['fwd_packet_count'] if flow['fwd_packet_count'] > 0 else 0
                bwd_header_len_scaled = flow.get('bwd_header_len', 0) / flow['bwd_packet_count'] if flow['bwd_packet_count'] > 0 else 0

                fwd_iats = np.diff(flow.get('fwd_times', [])) * 1000000 if len(flow.get('fwd_times', [])) > 1 else []
                bwd_iats = np.diff(flow.get('bwd_times', [])) * 1000000 if len(flow.get('bwd_times', [])) > 1 else []

                fwd_iat_total = sum(fwd_iats) if len(fwd_iats) > 0 else 0
                fwd_iat_mean = np.mean(fwd_iats) if len(fwd_iats) > 0 else 0
                fwd_iat_std = np.std(fwd_iats) if len(fwd_iats) > 0 else 0
                fwd_iat_max = max(fwd_iats) if len(fwd_iats) > 0 else 0
                fwd_iat_min = min(fwd_iats) if len(fwd_iats) > 0 else 0

                bwd_iat_total = sum(bwd_iats) if len(bwd_iats) > 0 else 0
                bwd_iat_mean = np.mean(bwd_iats) if len(bwd_iats) > 0 else 0
                bwd_iat_std = np.std(bwd_iats) if len(bwd_iats) > 0 else 0
                bwd_iat_max = max(bwd_iats) if len(bwd_iats) > 0 else 0
                bwd_iat_min = min(bwd_iats) if len(bwd_iats) > 0 else 0

                feat_dict_ddos = {
                    'Protocol': protocol, 'Flow Duration': duration_val, 'Total Fwd Packets': flow['fwd_packet_count'], 'Total Backward Packets': flow['bwd_packet_count'],
                    'Fwd Packets Length Total': sum(flow['fwd_lengths']), 'Bwd Packets Length Total': sum(flow['bwd_lengths']),
                    'Fwd Packet Length Max': fwd_len_max, 'Fwd Packet Length Min': fwd_len_min, 'Fwd Packet Length Mean': fwd_len_mean, 'Fwd Packet Length Std': fwd_len_std,
                    'Bwd Packet Length Max': bwd_len_max, 'Bwd Packet Length Min': bwd_len_min, 'Bwd Packet Length Mean': bwd_len_mean, 'Bwd Packet Length Std': bwd_len_std,
                    'Flow Bytes/s': flow_bytes_s, 'Flow Packets/s': flow_pkts_s, 'Flow IAT Mean': np.mean(flow['iats']) if flow['iats'] else 0, 'Flow IAT Std': np.std(flow['iats']) if flow['iats'] else 0, 'Flow IAT Max': iat_max_val, 'Flow IAT Min': min(flow['iats']) if flow['iats'] else 0,
                    'Fwd IAT Total': fwd_iat_total, 'Fwd IAT Mean': fwd_iat_mean, 'Fwd IAT Std': fwd_iat_std, 'Fwd IAT Max': fwd_iat_max, 'Fwd IAT Min': fwd_iat_min,
                    'Bwd IAT Total': bwd_iat_total, 'Bwd IAT Mean': bwd_iat_mean, 'Bwd IAT Std': bwd_iat_std, 'Bwd IAT Max': bwd_iat_max, 'Bwd IAT Min': bwd_iat_min,
                    'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, 'Fwd URG Flags': 0, 'Bwd URG Flags': 0, 
                    'Fwd Header Length': fwd_header_len_scaled, 
                    'Bwd Header Length': bwd_header_len_scaled, 
                    'Fwd Packets/s': fwd_pkts_s, 'Bwd Packets/s': bwd_pkts_s,
                    'Packet Length Min': min(flow['all_lengths']) if flow['all_lengths'] else 0, 'Packet Length Max': max(flow['all_lengths']) if flow['all_lengths'] else 0, 'Packet Length Mean': np.mean(flow['all_lengths']) if flow['all_lengths'] else 0, 'Packet Length Std': np.std(flow['all_lengths']) if flow['all_lengths'] else 0, 'Packet Length Variance': np.var(flow['all_lengths']) if flow['all_lengths'] else 0,
                    'FIN Flag Count': flow['fin_count'], 'SYN Flag Count': flow['syn_count'], 'RST Flag Count': flow['rst_count'], 'PSH Flag Count': 0, 'ACK Flag Count': 1, 'URG Flag Count': 0, 'CWE Flag Count': 0, 'ECE Flag Count': 0,
                    'Down/Up Ratio': (flow['bwd_packet_count'] / flow['fwd_packet_count']) if flow['fwd_packet_count'] > 0 else 0, 'Avg Packet Size': np.mean(flow['all_lengths']) if flow['all_lengths'] else 0, 'Avg Fwd Segment Size': fwd_len_mean, 'Avg Bwd Segment Size': bwd_len_mean,
                    'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0, 'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0,
                    'Subflow Fwd Packets': flow['fwd_packet_count'], 'Subflow Fwd Bytes': sum(flow['fwd_lengths']), 'Subflow Bwd Packets': flow['bwd_packet_count'], 'Subflow Bwd Bytes': sum(flow['bwd_lengths']),
                    'Init Fwd Win Bytes': flow['init_fwd_win_byts'], 
                    'Init Bwd Win Bytes': flow['init_bwd_win_byts'] if flow.get('handshake_completed', False) else 0, 
                    'Fwd Act Data Packets': flow['fwd_packet_count'], 'Fwd Seg Size Min': flow['fwd_seg_size_min'],
                    'Active Mean': 0, 'Active Std': 0, 'Active Max': 0, 'Active Min': 0, 'Idle Mean': 0, 'Idle Std': 0, 'Idle Max': 0, 'Idle Min': 0
                }
                df_ddos = pd.DataFrame([feat_dict_ddos]).reindex(columns=model_ddos.feature_names_in_, fill_value=0)
                pred_d = model_ddos.predict(df_ddos)
                try:
                    lbl_ddos = str(le_ddos.inverse_transform([int(pred_d[0])])[0]).strip()
                except Exception:
                    lbl_ddos = "DDoS" if pred_d[0] != 0 else "Benign"
            except Exception as e:
                pass

            # Corrélation du Système Expert
            ml_ddos_detected = (lbl_ddos.upper() != "BENIGN")

            # Signature temporelle indispensable pour un DoS Lent (SlowHTTPTest / Slowloris) :
            # Une attaque lente s'étire intentionnellement dans le temps (rétention des sockets) avec des délais (IAT > 1.5s ou durée >= 2s).
            # Une transaction HTTP normale et rapide (comme curl en quelques millisecondes) est un trafic sain légitime.
            is_slow_temporal_signature = (duration_sec >= 2.0 or iat_max_val >= 1500000.0)
            ml_slow_detected = (lbl_slow.upper() != "BENIGN") and is_slow_temporal_signature
            ml_detected = ml_ddos_detected or ml_slow_detected
            
            heuristic_slow_detected = (
                duration_sec >= 3.0 and 
                iat_max_val >= 2000000.0 and 
                total_packets < 150 and
                (flow['fwd_packet_count'] / safe_duration_sec) < 20.0
            )
            
            # Une attaque volumétrique requiert un volume minimal de paquets (ex: >= 20)
            # pour éviter qu'un simple handshake TCP de 3 paquets en 2 ms soit calculé mathématiquement à 1500 Pkts/s.
            heuristic_volumetric_detected = (flow_pkts_s >= DDOS_PKT_RATE_THRESHOLD and total_packets >= 20)
            heuristic_detected = heuristic_volumetric_detected or heuristic_slow_detected

            # Application du mode de detection configure (--detection-mode)
            det_mode = args.detection_mode.lower()
            if det_mode in ("heuristique", "heuristic"):
                ml_detected = False
                ml_ddos_detected = False
                ml_slow_detected = False
            elif det_mode in ("rf", "ml"):
                heuristic_detected = False
                heuristic_volumetric_detected = False
                heuristic_slow_detected = False
            elif det_mode == "hybrid":
                # Mode hybride strict : consensus requis (ML ET Heuristique doivent concorder)
                if not (ml_detected and heuristic_detected):
                    ml_detected = False
                    heuristic_detected = False

            mechanism = "None"
            if ml_detected and heuristic_detected: mechanism = "Hybrid_Both"
            elif ml_detected: mechanism = "ML_Model"
            elif heuristic_detected: mechanism = "Heuristic"
            
            verdict = "Benign"
            if mechanism in ("ML_Model", "Hybrid_Both"):
                if ml_ddos_detected:
                    verdict = lbl_ddos
                elif ml_slow_detected:
                    verdict = lbl_slow
                else:
                    verdict = lbl_ddos if ml_ddos_detected else lbl_slow
            elif mechanism == "Heuristic":
                if heuristic_volumetric_detected:
                    if protocol == 17.0 and (dport == 389 or sport == 389): verdict = "DDoS_CLDAP_Amplification"
                    elif protocol == 17.0: verdict = "DDoS_UDP_Flood"
                    elif protocol == 6.0 and flow.get('syn_count', 0) > 0: verdict = "DDoS_SYN_Flood"
                    else: verdict = "DDoS_Volumetric_Generic"
                else:
                    verdict = "Slowloris"

            mitigation_triggered = "No_Action"
            if verdict.upper() != "BENIGN":
                if args.mitigation == "on":
                    if flow['attacker_ip'] not in BLOCKED_IPS:
                        try:
                            import onos_mitigation
                            onos_mitigation.block_ip(flow['attacker_ip'])
                            BLOCKED_IPS.add(flow['attacker_ip'])
                            BLOCKED_IPS_TIMERS[flow['attacker_ip']] = current_time
                            mitigation_triggered = "Blocked_SDN"
                        except: mitigation_triggered = "Mitigation_Failed"
                    else: mitigation_triggered = "Already_Blocked"

            # Supervision hardware
            cpu_usage = psutil.cpu_percent()
            ram_usage = psutil.virtual_memory().percent
            disk_write_mb = psutil.disk_io_counters().write_bytes / (1024 * 1024)

            timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_key = f"{flow['attacker_ip']}_{verdict}"

            if verdict.upper() != "BENIGN":
                should_log = False
                if log_key not in WRITTEN_ALERTS:
                    should_log = True
                    WRITTEN_ALERTS.add(log_key)
                elif args.mitigation == "off" and (current_time - flow.get('last_logged_time', 0)) >= 5.0:
                    should_log = True

                if should_log:
                    flow['last_logged_time'] = current_time
                    ids_cpu, ids_ram_mb, lb_cpu, lb_ram_mb = get_process_metrics()
                    print(f"🚨 [{timestamp_str}] ALERT !!! IP: {flow['attacker_ip']} -> Verdict: {verdict} | Mecanisme: {mechanism} | Mitigation: {mitigation_triggered} | Rate: {flow_pkts_s:.1f} Pkts/s | IDS CPU: {ids_cpu:.1f}%")
                    with open(LOG_FILE, "a") as f_log:
                        f_log.write(f"{timestamp_str},{flow['attacker_ip']},{protocol},{duration_sec:.2f},{total_packets},{flow_pkts_s:.1f},{iat_max_val},{verdict},{mechanism},{mitigation_triggered},{cpu_usage},{ram_usage},{disk_write_mb:.2f},{ids_cpu:.1f},{ids_ram_mb:.1f},{lb_cpu:.1f},{lb_ram_mb:.1f}\n")
            else:
                if flow['attacker_ip'] not in WHITELIST_IPS:
                    benign_key = f"{flow['attacker_ip']}_{flow_id[1]}_Benign"
                    if benign_key not in WRITTEN_ALERTS and (is_closing or duration_sec >= 0.5 or total_packets >= 3):
                        WRITTEN_ALERTS.add(benign_key)
                        ids_cpu, ids_ram_mb, lb_cpu, lb_ram_mb = get_process_metrics()
                        with open(LOG_FILE, "a") as f_log:
                            f_log.write(f"{timestamp_str},{flow['attacker_ip']},{protocol},{duration_sec:.2f},{total_packets},{flow_pkts_s:.1f},{iat_max_val},Benign,None,Normal_Allowed,{cpu_usage},{ram_usage},{disk_write_mb:.2f},{ids_cpu:.1f},{ids_ram_mb:.1f},{lb_cpu:.1f},{lb_ram_mb:.1f}\n")
                        print(f"✅ [Trafic Normal (TN)] Transaction saine enregistrée : {flow['attacker_ip']} | Rate: {flow_pkts_s:.1f} Pkts/s")
                    else:
                        print(f"[Trafic Normal] Client sain : {flow['attacker_ip']} | Rate: {flow_pkts_s:.1f} Pkts/s")

if __name__ == '__main__':
    print(f"[IDS Cloud] Sniffing actif sur : [{args.interface}] | Mode Détection: [{args.detection_mode.upper()}] | Mitigation: [{args.mitigation.upper()}]")
    while True:
        try: sniff(iface=args.interface, prn=process_packet, store=0)
        except KeyboardInterrupt: break
        except Exception as e:
            time.sleep(1)
