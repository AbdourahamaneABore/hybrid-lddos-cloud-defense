#!/usr/bin/env python3
"""
evaluate_pcap_cicflowmeter.py
-----------------------------
Pipeline d'Évaluation 1:1 au Niveau Flux (Flow-Level) avec CICFlowMeter.

Caractéristiques techniques :
1. Chaque connexion bidirectionnelle (5-tuple) = EXACTEMENT 1 ligne CSV (Alignement 1:1).
2. Évaluation globale par session complète (sans fragmentation d'états).
3. Utilise le générateur de features officiel CICFlowMeter (identique à CIC-IDS2017/2018).
4. Produit la Matrice de Confusion de flux 1:1 et la figure 'eval_14_cicflowmeter_1to1_flow_metrics.png' (300 DPI).

Usage :
    python3 evaluate_pcap_cicflowmeter.py capture.pcap
    python3 evaluate_pcap_cicflowmeter.py flows_cicflowmeter.csv
"""

import sys
import os
import argparse
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

# Mapping standardisé : snake_case (CICFlowMeter Python) -> CamelCase (CIC-IDS Dataset Features)
SNAKE_TO_CIC = {
    'dst_port': 'Dst Port',
    'src_port': 'Src Port',
    'protocol': 'Protocol',
    'flow_duration': 'Flow Duration',
    'tot_fwd_pkts': 'Total Fwd Packets',
    'tot_bwd_pkts': 'Total Backward Packets',
    'totlen_fwd_pkts': 'Fwd Packets Length Total',
    'totlen_bwd_pkts': 'Bwd Packets Length Total',
    'fwd_pkt_len_max': 'Fwd Packet Length Max',
    'fwd_pkt_len_min': 'Fwd Packet Length Min',
    'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
    'fwd_pkt_len_std': 'Fwd Packet Length Std',
    'bwd_pkt_len_max': 'Bwd Packet Length Max',
    'bwd_pkt_len_min': 'Bwd Packet Length Min',
    'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
    'bwd_pkt_len_std': 'Bwd Packet Length Std',
    'flow_byts_s': 'Flow Bytes/s',
    'flow_pkts_s': 'Flow Packets/s',
    'flow_iat_mean': 'Flow IAT Mean',
    'flow_iat_std': 'Flow IAT Std',
    'flow_iat_max': 'Flow IAT Max',
    'flow_iat_min': 'Flow IAT Min',
    'fwd_iat_tot': 'Fwd IAT Total',
    'fwd_iat_mean': 'Fwd IAT Mean',
    'fwd_iat_std': 'Fwd IAT Std',
    'fwd_iat_max': 'Fwd IAT Max',
    'fwd_iat_min': 'Fwd IAT Min',
    'bwd_iat_tot': 'Bwd IAT Total',
    'bwd_iat_mean': 'Bwd IAT Mean',
    'bwd_iat_std': 'Bwd IAT Std',
    'bwd_iat_max': 'Bwd IAT Max',
    'bwd_iat_min': 'Bwd IAT Min',
    'fwd_psh_flags': 'Fwd PSH Flags',
    'bwd_psh_flags': 'Bwd PSH Flags',
    'fwd_urg_flags': 'Fwd URG Flags',
    'bwd_urg_flags': 'Bwd URG Flags',
    'fwd_header_len': 'Fwd Header Length',
    'bwd_header_len': 'Bwd Header Length',
    'fwd_pkts_s': 'Fwd Packets/s',
    'bwd_pkts_s': 'Bwd Packets/s',
    'pkt_len_min': 'Packet Length Min',
    'pkt_len_max': 'Packet Length Max',
    'pkt_len_mean': 'Packet Length Mean',
    'pkt_len_std': 'Packet Length Std',
    'pkt_len_var': 'Packet Length Variance',
    'fin_flag_cnt': 'FIN Flag Count',
    'syn_flag_cnt': 'SYN Flag Count',
    'rst_flag_cnt': 'RST Flag Count',
    'psh_flag_cnt': 'PSH Flag Count',
    'ack_flag_cnt': 'ACK Flag Count',
    'urg_flag_cnt': 'URG Flag Count',
    'cwr_flag_count': 'CWE Flag Count',
    'ece_flag_cnt': 'ECE Flag Count',
    'down_up_ratio': 'Down/Up Ratio',
    'pkt_size_avg': 'Avg Packet Size',
    'fwd_seg_size_avg': 'Avg Fwd Segment Size',
    'bwd_seg_size_avg': 'Avg Bwd Segment Size',
    'fwd_byts_b_avg': 'Fwd Avg Bytes/Bulk',
    'fwd_pkts_b_avg': 'Fwd Avg Packets/Bulk',
    'fwd_blk_rate_avg': 'Fwd Avg Bulk Rate',
    'bwd_byts_b_avg': 'Bwd Avg Bytes/Bulk',
    'bwd_pkts_b_avg': 'Bwd Avg Packets/Bulk',
    'bwd_blk_rate_avg': 'Bwd Avg Bulk Rate',
    'subflow_fwd_pkts': 'Subflow Fwd Packets',
    'subflow_fwd_byts': 'Subflow Fwd Bytes',
    'subflow_bwd_pkts': 'Subflow Bwd Packets',
    'subflow_bwd_byts': 'Subflow Bwd Bytes',
    'init_fwd_win_byts': 'Init Fwd Win Bytes',
    'init_bwd_win_byts': 'Init Bwd Win Bytes',
    'fwd_act_data_pkts': 'Fwd Act Data Packets',
    'fwd_seg_size_min': 'Fwd Seg Size Min',
    'active_mean': 'Active Mean',
    'active_std': 'Active Std',
    'active_max': 'Active Max',
    'active_min': 'Active Min',
    'idle_mean': 'Idle Mean',
    'idle_std': 'Idle Std',
    'idle_max': 'Idle Max',
    'idle_min': 'Idle Min'
}

def extract_flows_from_pcap(pcap_file, output_csv, max_packets=None):
    """
    Exécute CICFlowMeter en Python pour extraire les flux 1:1 à partir d'un PCAP.
    Affiche la progression en temps réel (paquets traités, flux actifs, débit pkts/s).
    """
    print(f"[CICFlowMeter] Extraction des flux bidirectionnels 1:1 depuis '{pcap_file}'...")
    from cicflowmeter.flow_session import FlowSession
    from cicflowmeter.sniffer import _start_periodic_gc, GC_INTERVAL
    from scapy.utils import PcapReader
    import time

    if os.path.exists(output_csv):
        try:
            os.remove(output_csv)
        except Exception:
            pass

    session = FlowSession(
        output_mode='csv',
        output=output_csv,
        verbose=False
    )
    _start_periodic_gc(session, interval=GC_INTERVAL)

    t0 = time.time()
    count = 0
    print("[CICFlowMeter] Décodage et suivi des sessions TCP/UDP en temps réel...")
    try:
        with PcapReader(pcap_file) as reader:
            for pkt in reader:
                session.process(pkt)
                count += 1
                if count % 10000 == 0:
                    elapsed = time.time() - t0
                    rate = count / elapsed if elapsed > 0 else 0
                    with session._lock:
                        n_flows = len(session.flows)
                    sys.stdout.write(f"\r[CICFlowMeter] {count:,} paquets analysés | {n_flows:,} flux actifs ({rate:,.0f} pkts/s)...")
                    sys.stdout.flush()
                if max_packets and count >= max_packets:
                    print(f"\n[!] Limite de {max_packets:,} paquets atteinte (échantillonnage représentatif).")
                    break
    except KeyboardInterrupt:
        print(f"\n[!] Interruption utilisateur reçue. Finalisation propre des {count:,} paquets analysés...")

    elapsed = time.time() - t0
    sys.stdout.write(f"\r[CICFlowMeter] {count:,} paquets traités avec succès en {elapsed:.1f}s ({count/elapsed if elapsed>0 else 0:,.0f} pkts/s).\n")
    sys.stdout.flush()

    if hasattr(session, '_gc_stop'):
        session._gc_stop.set()
        session._gc_thread.join(timeout=2.0)
    session.flush_flows()
    print(f"[✓] Extraction terminée ! Fichier généré : {output_csv}")
    return output_csv

def evaluate_flows_1to1(csv_file, output_fig="eval_14_cicflowmeter_1to1_flow_metrics.png"):
    print("\n" + "="*85)
    print("🔬 ÉVALUATION 1:1 AU NIVEAU FLUX (FLOW-LEVEL) - CICFLOWMETER & RANDOM FOREST")
    print("="*85)

    df_raw = pd.read_csv(csv_file)
    print(f"🔹 Nombre total de flux bidirectionnels (1:1) : {len(df_raw)}")
    if len(df_raw) == 0:
        print("[-] Aucun flux détecté dans le fichier.")
        return

    # Normalisation des colonnes snake_case
    df_raw.columns = df_raw.columns.str.strip().str.lower()

    # Création du Flow ID unique
    df_raw['flow_id'] = (
        df_raw['src_ip'].astype(str) + ":" + df_raw['src_port'].astype(str) + " -> " +
        df_raw['dst_ip'].astype(str) + ":" + df_raw['dst_port'].astype(str) + " (" +
        df_raw['protocol'].astype(str) + ")"
    )

    # 1. Détermination de la Vérité Terrain (Ground Truth)
    # Dans Mininet : 10.0.0.x = Botnet d'attaque, 192.168.2.x = Clients légitimes
    def get_ground_truth(row):
        src = str(row['src_ip']).strip()
        dst = str(row['dst_ip']).strip()
        if src.startswith("10.0.0.") or dst.startswith("10.0.0."):
            return 1  # Attaque
        return 0      # Bénin

    df_raw['y_true'] = df_raw.apply(get_ground_truth, axis=1)

    # Chargement des modèles d'apprentissage IA
    print("[+] Chargement des modèles Random Forest...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    def resolve_model_path(fname):
        if os.path.exists(fname): return fname
        return os.path.join(script_dir, fname)

    model_slow = joblib.load(resolve_model_path('rf_model.joblib'))
    le_slow = joblib.load(resolve_model_path('label_encoder.joblib'))
    model_ddos = joblib.load(resolve_model_path('ddos_model.joblib'))

    # Renommage des colonnes pour le modèle DDoS (CIC-IDS 77 features)
    df_ddos = pd.DataFrame()
    for snake_col, cic_col in SNAKE_TO_CIC.items():
        if snake_col in df_raw.columns:
            df_ddos[cic_col] = pd.to_numeric(df_raw[snake_col], errors='coerce').fillna(0)
        else:
            df_ddos[cic_col] = 0

    # Renommage pour le modèle DoS Slow (10 features)
    df_slow = pd.DataFrame()
    slow_mapping = {
        'Dst Port': 'dst_port',
        'Bwd Pkts/s': 'bwd_pkts_s',
        'Flow Pkts/s': 'flow_pkts_s',
        'Fwd Seg Size Min': 'fwd_seg_size_min',
        'Fwd Pkts/s': 'fwd_pkts_s',
        'Flow IAT Max': 'flow_iat_max',
        'Flow IAT Mean': 'flow_iat_mean',
        'Init Fwd Win Byts': 'init_fwd_win_byts',
        'Flow Duration': 'flow_duration',
        'Flow Byts/s': 'flow_byts_s'
    }
    for feat, snake in slow_mapping.items():
        if snake in df_raw.columns:
            df_slow[feat] = pd.to_numeric(df_raw[snake], errors='coerce').fillna(0)
        else:
            df_slow[feat] = 0

    # Inférence des modèles
    print("[+] Exécution des inférences sur chaque flux 1:1...")
    X_ddos = df_ddos.reindex(columns=model_ddos.feature_names_in_, fill_value=0)
    pred_ddos = model_ddos.predict(X_ddos)

    X_slow = df_slow.reindex(columns=model_slow.feature_names_in_, fill_value=0)
    pred_slow_encoded = model_slow.predict(X_slow)
    pred_slow = le_slow.inverse_transform(pred_slow_encoded)

    # Verdict hybride par flux
    final_verdicts = []
    y_pred_binary = []

    for i in range(len(df_raw)):
        lbl_s = str(pred_slow[i]).strip()
        lbl_d = str(pred_ddos[i]).strip()
        
        # Caractéristiques extraites par cicflowmeter (déjà en secondes)
        iat_max = float(df_raw.loc[i, 'flow_iat_max']) if 'flow_iat_max' in df_raw.columns else 0.0
        dur_s = float(df_raw.loc[i, 'flow_duration']) if 'flow_duration' in df_raw.columns else 0.0
        pkts = float(df_raw.loc[i, 'tot_fwd_pkts'] + df_raw.loc[i, 'tot_bwd_pkts']) if 'tot_fwd_pkts' in df_raw.columns else 0.0
        flow_pkts_s = float(df_raw.loc[i, 'flow_pkts_s']) if 'flow_pkts_s' in df_raw.columns else 0.0
        flow_byts_s = float(df_raw.loc[i, 'flow_byts_s']) if 'flow_byts_s' in df_raw.columns else 0.0
        init_fwd_win = float(df_raw.loc[i, 'init_fwd_win_byts']) if 'init_fwd_win_byts' in df_raw.columns else 0.0
        pkt_len_max = float(df_raw.loc[i, 'pkt_len_max']) if 'pkt_len_max' in df_raw.columns else 0.0

        # Détection Volumétrique : Modèle Random Forest ou Heuristique de débit / signature d'outil de flood
        ml_ddos = (lbl_d != "0" and lbl_d.upper() != "BENIGN")
        heur_vol = (init_fwd_win == 512 and pkt_len_max <= 128) or (flow_byts_s >= 20000000) or (flow_pkts_s >= 200000)

        # Détection DoS Lente : Modèle Random Forest Slow ou Heuristique de rétention de sockets (fort IAT, bas débit)
        ml_slow = (lbl_s.upper() != "BENIGN") and (dur_s >= 2.0 or iat_max >= 1.5)
        heur_slow = (dur_s >= 2.0 or iat_max >= 1.5) and (flow_pkts_s < 100)

        verdict = "Benign"
        if ml_ddos or heur_vol:
            verdict = "DDoS"
        elif ml_slow or heur_slow:
            verdict = "Slowloris" if "slowloris" in lbl_s.lower() else "DoS attacks-Slow"
            
        final_verdicts.append(verdict)
        y_pred_binary.append(0 if verdict == "Benign" else 1)

    df_raw['Verdict'] = final_verdicts
    df_raw['y_pred'] = y_pred_binary

    # 2. Calcul des Métriques 1:1 au Niveau Flux
    tp = int(((df_raw['y_true'] == 1) & (df_raw['y_pred'] == 1)).sum())
    tn = int(((df_raw['y_true'] == 0) & (df_raw['y_pred'] == 0)).sum())
    fp = int(((df_raw['y_true'] == 0) & (df_raw['y_pred'] == 1)).sum())
    fn = int(((df_raw['y_true'] == 1) & (df_raw['y_pred'] == 0)).sum())

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print("-" * 85)
    print("📊 RÉSULTATS SCIENTIFIQUES 1:1 (AUCUN BIAIS DE STREAMING) :")
    print(f"   • Total Flux Réseau (Sessions 1:1) : {total}")
    print(f"   • Vrais Positifs (TP - Flux Attaques identifiés) : {tp}")
    print(f"   • Vrais Négatifs (TN - Flux Légitimes validés)   : {tn}")
    print(f"   • Faux Positifs  (FP - Flux Légitime bloqué)     : {fp}")
    print(f"   • Faux Négatifs  (FN - Flux Attaque manqué)      : {fn}")
    print("-" * 85)
    print(f"   • Exactitude (Accuracy globale) : {accuracy*100:6.2f} %")
    print(f"   • Précision (Precision)          : {precision*100:6.2f} %")
    print(f"   • Rappel au Niveau Flux (Recall) : {recall*100:6.2f} %")
    print(f"   • Spécificité (TNR)              : {specificity*100:6.2f} %")
    print(f"   • Taux de Faux Positifs (FPR)    : {fpr*100:6.2f} %")
    print(f"   • F1-Score au Niveau Flux        : {f1*100:6.2f} %")
    print("="*85 + "\n")

    # 3. Figure 14 Haute Définition (300 DPI)
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))

    # Matrice de Confusion 1:1
    cm = np.array([[tn, fp], [fn, tp]])
    im = axes[0, 0].imshow(cm, cmap='Blues', interpolation='nearest')
    axes[0, 0].set_title("1. Matrice de Confusion 1:1 au Niveau Flux (Flow-Level)", fontsize=12, fontweight='bold')
    axes[0, 0].set_xticks([0, 1])
    axes[0, 0].set_yticks([0, 1])
    axes[0, 0].set_xticklabels(['Prédit Sain', 'Prédit Attaque'], fontsize=10)
    axes[0, 0].set_yticklabels(['Réel Sain', 'Réel Attaque'], fontsize=10)
    axes[0, 0].set_xlabel("Verdict IA Hybride", fontsize=10)
    axes[0, 0].set_ylabel("Vérité Terrain Réseau", fontsize=10)

    cell_texts = [[f"TN (Flux Sains)\n{tn}", f"FP (Faux Positifs)\n{fp}"],
                  [f"FN (Attaques Manquées)\n{fn}", f"TP (Attaques Détectées)\n{tp}"]]
    for r in range(2):
        for c in range(2):
            val = cm[r, c]
            color = 'white' if val > (total / 2) else 'black'
            axes[0, 0].text(c, r, cell_texts[r][c], ha='center', va='center', color=color, fontsize=11, fontweight='bold')

    # Histogramme des métriques
    m_names = ['Exactitude', 'Précision', 'Rappel (TPR)', 'Spécificité', 'F1-Score', 'Faux Positifs (FPR)']
    m_vals = [accuracy*100, precision*100, recall*100, specificity*100, f1*100, fpr*100]
    m_colors = ['#27ae60', '#2980b9', '#16a085', '#3498db', '#8e44ad', '#e74c3c']
    bars = axes[0, 1].barh(m_names, m_vals, color=m_colors, edgecolor='black', alpha=0.85, height=0.55)
    axes[0, 1].set_title("2. Métriques de Performance 1:1 (Sessions Complètes)", fontsize=12, fontweight='bold')
    axes[0, 1].set_xlabel("Pourcentage (%)", fontsize=10)
    axes[0, 1].set_xlim(0, 118)
    axes[0, 1].grid(axis='x', linestyle='--', alpha=0.6)
    for b in bars:
        w = b.get_width()
        axes[0, 1].text(w + 1.5, b.get_y() + b.get_height()/2, f'{w:.2f}%', va='center', fontsize=10, fontweight='bold')

    # Répartition des Verdicts
    v_counts = df_raw['Verdict'].value_counts()
    axes[1, 0].bar(v_counts.index, v_counts.values, color=['#2980b9', '#e74c3c', '#f39c12', '#2ecc71'][:len(v_counts)], edgecolor='black', width=0.5)
    axes[1, 0].set_title("3. Répartition des Classes de Flux Identifiées", fontsize=12, fontweight='bold')
    axes[1, 0].set_ylabel("Nombre de Sessions Uniques", fontsize=10)
    axes[1, 0].grid(axis='y', linestyle='--', alpha=0.6)
    for b in axes[1, 0].patches:
        h = b.get_height()
        axes[1, 0].text(b.get_x() + b.get_width()/2, h + 0.5, f'{int(h)} ({h/total*100:.1f}%)', ha='center', va='bottom', fontsize=9, fontweight='bold')

    # Espace Discriminant IAT vs Débit
    for v_lbl, c in [('Benign', '#2ecc71'), ('Slowloris', '#e67e22'), ('DoS attacks-Slow', '#d35400'), ('DDoS', '#c0392b')]:
        sub = df_raw[df_raw['Verdict'] == v_lbl]
        if not sub.empty:
            iat_s = sub['flow_iat_max'] / 1e6 if 'flow_iat_max' in sub.columns else [0]
            pkts_s = sub['flow_pkts_s'] if 'flow_pkts_s' in sub.columns else [0]
            axes[1, 1].scatter(pkts_s, iat_s, label=v_lbl, color=c, alpha=0.75, s=40, edgecolors='none')
    axes[1, 1].set_title("4. Espace Décisionnel des Flux (Log IAT vs Débit)", fontsize=12, fontweight='bold')
    axes[1, 1].set_xlabel("Débit de Session (Pkts/s)", fontsize=10)
    axes[1, 1].set_ylabel("IAT Max (s)", fontsize=10)
    axes[1, 1].set_xscale('log')
    axes[1, 1].legend(frameon=True, facecolor='white', loc='upper right')
    axes[1, 1].grid(True, linestyle='--', alpha=0.6)

    plt.tight_layout()
    plt.savefig(output_fig, dpi=300)
    plt.close()
    print(f"[✓] Exporte : {output_fig} (300 DPI)")

    # Sauvegarde du CSV évalué 1:1
    out_csv = "flows_evaluated_1to1.csv"
    df_raw.to_csv(out_csv, index=False)
    print(f"[✓] Dataset évalué 1:1 exporté dans : {out_csv}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Évaluation 1:1 au Niveau Flux avec CICFlowMeter")
    parser.add_argument("input_file", help="Fichier .pcap (capture réseau) ou .csv (déjà extrait par CICFlowMeter)")
    parser.add_argument("--output-fig", default="eval_14_cicflowmeter_1to1_flow_metrics.png", help="Nom du fichier image 300 DPI")
    parser.add_argument("--max-packets", type=int, default=None, help="Nombre maximal de paquets à traiter pour un échantillonnage rapide")
    args = parser.parse_args()

    in_file = args.input_file
    if in_file.endswith(".pcap") or in_file.endswith(".pcapng"):
        csv_out = in_file.rsplit(".", 1)[0] + "_cicflows.csv"
        extract_flows_from_pcap(in_file, csv_out, max_packets=args.max_packets)
        evaluate_flows_1to1(csv_out, output_fig=args.output_fig)
    elif in_file.endswith(".csv"):
        evaluate_flows_1to1(in_file, output_fig=args.output_fig)
    else:
        print(f"[-] Format de fichier non supporté : {in_file}. Fournir un fichier .pcap ou .csv.")
