# Matrice et Protocole d'Expérimentation Système

Ce document définit le protocole expérimental rigoureux permettant d'évaluer de manière isolée et comparative les différents mécanismes de détection ainsi que les différents profils d'attaques sur le banc de test SDN.

---

## 🎯 1. Matrice des Campagnes Expérimentales

Le banc de test permet de croiser les **moteurs de détection** avec les **profils de charge malveillante** afin d'identifier avec précision les forces, limites et complémentarités de chaque approche.

| ID Campagne | Profil de Trafic / Attaque | Moteur de Détection Testé | Argument `--detection-mode` | Télémétrie QoS Client | Fichier Log IDS |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **EXP-V1** | Volumétrique Seul (SYN + UDP) | Random Forest Seul | `rf` | `client_qos_vol_rf.csv` | `ids_vol_rf.csv` |
| **EXP-V2** | Volumétrique Seul (SYN + UDP) | Heuristique Seule | `heuristique` | `client_qos_vol_heur.csv` | `ids_vol_heur.csv` |
| **EXP-V3** | Volumétrique Seul (SYN + UDP) | Hybride Synergique | `all` | `client_qos_vol_all.csv` | `ids_vol_all.csv` |
| **EXP-S1** | Attaques Lentes Seules (Slow DoS) | Random Forest Seul | `rf` | `client_qos_slow_rf.csv` | `ids_slow_rf.csv` |
| **EXP-S2** | Attaques Lentes Seules (Slow DoS) | Heuristique Seule | `heuristique` | `client_qos_slow_heur.csv` | `ids_slow_heur.csv` |
| **EXP-S3** | Attaques Lentes Seules (Slow DoS) | Hybride Synergique | `all` | `client_qos_slow_all.csv` | `ids_slow_all.csv` |
| **EXP-M1** | Mixte Global (100 Bots) | Random Forest Seul | `rf` | `client_qos_mix_rf.csv` | `ids_mix_rf.csv` |
| **EXP-M2** | Mixte Global (100 Bots) | Heuristique Seule | `heuristique` | `client_qos_mix_heur.csv` | `ids_mix_heur.csv` |
| **EXP-M3** | Mixte Global (100 Bots) | Hybride Strict (ET) | `hybrid` | `client_qos_mix_strict.csv` | `ids_mix_strict.csv` |
| **EXP-M4** | Mixte Global (100 Bots) | Hybride Synergique (Complet) | `all` | `client_qos_mix_all.csv` | `ids_mix_all.csv` |
| **EXP-BASE**| Mixte Global (100 Bots) | Aucun (Baseline Passif) | `--mitigation off` | `client_qos_baseline.csv` | `ids_baseline_off.csv` |

---

## 📏 2. Indicateurs Clés de Performance (KPIs)

Pour chaque scénario, l'évaluation s'appuie sur quatre dimensions complémentaires :

1. **Efficacité de Neutralisation Source (Host-Level)** :
   * **Host Recall (%)** : Taux d'adresses IP attaquantes neutralisées par une règle OpenFlow DROP priorité 40000 sur OVS `s1`.
   * **Time-To-Mitigate (TTM)** : Temps écoulé (en secondes) entre la première requête d'un bot et l'éviction définitive par le contrôleur ONOS.
   * **Taux de Faux Positifs (FPR)** : Détections erronées touchant le sous-réseau client `192.168.2.0/24`.

2. **Qualité de Service & Disponibilité Web (Client QoS)** :
   * **Disponibilité HTTP (%)** : Ratio de requêtes achevées avec succès (`HTTP 200 OK`) envoyées par `monitor_http_client.py`.
   * **Latence RTT (ms)** : Temps d'aller-retour moyen, médian et 95e percentile (P95).
   * **Taux d'Échec (%)** : Requêtes en timeout ou recevant `HTTP 503 Service Unavailable`.

3. **Impact Réseau & Débit** :
   * **Réduction de charge sur le service** : Paquets et octets parvenant au Load Balancer (relevés via `collect_traffic_counters.py`).
   * **Élagage du journal IDS (%)** : Baisse du nombre de lignes enregistrées consécutivement au blocage précoce à la source.

4. **Empreinte Matérielle Isolée par Processus** :
   * Consommation CPU (%) et RAM (Mo) dédiée au processus IDS (`PID`).
   * Consommation CPU (%) et RAM (Mo) dédiée au processus Load Balancer (`HAProxy`).

---

## 🔬 3. Procédure Détaillée par Profil d'Attaque

> ⚠️ **Règle d'or opérationnelle** : Avant de démarrer n'importe quelle campagne ou basculer d'un mode de détection à un autre, exécuter systématiquement :
> ```bash
> ./unblock_all.sh
> ```
> Cela purge l'intégralité des règles DROP OpenFlow (priorité 40000) installées sur ONOS et le switch OVS `s1`, garantissant l'indépendance stricte des mesures.

### ⏱️ Chronologie d'Exécution & Synchronisation des Outils

Pour assurer la cohérence entre les flux réseaux, les compteurs de règles physiques et la télémétrie client, chaque session doit suivre la séquence temporelle ci-dessous :

| Étape | Horodatage | Rôle & Action | Commande | Remarque Critique |
| :--- | :--- | :--- | :--- | :--- |
| **0. Reset Réseau** | $T = 0$ | Purge OpenFlow | `./unblock_all.sh` | Réinitialise l'état du switch et supprime les règles résiduelles. |
| **1. Télémétrie Client** | $T = 0$ | Mesure QoS Web | `h_clt1 python3 monitor_http_client.py ... &` | Mesure continue de la disponibilité HTTP et latence (ms). |
| **2. Capture PCAP** | $T = 0$ | Capture physique | `sudo tcpdump -i s1-eth1 -w traffic_session.pcap &` | **À lancer avant l'attaque** pour enregistrer 100 % des paquets bruts. |
| **3. IDS / IPS** | $T = 0$ | Moteur de détection | `sudo env "PATH=$PATH" python3 ids_detector.py ...` | Détection et poussée des règles DROP priorité 40000. |
| **4. Attaque** | $T + 10\,\text{s}$ | Injection de charge | `py [net.get('h_atk...').cmd(...)]` | Début de la saturation (volumétrique, lente ou mixte). |
| **5. Audit Matériel** | $T + 3\,\text{min}$ | Compteurs OVS | `python3 collect_traffic_counters.py` | **À lancer avant arrêt et avant `./unblock_all.sh`** pour figer `n_packets`/`n_bytes`. |
| **6. Fin d'Attaque** | $T + 5\,\text{min}$ | Arrêt processus | Arrêt des attaques, IDS (`Ctrl+C`), `tcpdump` (`sudo killall tcpdump`) | Termine la phase d'enregistrement de trafic. |
| **7. Analyse 1:1** | Post-test | Reconstitution CICFlowMeter | `python3 evaluate_pcap_cicflowmeter.py traffic_session.pcap` | Calcule les métriques de classification sur le PCAP complet. |
| **8. Graphiques QoS** | Post-test | Visualisations 300 DPI | `python3 ids_analytics.py ... --qos ...` | Produit `eval_15`, `eval_4` et le rapport textuel. |
| **9. Nettoyage Final**| Fin | Purge OpenFlow | `./unblock_all.sh` | Réinitialise le commutateur pour l'expérience suivante. |

---

### A. CAMPAGNE 1 : Attaques Volumétriques Seules (SYN Flood + UDP Flood)
*Objectif : Évaluer la capacité à endiguer un flot massif de paquets sans corrompre les requêtes légitimes.*

#### 1. Lancement de la télémétrie client (Console `mininet>`) :
```bash
h_clt1 python3 monitor_http_client.py --target http://10.10.0.100 --output client_qos_vol.csv &
h_clt2 python3 monitor_http_client.py --target http://10.10.0.100 --output client_qos_vol.csv &
```

#### 2. Démarrage de la capture PCAP et de l'IDS (Terminal Hôte) :
> **Pré-requis systématique** : Réinitialiser les règles OpenFlow pour partir d'un état réseau neutre :
```bash
./unblock_all.sh
```

* **Démarrer la capture réseau continue (Terminal 3)** :
  ```bash
  sudo tcpdump -i s1-eth1 -w traffic_vol.pcap &
  ```

* **Démarrer l'IDS selon le mode choisi (Terminal 2)** :
  * *Option RF seul* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode rf --log-file ids_vol_rf.csv
    ```
  * *Option Heuristique seule* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode heuristique --log-file ids_vol_heur.csv
    ```
  * *Option Hybride synergique* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode all --log-file ids_vol_all.csv
    ```

#### 3. Déclenchement de l'attaque volumétrique isolée (Console `mininet>`) :
```python
# SYN Flood - 8 attaquants (h_atk86 à h_atk93)
py [net.get(f'h_atk{i}').cmd('hping3 -c 20000 -d 64 -S -p 80 --flood 10.10.0.100 &') for i in range(86, 94)]

# UDP Flood - 7 attaquants (h_atk94 à h_atk100)
py [net.get(f'h_atk{i}').cmd('hping3 --udp -p 389 --flood 10.10.0.100 &') for i in range(94, 101)]
```

#### 4. Arrêt, audit matériel et analyse :
1. **Relever les compteurs matériels OVS (AVANT d'arrêter et AVANT `./unblock_all.sh`)** :
   ```bash
   python3 collect_traffic_counters.py
   ```
2. Interrompre les attaques dans `mininet>`.
3. Interrompre l'IDS avec `Ctrl+C` et arrêter la capture PCAP :
   ```bash
   sudo killall tcpdump
   ```
4. **Réinitialiser les règles OpenFlow sur le commutateur OVS** :
   ```bash
   ./unblock_all.sh
   ```
5. **Générer le rapport et les graphiques analytiques (IDS & QoS)** :
   ```bash
   python3 ids_analytics.py ids_vol_all.csv --qos client_qos_vol.csv
   ```
6. **(Optionnel) Évaluation 1:1 via CICFlowMeter** :
   ```bash
   python3 evaluate_pcap_cicflowmeter.py traffic_vol.pcap
   ```

---

### B. CAMPAGNE 2 : Attaques Lentes Seules (Slow DoS / LDDoS)
*Objectif : Évaluer la finesse de discrimination sur des flux à très bas débit et fort temps inter-paquets (IAT), invisibles pour les seuils volumétriques naïfs.*

#### 1. Lancement de la télémétrie client (Console `mininet>`) :
```bash
h_clt1 python3 monitor_http_client.py --target http://10.10.0.100 --output client_qos_slow.csv &
h_clt2 python3 monitor_http_client.py --target http://10.10.0.100 --output client_qos_slow.csv &
```

#### 2. Démarrage de la capture PCAP et de l'IDS (Terminal Hôte) :
> **Pré-requis systématique** : Réinitialiser les règles OpenFlow pour partir d'un état réseau neutre :
```bash
./unblock_all.sh
```

* **Démarrer la capture réseau continue (Terminal 3)** :
  ```bash
  sudo tcpdump -i s1-eth1 -w traffic_slow.pcap &
  ```

* **Démarrer l'IDS selon le mode choisi (Terminal 2)** :
  * *Option RF seul* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode rf --log-file ids_slow_rf.csv
    ```
  * *Option Heuristique seule* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode heuristique --log-file ids_slow_heur.csv
    ```
  * *Option Hybride synergique* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode all --log-file ids_slow_all.csv
    ```

#### 3. Déclenchement des attaques lentes isolées (Console `mininet>`) :
```python
# SlowHTTPTest Mode Header (Slowloris GET) - 25 attaquants (h_atk1 à h_atk25)
py [net.get(f'h_atk{i}').cmd("slowhttptest -c 100 -H -i 10 -r 50 -t GET -u http://10.10.0.100 -x 24 -p 3 > /dev/null 2>&1 &") for i in range(1, 26)]

# SlowHTTPTest Mode Body (RUDY POST) - 25 attaquants (h_atk26 à h_atk50)
py [net.get(f'h_atk{i}').cmd("slowhttptest -c 100 -B -i 10 -r 50 -s 8192 -t POST -u http://10.10.0.100 -x 24 -p 3 > /dev/null 2>&1 &") for i in range(26, 51)]

# SlowHTTPTest Mode Read (Slow Read) - 20 attaquants (h_atk51 à h_atk70)
py [net.get(f'h_atk{i}').cmd("slowhttptest -c 100 -X -r 50 -w 1 -y 16 -n 5 -z 5 -k 100 -u http://10.10.0.100 -p 3 > /dev/null 2>&1 &") for i in range(51, 71)]

# Sockets Persistantes (Slowloris Python) - 15 attaquants (h_atk71 à h_atk85)
py [net.get(f'h_atk{i}').cmd('python3 slowloris_attack.py 10.10.0.100 &') for i in range(71, 86)]
```

#### 4. Arrêt, audit matériel et analyse :
1. **Relever les compteurs matériels OVS (AVANT d'arrêter et AVANT `./unblock_all.sh`)** :
   ```bash
   python3 collect_traffic_counters.py
   ```
2. Interrompre les attaques dans `mininet>`.
3. Interrompre l'IDS avec `Ctrl+C` et arrêter la capture PCAP :
   ```bash
   sudo killall tcpdump
   ```
4. **Réinitialiser les règles OpenFlow sur le commutateur OVS** :
   ```bash
   ./unblock_all.sh
   ```
5. **Générer le rapport et les graphiques analytiques (IDS & QoS)** :
   ```bash
   python3 ids_analytics.py ids_slow_all.csv --qos client_qos_slow.csv
   ```
6. **(Optionnel) Évaluation 1:1 via CICFlowMeter** :
   ```bash
   python3 evaluate_pcap_cicflowmeter.py traffic_slow.pcap
   ```

---

### C. CAMPAGNE 3 : Attaque Mixte Globale (100 Bots Simultanés)
*Objectif : Confrontation à grande échelle avec les 100 bots activés en simultané combinant volumétrie et épuisement lent des sockets HAProxy.*

#### 1. Lancement de la télémétrie client (Console `mininet>`) :
```bash
h_clt1 python3 monitor_http_client.py --target http://10.10.0.100 --output client_qos_mix.csv &
h_clt2 python3 monitor_http_client.py --target http://10.10.0.100 --output client_qos_mix.csv &
```

#### 2. Démarrage de la capture PCAP et de l'IDS (Terminal Hôte) :
> **Pré-requis systématique** : Réinitialiser les règles OpenFlow pour partir d'un état réseau neutre :
```bash
./unblock_all.sh
```

* **Démarrer la capture réseau continue (Terminal 3)** :
  ```bash
  sudo tcpdump -i s1-eth1 -w traffic_mix.pcap &
  ```

* **Démarrer l'IDS selon le mode comparatif désiré (Terminal 2)** :
  * *Option Hybride Synergique (Complet)* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode all --log-file ids_mix_all.csv
    ```
  * *Option Random Forest Seul* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode rf --log-file ids_mix_rf.csv
    ```
  * *Option Heuristique Seule* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode heuristique --log-file ids_mix_heur.csv
    ```
  * *Option Hybride Strict* :
    ```bash
    sudo env "PATH=$PATH" python3 ids_detector.py --interface any --mitigation on --detection-mode hybrid --log-file ids_mix_strict.csv
    ```

#### 3. Déclenchement conjoint des 100 attaquants (Console `mininet>`) :
```python
py [net.get(f'h_atk{i}').cmd("slowhttptest -c 100 -H -i 10 -r 50 -t GET -u http://10.10.0.100 -x 24 -p 3 > /dev/null 2>&1 &") for i in range(1, 26)]
py [net.get(f'h_atk{i}').cmd("slowhttptest -c 100 -B -i 10 -r 50 -s 8192 -t POST -u http://10.10.0.100 -x 24 -p 3 > /dev/null 2>&1 &") for i in range(26, 51)]
py [net.get(f'h_atk{i}').cmd("slowhttptest -c 100 -X -r 50 -w 1 -y 16 -n 5 -z 5 -k 100 -u http://10.10.0.100 -p 3 > /dev/null 2>&1 &") for i in range(51, 71)]
py [net.get(f'h_atk{i}').cmd('python3 slowloris_attack.py 10.10.0.100 &') for i in range(71, 86)]
py [net.get(f'h_atk{i}').cmd('hping3 -c 10000 -d 64 -S -p 80 --flood 10.10.0.100 &') for i in range(86, 93)]
py [net.get(f'h_atk{i}').cmd('hping3 --udp -p 389 --flood 10.10.0.100 &') for i in range(93, 101)]
```

#### 4. Arrêt, audit matériel et analyse :
1. **Relever les compteurs matériels OVS (AVANT d'arrêter et AVANT `./unblock_all.sh`)** :
   ```bash
   python3 collect_traffic_counters.py
   ```
2. Interrompre les attaques dans `mininet>`.
3. Interrompre l'IDS avec `Ctrl+C` et arrêter la capture PCAP :
   ```bash
   sudo killall tcpdump
   ```
4. **Réinitialiser les règles OpenFlow sur le commutateur OVS** :
   ```bash
   ./unblock_all.sh
   ```
5. **Générer le rapport et les graphiques analytiques (IDS & QoS)** :
   ```bash
   python3 ids_analytics.py ids_mix_all.csv --qos client_qos_mix.csv
   ```
6. **(Optionnel) Évaluation 1:1 via CICFlowMeter** :
   ```bash
   python3 evaluate_pcap_cicflowmeter.py traffic_mix.pcap
   ```

---

## 📊 4. Protocoles de Comparaison Croisée

### Comparatif 1 : Inférence Random Forest vs Heuristique vs Hybride
Pour comparer formellement les logs obtenus avec deux modes différents (ex: RF vs Hybride) :
```bash
python3 ids_analytics.py --compare ids_mix_all.csv ids_mix_rf.csv --qos client_qos_mix.csv
```
Ce script confronte directement :
* La neutralisation des hôtes botnet.
* Le débit crête et le débit moyen subi.
* Le temps moyen d'exposition aux menaces.
* L'empreinte CPU et mémoire vive.

### Comparatif 2 : Session 1:1 sans fragmentation via CICFlowMeter
Pour évaluer le rappel et la matrice de confusion sur les connexions complètes reconstruites à partir du fichier PCAP :
```bash
# Capture pendant la campagne :
sudo tcpdump -i s1-eth1 -w traffic_session.pcap

# Analyse 1:1 post-session :
python3 evaluate_pcap_cicflowmeter.py traffic_session.pcap
```
Génère la figure haute résolution `eval_14_cicflowmeter_1to1_flow_metrics.png` (300 DPI) et la table `flows_evaluated_1to1.csv`.

### Comparatif 3 : Relevé des compteurs OpenFlow OVS et disponibilité web
```bash
python3 collect_traffic_counters.py
```
Fournit les métriques physiques matérielles :
* Paquets et octets rejetés au niveau du commutateur OpenFlow (règles `priority=40000`).
* Disponibilité instantanée et temps d'accès au Load Balancer HAProxy.

---

## 📋 5. Tableau Récapitulatif des Propriétés des Moteurs

| Critère d'Évaluation | Random Forest Pur (`rf`) | Heuristiques Pures (`heuristique`) | Hybride Synergique (`all`) | Hybride Strict (`hybrid`) |
| :--- | :--- | :--- | :--- | :--- |
| **Sensibilité Volumétrique** | Moyenne à Élevée | Maximale (Seuil immédiat Pkts/s) | Maximale (Réactivité immédiate) | Moyenne (Requiert double accord) |
| **Sensibilité Slow DoS / LDDoS** | Élevée (Reconnaissance patterns) | Élevée (Seuil IAT $\ge 8s$) | Optimale (Synergie croisée) | Élevée (Zéro faux positif) |
| **Risque de Faux Positifs** | Faible | Très Faible | Très Faible | Nul (Double validation) |
| **Temps de Réaction (TTD)** | Variable (Taille fenêtre flux) | Immédiat dès dépassement seuil | Immédiat (Heuristique + IA) | Modéré (Temps de convergence) |
| **Résilience Évasion** | Élevée face au bruit | Faible si attaque sous le seuil | Élevée (Complémentarité) | Maximale |

---

## 🚀 6. Évaluation Automatisée de Toutes les Campagnes (`batch_evaluate_campaigns.py`)

Un script d'automatisation global permet de parcourir l'ensemble des sous-dossiers de campagnes, d'exécuter `ids_analytics.py` et `evaluate_pcap_cicflowmeter.py` en conservant l'ensemble des figures et fichiers CSV dans chaque sous-dossier respectif, et de générer une synthèse consolidée ainsi qu'un prompt de rédaction :

```bash
# Exécution complète (Analytics IDS + Évaluation 1:1 CICFlowMeter sur tous les sous-dossiers) :
python3 batch_evaluate_campaigns.py

# Option rapide (Analytics IDS uniquement, sans recalculer les PCAP) :
python3 batch_evaluate_campaigns.py --skip-pcap

# Option synthèse seule (génère immédiatement les tableaux comparatifs et le prompt) :
python3 batch_evaluate_campaigns.py --summary-only
```

### Fichiers et Résultats Produits :
1. **Dans chaque sous-dossier de campagne** :
   - Figures haute résolution `eval_1_*.png` à `eval_13_*.png`, `eval_15_*.png` (300 DPI) et `dashboard_*.png`.
   - Figure d'évaluation des sessions 1:1 `eval_14_cicflowmeter_1to1_flow_metrics.png` et dataset `flows_evaluated_1to1.csv`.
2. **À la racine du dossier d'expérimentation (`Experimentation/`)** :
   - `synthese_globale_experimentations.md` : Tableau comparatif consolidé regroupant détection, neutralisation, QoS et compteurs OpenFlow pour l'ensemble des 11 campagnes et modes.
   - `prompt_mise_a_jour_rapport.md` : Prompt structuré et contextualisé, prêt à être copié-collé pour rédiger ou mettre à jour la section de résultats du rapport technique.

