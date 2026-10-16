#!/usr/bin/env bash
# Script de déblocage global pour l'IDS/IPS SDN ONOS
echo "[*] Réinitialisation et déblocage de toutes les règles de mitigation sur ONOS..."
python3 ./onos_mitigation.py unblock_all
