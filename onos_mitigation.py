#!/usr/bin/env python3
import requests
import json
import logging

# Configuration de base pour ONOS
ONOS_IP = "127.0.0.1"
ONOS_PORT = 8181
ONOS_USER = "onos"
ONOS_PASS = "rocks"
ONOS_URL = f"http://{ONOS_IP}:{ONOS_PORT}/onos/v1"

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ONOS-Mitigation")

# Ensemble pour garder trace des adresses déjà bloquées
blocked_ips = set()

def get_devices():
    """
    Récupère la liste de tous les identifiants de switchs (device IDs) actifs sur ONOS.
    """
    url = f"{ONOS_URL}/devices"
    try:
        response = requests.get(url, auth=(ONOS_USER, ONOS_PASS), timeout=5)
        if response.status_code == 200:
            devices_data = response.json().get("devices", [])
            device_ids = [d["id"] for d in devices_data if d.get("available", False)]
            return device_ids
        else:
            logger.error(f"Impossible de recuperer les equipements. Status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Erreur de connexion a ONOS REST API : {e}")
    return []

def block_ip(attacker_ip):
    """
    Crée et pousse une règle de flux (Flow Rule) dans chaque switch ONOS pour DROP 
    tous les paquets IPv4 provenant de l'adresse IP de l'attaquant.
    """
    if attacker_ip in blocked_ips:
        logger.info(f"L'adresse IP {attacker_ip} est deja mitigee/bloquee.")
        return True

    logger.warning(f"🚨 Déclenchement de la mitigation pour l'adresse IP : {attacker_ip}")

    # Récupération des commutateurs actifs
    devices = get_devices()
    if not devices:
        devices = ["of:0000000000000001"]

    success = False
    for device_id in devices:
        url = f"{ONOS_URL}/flows/{device_id}"
        
        flow_rule = {
            "priority": 40000,
            "timeout": 0,
            "isPermanent": True,
            "treatment": {
                "instructions": []
            },
            "selector": {
                "criteria": [
                    {
                        "type": "ETH_TYPE",
                        "ethType": "0x0800"
                    },
                    {
                        "type": "IPV4_SRC",
                        "ip": f"{attacker_ip}/32"
                    }
                ]
            }
        }

        try:
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            response = requests.post(
                url, 
                auth=(ONOS_USER, ONOS_PASS), 
                data=json.dumps(flow_rule), 
                headers=headers, 
                timeout=5
            )
            if response.status_code in [200, 201]:
                logger.info(f"Règle de blocage (DROP) poussee avec succes sur {device_id} pour {attacker_ip}.")
                success = True
            else:
                logger.error(f"Echec de mitigation sur {device_id} (Code: {response.status_code}). Response: {response.text}")
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de la flow rule vers {device_id} : {e}")

    if success:
        blocked_ips.add(attacker_ip)
    return success

def unblock_ip(attacker_ip):
    """
    Supprime la règle de blocage (Flow Rule) dans chaque switch ONOS pour l'adresse IP spécifiée.
    """
    if attacker_ip not in blocked_ips:
        logger.info(f"L'adresse IP {attacker_ip} n'est pas localement marquee comme bloquee. Tentative de suppression sur ONOS...")
    
    logger.warning(f"🔓 Déclenchement du déblocage (unblock) pour l'adresse IP : {attacker_ip}")
    
    devices = get_devices()
    if not devices:
        devices = ["of:0000000000000001"]
        
    success = False
    for device_id in devices:
        url = f"{ONOS_URL}/flows/{device_id}"
        try:
            response = requests.get(url, auth=(ONOS_USER, ONOS_PASS), timeout=5)
            if response.status_code == 200:
                flows = response.json().get("flows", [])
                for flow in flows:
                    if flow.get("priority") == 40000:
                        criteria = flow.get("selector", {}).get("criteria", [])
                        is_match = False
                        for crit in criteria:
                            if crit.get("type") == "IPV4_SRC" and attacker_ip in crit.get("ip", ""):
                                is_match = True
                                break
                        if is_match:
                            flow_id = flow.get("id")
                            if flow_id:
                                delete_url = f"{ONOS_URL}/flows/{device_id}/{flow_id}"
                                del_response = requests.delete(delete_url, auth=(ONOS_USER, ONOS_PASS), timeout=5)
                                if del_response.status_code in [200, 204]:
                                    logger.info(f"Règle de blocage supprimee avec succes sur {device_id} (Flow ID: {flow_id}) pour {attacker_ip}.")
                                    success = True
                                else:
                                    logger.error(f"Echec de suppression du flux {flow_id} sur {device_id} (Code: {del_response.status_code}).")
            else:
                logger.error(f"Impossible de recuperer les flux pour {device_id} (Code: {response.status_code}).")
        except Exception as e:
            logger.error(f"Erreur lors du déblocage de {attacker_ip} sur {device_id} : {e}")

    if attacker_ip in blocked_ips:
        blocked_ips.discard(attacker_ip)
        
    return success

def unblock_all():
    """
    Supprime TOUTES les règles de blocage (priorité 40000) de l'ensemble des switchs ONOS.
    """
    logger.warning("🔓 Déclenchement de la réinitialisation/déblocage global (Unblock All) sur ONOS...")
    devices = get_devices()
    if not devices:
        devices = ["of:0000000000000001"]
        
    removed_count = 0
    for device_id in devices:
        url = f"{ONOS_URL}/flows/{device_id}"
        try:
            response = requests.get(url, auth=(ONOS_USER, ONOS_PASS), timeout=5)
            if response.status_code == 200:
                flows = response.json().get("flows", [])
                for flow in flows:
                    if flow.get("priority") == 40000:
                        flow_id = flow.get("id")
                        if flow_id:
                            delete_url = f"{ONOS_URL}/flows/{device_id}/{flow_id}"
                            del_res = requests.delete(delete_url, auth=(ONOS_USER, ONOS_PASS), timeout=5)
                            if del_res.status_code in [200, 204]:
                                removed_count += 1
        except Exception as e:
            logger.error(f"Erreur lors du déblocage global sur {device_id} : {e}")

    blocked_ips.clear()
    logger.info(f"✓ Déblocage global termine : {removed_count} regles de blocage supprimees sur ONOS.")
    return removed_count

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 onos_mitigation.py [block|unblock|unblock_all] [IP]")
        sys.exit(1)
    
    action = sys.argv[1].lower()
    
    if action == "unblock_all":
        unblock_all()
    elif action == "unblock":
        test_ip = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.1"
        unblock_ip(test_ip)
    else:
        test_ip = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.1"
        block_ip(test_ip)
