#!/usr/bin/env python3
# ============================================================================
# threaded_server.py
# ----------------------------------------------------------------------------
# Serveur HTTP multithreadé utilisé dans l'environnement expérimental Cloud.
#
# Objectif :
# ----------
# Ce programme met en place un serveur Web léger capable de gérer plusieurs
# connexions TCP simultanées.
#
# Il représente le service applicatif protégé par le système IDS.
# Les clients légitimes génèrent du trafic normal vers ce serveur tandis que
# les machines attaquantes exécutent des attaques de type Slow DoS ou DDoS.
#
# Contrairement à un serveur HTTP classique mono-thread, cette implémentation
# utilise plusieurs threads afin de simuler un comportement plus proche d'un
# serveur Web réel capable de traiter plusieurs requêtes concurrentes.
#
# Architecture expérimentale :
#
#     Clients
#        |
#        |
#        v
#   Load Balancer
#        |
#        |
#        v
#   Serveur HTTP multithreadé
#
# L'objectif est d'observer la réaction du service face aux attaques réseau
# et de permettre au module IDS de capturer et analyser les flux générés.
# ============================================================================


# ============================================================================
# Importation des bibliothèques Python natives
# ============================================================================


# HTTPServer fournit l'implémentation de base d'un serveur HTTP.
#
# SimpleHTTPRequestHandler est un gestionnaire HTTP minimal capable de :
#
#   - recevoir des requêtes GET/HEAD ;
#   - retourner des fichiers présents dans le répertoire courant ;
#   - générer automatiquement des réponses HTTP.
#
# Cette combinaison permet de créer rapidement un serveur Web expérimental.

from http.server import HTTPServer, SimpleHTTPRequestHandler

# ThreadingMixIn permet de transformer un serveur classique en serveur
# multithreadé.
#
# Chaque nouvelle connexion cliente sera exécutée dans un thread indépendant.
#
# Cette approche est particulièrement importante pour les expérimentations
# Slow DoS, car ces attaques reposent sur l'ouverture simultanée d'un grand
# nombre de connexions TCP maintenues ouvertes.

from socketserver import ThreadingMixIn

# Le module sys permet d'interagir avec l'environnement Python.
#
# Ici il est utilisé pour quitter proprement le programme lors de
# l'interruption du serveur.

import sys

# ============================================================================
# Définition du serveur HTTP multithreadé
# ============================================================================

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    
    """
    Serveur HTTP capable de traiter plusieurs connexions simultanément.

    Héritage multiple :

        ThreadingMixIn
            |
            |-- ajoute la gestion des threads

        HTTPServer
            |
            |-- fournit le comportement serveur HTTP classique


    Sans ThreadingMixIn :
        Une seule requête bloque le serveur jusqu'à sa terminaison.

    Avec ThreadingMixIn :
        Chaque client possède son propre thread d'exécution.

    Cette propriété permet de reproduire un comportement proche
    d'un serveur Web de production.
    """



    # ------------------------------------------------------------------------
    # Gestion automatique des threads.
    #
    # Lorsque daemon_threads vaut True :
    #
    #   - les threads associés aux connexions clientes sont considérés
    #     comme des threads secondaires ;
    #
    #   - lors de l'arrêt du serveur, ils sont automatiquement terminés.
    #
    # Cela évite que le programme reste bloqué par des connexions
    # encore ouvertes.
    #
    # Ce comportement est particulièrement utile dans un laboratoire
    # d'expérimentation réseau où de nombreuses connexions peuvent être
    # volontairement maintenues ouvertes par des attaques Slow DoS.
    # ------------------------------------------------------------------------

    daemon_threads = True

# ============================================================================
# Programme principal
# ============================================================================

if __name__ == '__main__':

    # ------------------------------------------------------------------------
    # Port d'écoute du serveur Web.
    #
    # Le port 80 correspond au port HTTP standard.
    #
    # Dans cette expérimentation :
    #
    #     Load Balancer --> Serveur Web
    #
    # Les attaques Slowloris ciblent également ce port afin de reproduire
    # une attaque contre un service Web classique.
    # ------------------------------------------------------------------------

    port = 80

    # ------------------------------------------------------------------------
    # Création de l'instance serveur.
    #
    # Adresse :
    #
    #     0.0.0.0
    #
    # signifie que le serveur accepte les connexions provenant de toutes
    # les interfaces réseau disponibles.
    #
    # Cela est nécessaire dans Mininet car les communications proviennent
    # des différentes machines virtuelles :
    #
    #     h_cli*
    #     h_atk*
    #     h_lb
    #
    # Handler :
    #
    #     SimpleHTTPRequestHandler
    #
    # indique que le serveur utilisera le gestionnaire HTTP standard
    # fourni par Python.
    # ------------------------------------------------------------------------

    server = ThreadedHTTPServer(('0.0.0.0', port), SimpleHTTPRequestHandler)

    # ------------------------------------------------------------------------
    # Message d'information indiquant que le service Web est opérationnel.
    # ------------------------------------------------------------------------

    print(f"Serveur multi-thréadé actif sur le port {port}...")

    # ------------------------------------------------------------------------
    # Boucle principale du serveur.
    #
    # serve_forever() maintient le serveur en fonctionnement permanent.
    #
    # Pendant cette phase :
    #
    #   - les requêtes HTTP entrantes sont acceptées ;
    #
    #   - un thread est créé pour chaque connexion ;
    #
    #   - les réponses HTTP sont générées.
    #
    # Cette boucle représente le comportement normal d'un serveur Web.
    # ------------------------------------------------------------------------

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
