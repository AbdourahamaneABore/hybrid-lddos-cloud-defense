#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
import time

class MassifIDSTopo(Topo):
    def build(self, num_attackers=100, num_servers=10, num_legitimes=10):
        # Commutateur OpenFlow 1.3 lie au controleur ONOS
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        
        # Infrastructure Legitime
        self.addLink(self.addHost('h_lb', ip='10.10.0.100/24', defaultRoute='dev h_lb-eth0'), s1)

        for i in range(1, num_servers + 1):
            ip_id = 200 + i
            host_name = f'h_srv{i}'
            self.addLink(self.addHost(host_name, ip=f'10.10.0.{ip_id}/24', defaultRoute=f'dev {host_name}-eth0'), s1)
        
        for i in range(1, num_legitimes + 1):
            host_name = f'h_clt{i}'
            self.addLink(self.addHost(host_name, ip=f'192.168.2.{i}/24', defaultRoute=f'dev {host_name}-eth0'), s1)
        
        # Generation automatisee du Botnet d'attaquants
        print(f"[*] Instanciation de {num_attackers} hotes attaquants dans la topologie...")
        for i in range(1, num_attackers + 1):
            ip_id = i
            host_name = f'h_atk{i}'
            attacker_ip = f'10.0.0.{ip_id}/24'
            self.addLink(self.addHost(host_name, ip=attacker_ip, defaultRoute=f'dev {host_name}-eth0'), s1)

if __name__ == '__main__':
    # Modifier num_attackers a 100, 200 ou 300 pour evaluer les limites de l'IDS
    topo = MassifIDSTopo(num_attackers=100)
    onos_controller = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, switch=OVSSwitch, controller=onos_controller)
    
    net.start()
    print("[✓] Topologie massive employee avec succes. Pret pour les injections.")
    CLI(net)
    net.stop()
