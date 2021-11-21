import sys
import os
from scapy.all import *
from datetime import datetime
import requests
from scapy import *

from threading import Thread, Event, Lock
from time import sleep


IFACE_NAME = "Intel(R) Wireless-AC 9560 160MHz"
MAC_URL = 'http://macvendors.co/api/%s'

data_lock = Lock()

dispositivos = []


class Sniffer(Thread):
    def  __init__(self):
        super().__init__()
        self._stopper = threading.Event()

    def run(self):
        # Faz um sniff no arp para novas conexões
        sniff(iface=IFACE_NAME, filter="arp", prn=arp_monitor_callback, stop_filter=self.stopped)

    def join(self, timeout=None):
        self.stop()
        super().join(timeout)

    def stopped(self, packet):
        return self._stopper.isSet()

    def stop(self):
        self._stopper.set()

class DetectarDispositivos(Thread):
    def  __init__(self):
        super().__init__()
        self._stopper = threading.Event()

    def stopped(self):
        return self._stopper.isSet()

    def stop(self):
        self._stopper.set()

    def run(self):
        # pega o ip do roteador para verificar um intervalo de ips e descobrir quem já está conectado
        router_ip = conf.route.route("0.0.0.0")[2]
        router_ip = router_ip.split(".")
        without_last_part = router_ip[0]+"."+router_ip[1]+"."+router_ip[2]+"."

        print("### Detectando dispositivos já conectados a rede... ###")

        conf.verb = 0
        for ip in range(1, 256):
            if self.stopped():
                break
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(pdst = without_last_part + str(ip))
            answer = srp1(ether/arp, timeout = 1, iface = IFACE_NAME)

            if answer:
                adicionar_disp(answer)


        print("\n### Fim da detecção de dispositivos já conectados a rede ###")

    def join(self, timeout=None):
        self.stop()
        super().join(timeout)

class OfflineOnline(Thread):
    def  __init__(self):
        super().__init__()
        self._stopper = threading.Event()

    def stopped(self):
        return self._stopper.isSet()

    def stop(self):
        self._stopper.set()

    def run(self):
        # ping infinito entre os dispositivos para ver quem está online ou offline
        while not self.stopped():
            for dispositivo in dispositivos:
                ans = sr1(IP(dst=dispositivo.ip) / ICMP(), timeout=15, iface=IFACE_NAME, verbose=0)
                if ans and dispositivo.online == False:
                    dispositivo.online = True
                    os.system('cls' if os.name == 'nt' else 'clear')
                    print("\n[UPDATE] Dispositivo online:")
                    print(dispositivo)
                    print("[END UPDATE]")
                    exibir_dispositivos()
                elif dispositivo.online == True:
                    dispositivo.online = False
                    os.system('cls' if os.name == 'nt' else 'clear')
                    print("\n[UPDATE] Dispositivo offline:")
                    print(dispositivo)
                    print("[END UPDATE]")
                    exibir_dispositivos()


    def join(self, timeout=None):
        self.stop()
        super().join(timeout)


class Dispositivo():
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        try:
            # usar mac para pegar fabricante
            r = requests.get(MAC_URL % self.mac)
            self.fabricante = r.json()['result']['company']
        except:
            self.fabricante = None
        self.roteador = True if conf.route.route("0.0.0.0")[2] == ip else False # conf.route.route("0.0.0.0")[2] -> pegar ip do roteador
        self.online = True
        self.primeira_descoberta = datetime.now()

    def __str__(self):
        return "{} {} {} {} {} {}".format(self.ip, self.mac, self.fabricante, "Roteador" if self.roteador else "Host", "Online" if self.online else "Offline", self.primeira_descoberta)


def dispositivo_ja_descoberto(mac):
    for dispositivo in dispositivos:
        if dispositivo.mac == mac:
            dispositivo.online = True
            return True
    return False


def adicionar_disp(pkt):
    with data_lock:
        #verificar se o device ta na lista de dispositivos, senao tiver adicionar (com horario da descoberta)
        if(dispositivo_ja_descoberto(pkt[Ether].src) is not True):
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n[UPDATE] Novo dispositivo descoberto com mac: "+pkt[Ether].src)
            dispositivos.append(Dispositivo(pkt[ARP].psrc, pkt[Ether].src))
            exibir_dispositivos()
            return True


def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has ou is-at
        adicionar_disp(pkt)

def exibir_dispositivos():
    dispositivos_ordenados = sorted(dispositivos, key=lambda item: (item.online))
    print("\n##Lista de dispositivos conectados na rede##")
    for dispositivo in dispositivos_ordenados:
        print(dispositivo)
    print("#####")

sniffer_arp = Sniffer()
offline_online = OfflineOnline()
detector = DetectarDispositivos()

print("[*] Iniciando detecção...")

detector.start()
sniffer_arp.start()
offline_online.start()

try:
    while True:
        sleep(100)

except KeyboardInterrupt:
    print("\n[*] Parando detecção.....")
    offline_online.join()
    sniffer_arp.join()
    detector.join()
