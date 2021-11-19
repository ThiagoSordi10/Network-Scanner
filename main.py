import sys
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

        self.stop_sniffer = Event()

    def run(self):
        sniff(iface=IFACE_NAME, filter="arp", prn=arp_monitor_callback, stop_filter=self.should_stop_sniffer)

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

class DetectarDispositivos(Thread):
    def  __init__(self):
        super().__init__()

    def run(self):
        # pega o ip do roteador para verificar um intervalo de ips e descobrir quem está conectado
        router_ip = conf.route.route("0.0.0.0")[2]
        router_ip = router_ip.split(".")
        last_i = router_ip[3]
        without_last_i = router_ip[0]+"."+router_ip[1]+"."+router_ip[2]+"."

        print("zn### Detectando dispositivos já conectados a rede... ###")

        TIMEOUT = 2
        conf.verb = 0
        for ip in range(last_i, 256):
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(pdst = without_last_i + str(ip))
            answer, unanswered = srp(ether/arp, timeout = 2, iface = IFACE_NAME, inter = 0.1)

            if answer:
                for sent, received in answer:
                    adicionar_disp(received)
                    break
            # else:
            #     print("Timeout waiting for %s" % without_last_i + str(ip))

        print("\n### Fim da detecção ###")

    def join(self, timeout=None):
        super().join(timeout)

class OfflineOnline(Thread):
    def  __init__(self):
        super().__init__()

    def run(self):
        while True:
            for dispositivo in dispositivos:
                ans = sr1(IP(dst=dispositivo.ip) / ICMP(), timeout=2, iface=IFACE_NAME, verbose=0)
                if ans:
                    dispositivo.online = True
                elif dispositivo.online == True:
                    dispositivo.online = False
                    print("\n[UPDATE] Dispositivo offline:")
                    print(dispositivo)
                    print("[END UPDATE]")

    def join(self, timeout=None):
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
        return "{} {} {} {} {}".format(self.ip, self.mac, self.fabricante, "Roteador" if self.roteador else "Host", "Online" if self.online else "Offline")


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
            print("\n[UPDATE] Novo dispositivo descoberto com mac: "+pkt[Ether].src)
            dispositivos.append(Dispositivo(pkt[ARP].psrc, pkt[Ether].src))
            return True


def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
        adicionar_disp(pkt)
            # return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")

sniffer_arp = Sniffer()
offline_online = OfflineOnline()
detector = DetectarDispositivos()

print("[*] Iniciando detecção...")

detector.start()
sniffer_arp.start()
offline_online.start()

try:
    while True:
        print("Menu de opções")
        print("1) Exibir lista de todos dispositivos descobertos")
        print("2) Exibir lista de dispositivos online")
        opt = input("Digite a opção: ")
        if(opt == "1"):
            print("##Lista de dispositivos conectados na rede##")
            for dispositivo in dispositivos:
                print(dispositivo)
            print("#####")
        elif(opt == "2"):
            print("##Lista de dispositivos online conectados na rede##")
            for dispositivo in dispositivos:
                if(dispositivo.online):
                    print(dispositivo)
            print("#####")

except KeyboardInterrupt:
    print("[*] Parando detecção")
    sniffer_arp.join()
    detector.join()
    offline_online.join()
