import click
import time
import copy
import scapy.all as scapy
from dataclasses import dataclass

from networktoolkit.vendorlookup import lookup_vendor
from networktoolkit.arpspoof import gen_arp_response
from networktoolkit.showhosts import show_hosts


@dataclass
class Client:
    ip_addr: str
    mac_addr: str
    mac_vendor: str


clients = {}


def handler(pkt):
    if scapy.ARP in pkt and pkt[scapy.ARP].op in (1, 2):
        mac_addr = pkt[scapy.ARP].hwsrc
        if mac_addr != "00:00:00:00:00:00" and mac_addr not in [
            scapy.get_if_hwaddr(i) for i in scapy.get_if_list()
        ]:
            ip_addr = pkt[scapy.ARP].psrc
            mac_vendor = lookup_vendor(mac_addr)
            client = Client(ip_addr, mac_addr, mac_vendor)
            if ip_addr in clients:
                if clients[ip_addr].mac_addr != mac_addr:
                    clients[ip_addr] = client
                    return f"{ip_addr:15} is now {mac_addr} ({mac_vendor})"
            else:
                clients[ip_addr] = client
                return f"{ip_addr:15}    is  {mac_addr} ({mac_vendor})"
    else:
        return show_hosts(pkt)


def netwatch(spoof_ip, delay):
    t = scapy.AsyncSniffer(prn=handler, store=0)
    t.start()
    try:
        if delay > 0:
            while True:
                for c in copy.copy(clients).values():
                    packet = gen_arp_response(c.ip_addr, spoof_ip)
                    if packet:
                        scapy.send(packet, verbose=False)
                    packet = gen_arp_response(spoof_ip, c.ip_addr)
                    if packet:
                        scapy.send(packet, verbose=False)
            time.sleep(delay)
        else:
            input()
    except KeyboardInterrupt:
        print("Stopping")
        t.stop()


@click.command()
@click.option(
    "-a",
    "--arp-spoof",
    default="192.168.0.1",
    help="IPv4 address to arp spoof",
)
@click.option(
    "-d",
    "--delay",
    default=0,
    help="Delay between sending each arp spoof of packets (seconds). 0 = don't arp spoof",
)
def cli(arp_spoof, delay):
    netwatch(arp_spoof, delay)
