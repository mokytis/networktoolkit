from dataclasses import dataclass

import click
import scapy.all as scapy

from networktoolkit import vendorlookup


@dataclass
class Client:
    """Dataclass for a network client"""

    ip_addr: str
    mac_addr: str
    mac_vendor: str


@click.command()
@click.argument("ip_range")
@click.option("-t", "--timeout", help="Scan timeout (seconds)", default=3)
@click.option("-v", "--vendor", help="Show mac vendor", is_flag=True)
def cli(ip_range, timeout, vendor):
    clients = get_clients(ip_range, timeout)
    for client in clients:
        output = f"{client.ip_addr}\t{client.mac_addr}"
        if vendor and client.mac_vendor:
            output += f"\t{client.mac_vendor}"
        click.echo(output)


def get_clients(ip, t):
    """Gets a list of accessable devices on the network in a given ip range

    :param ip: ip range to scan
    :param t: timeout (seconds)
    :type t: int

    :return: list of clients on network
    :rtype: list(Client)
    """

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    final_packet = broadcast / arp_request
    answered_list, _ = scapy.srp(final_packet, timeout=t, verbose=False)

    clients = []

    for sent, response in answered_list:
        ip_addr = response.psrc
        mac_addr = response.hwsrc
        mac_vendor = vendorlookup.lookup_vendor(mac_addr)
        clients.append(Client(ip_addr, mac_addr, mac_vendor))

    return clients
