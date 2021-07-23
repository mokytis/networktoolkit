#!/usr/bin/env python

import click
import logging
import scapy.all as scapy


def get_dns_query(dns_query):
    return dns_query.qname.decode()


def get_http_host(http_request):
    return f"{http_request.Host.decode()} {http_request.Path.decode()}"


def get_tls_servername(tls_ext_servername):
    return " ".join([sn.servername.decode() for sn in tls_ext_servername.servernames])


def show_hosts(pkt):
    layers = [
        {
            "name": "DNS",
            "layer_name": "DNSQR",
            "handler": get_dns_query,
        },
        {
            "name": "HTTP",
            "layer_name": "HTTPRequest",
            "handler": get_http_host,
        },
        {
            "name": "TLS",
            "layer_name": "TLS_Ext_ServerName",
            "handler": get_tls_servername,
        },
    ]
    if pkt.haslayer(scapy.IP):
        src_ip = pkt.getlayer(scapy.IP).src
        dst_ip = pkt.getlayer(scapy.IP).dst

        for l in layers:
            if l["layer_name"] in pkt:
                if data := l["handler"](pkt[l["layer_name"]]):
                    print(f"{src_ip:15}\t{dst_ip:15}\t{l['name']}\t{data}")


scapy.load_layer("tls")
scapy.load_layer("http")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


@click.command()
def cli():
    scapy.sniff(prn=show_hosts)
