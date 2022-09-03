
from ast import keyword
from typing import Any
import scapy.all as scapy
from scapy.layers import http

import argparse

# Sniff HTTP -------------------------

def sniff_http():
    scapy.sniff( store=False, prn=sniffed_http_packet )


def get_http_url(packet):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        return url.decode('utf-8')

def filter_raw_layer(packet):
    
    keywords = ['username', 'user', 'uname', 'login', 'pass', 'password']
    for key in keywords:
        if key in packet:
            print(f'\n[+] Catch out potencial packet >> {packet}\n')
            break

def sniffed_http_packet(packet):
    if packet.haslayer(http.HTTPRequest):

        url = get_http_url(packet)
        print(f'[+] HTTP Request >> {url}')

        if packet.haslayer(scapy.Raw):
            packet = packet[scapy.Raw].load.decode('utf-8')
            filter_raw_layer(packet)


# Main -------------------------

if __name__ == '__main__':
    sniff_http()
