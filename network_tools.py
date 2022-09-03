
from tabnanny import verbose
import time
import os
import subprocess
import scapy.all as scapy
from tabulate import tabulate
import argparse
import re
import ip_spoorfer
import netifaces


literal_ip_regex = r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-4]|2[0-4][0-9]|[01]?[0-9][0-9]?)'


def get_arg():
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', dest='ip_address', help='Target IP')
    parser.add_argument('-g', dest='gateway', help='Input Gateway')
    parser.add_argument('-i', dest='interface', help='Select your interface')

    parser.add_argument('-C', dest='choice', default = None, \
        choices=['ARP', 'SPOOF_IP'],  \
        help='Choose your action.')

    args = parser.parse_args()

    if args.ip_address is not None:
        assert valid_ip(args.ip_address) , '[-] No valid IP'

    if args.gateway is None:
        args.gateway = get_default_gateway()

    assert valid_network(args.gateway), '[-] No valid Gateway, or not network physically connected'

    return args

def valid_network(ip):
    try:
        subprocess.check_output(['ping', '-c' , '1' , ip],  timeout=10 )
        return True
    except subprocess.CalledProcessError:
        return False

def valid_ip(ip):
    return bool(re.match(
        r'((0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.|$)){4}', str(ip)))

def get_default_gateway():
    ip_regex = literal_ip_regex

    gateways = netifaces.gateways()
    defaults = gateways.get("default")
    if defaults:  
        gw_info = defaults.get( netifaces.AF_INET )
        ip_address = re.search(ip_regex, str(gw_info))
        return ip_address.group(0) if ip_address else None


def get_family_ip():

    gateways = netifaces.gateways()
    defaults = gateways.get("default")
    if defaults:
        family = netifaces.AF_INET
        gw_info = defaults.get( family )
        if gw_info:
            addresses = netifaces.ifaddresses(gw_info[1]).get(family)
            return [address['addr'] for address in addresses]

def enable_ip_forward(turn=False):
    assert type(turn) is bool
    mode = 1 if turn else 0
    subprocess.run( ["sysctl", "-w" , f"net.ipv4.ip_forward={str(mode)}"], stdout=open(os.devnull, 'wb') )

def request_arp(ip):
    arp_request = scapy.ARP(pdst = ip + "/24")
    broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')

    arp_request_broadcast = broadcast / arp_request
    arp_reply = scapy.srp(arp_request_broadcast, timeout=2, verbose=False) [0]

    arp_clients = {}
    for reply in arp_reply:
        arp_clients[ reply[1].psrc ] = reply[1].hwsrc
    return arp_clients

def print_arp_request(arp_clients, headers=['IP', 'MAC']):
    print("\n" + tabulate(arp_clients.items(), headers=headers, tablefmt='orgtbl') + "\n")

def arp_get_mac(target_ip, gateway):
    arp_clients = request_arp(gateway)
    mac_client = arp_clients.get(target_ip)
    return mac_client



if __name__ == "__main__":
    args = get_arg()

    if  args.gateway is None:
        args.gateway = get_default_gateway()

    if args.choice == 'ARP':
        print(f'[+] Sending ARP Request...')
        print_arp_request(request_arp(args.gateway))

    if args.choice == 'SPOOF_IP':
        assert args.ip_address is not None, f'You must select an IP in your netfor spoofing'
        ip_spoorfer.run_spoofer(args.ip_address, args.gateway)

