
from ast import Store
import subprocess
import argparse
import re
import os
from time import sleep, time
import network_tools
import ipaddress

print_ip_mac = lambda iface: print(f'[+] Ip: {network_tools.get_family_ip()}\n[+] Mac: {get_mac(iface)}')

literal_mac_regex = r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})'
literal_ip_regex = r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-4]|2[0-4][0-9]|[01]?[0-9][0-9]?)'

def get_arg():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', dest='interface', help='Select your interface')

    parser.add_argument('-n', dest='IP net', help='Select your IP net')
    parser.add_argument('-m', dest='mac', help='Input your new MAC to get')
    parser.add_argument('-p', dest='ip', help='Input your new IP to get')
    
    parser.add_argument('-g', dest='gateway', help='Input Gateway')

    parser.add_argument( '-v', '--verify', dest='verify', action='store_true', required=False,
                        help='Verify the net is connecting')

    args = parser.parse_args()
    if (args.mac is not None or args.ip is not None) and args.interface is None:
        parser.error(f'No interface specified to IP or MAC selected')

    if args.verify == True and args.interface is None:
        parser.error(f'You have to select an interface to verify')

    return args

def get_mac(interface):
    mac_regex = literal_mac_regex

    ifconfig_output = subprocess.check_output( ['ifconfig', interface] )
    mac_address = re.findall(mac_regex, ifconfig_output.decode('utf-8'))

    return mac_address.pop() if mac_address else None
    
def get_ipv4_type_c(interface):
    ip_regex = literal_ip_regex

    ip_addr_output = subprocess.check_output( ['ip', 'addr', 'show', 'dev' , interface] )
    ip_address = re.search(ip_regex, ip_addr_output.decode('utf-8'))
    return ip_address.group(0) if ip_address else None

def change_mac(interface, new_mac):
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw',  'ether', new_mac], shell=False)
    subprocess.call(['ifconfig', interface, 'up'])

def change_ip(interface, new_ip):
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.Popen(['sudo', 'ifconfig', interface, new_ip])
    subprocess.call(['ifconfig', interface, 'up'])

def calculate_ipv4_net(ip, mask=24):
    ip = ip.split('.')
    bin_ip, bin_net, dec_net = '', '', ''

    get_binary = lambda n: format(n, 'b').zfill(8)

    for decimal in ip:
        bin_ip += get_binary(int(decimal))
   
    for bin in range(32):
        if bin in range(mask, len(bin_ip)):
            bin_net += '0'
        else:
            bin_net += bin_ip[bin] 

    for hexadecimal in range(0,31,8):
        dec_net += str( int(bin_net[hexadecimal:hexadecimal+8], base=2) ) + '.'

    return dec_net[:len(dec_net)-1]


def verify_route(iface, route_ip, gateway, device_ip):
    if not network_tools.valid_network( gateway ):
        print('Adding gateway to routing table...')
        subprocess.call( ['route', 'add', '-net', route_ip, 'gw', device_ip, 'dev', iface], stdout=open(os.devnull, 'wb')  )

    if not network_tools.valid_network( '8.8.8.8' ):
        print('Adding default to routing table...')
        subprocess.call( ['route', 'add', 'default', 'gw', gateway], stdout=open(os.devnull, 'wb')  )
    else:
        return True


if __name__ == '__main__':
    args = get_arg()

    print('Initial Configuration: ')
    print_ip_mac(args.interface)
    
    if args.ip:
        print(f'[+] Changing IP...')
        change_ip(args.interface, args.ip) 
        # After changing, need some times to refresh it
        sleep(15)
      
    if args.mac:
        print(f'[+] Changing MAC...')
        change_mac(args.interface, args.mac)


    if args.verify:
        print('[+] Verifying...')
        args.gateway = network_tools.get_default_gateway()
        args.ip = get_ipv4_type_c(args.interface)
        args.net = calculate_ipv4_net(args.gateway, mask=24)
        for _ in range(3):
            if verify_route(args.interface, args.net, args.gateway, args.ip):
                break
            sleep(2)
        print('\nAfter verifying: ') 
        print_ip_mac(args.interface)  
    print('\nFinal congifuration')
    print_ip_mac(args.interface)     
