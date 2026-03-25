from __future__ import annotations

import scapy.all as scapy
scapy.conf.verb = 0

Ether, IP, UDP = scapy.Ether, scapy.IP, scapy.UDP


def get_src_mac(interface: str) -> str:
    return scapy.get_if_hwaddr(interface)


def get_dst_mac(interface: str, dst_ip: str) -> str | None:
    try:
        ans, _ = scapy.arping(iface=interface, net=dst_ip, timeout=1, verbose=False)
        for sent, received in ans:
            return received.hwsrc
        print(f"Could not find MAC Address for {dst_ip}")
        return None
    except Exception as e:
        print(f"Can't send ARP for {dst_ip}. Exception : {e}")
        return None


def invalid_ip(ip_str: str) -> bool:
    ips = ip_str.strip().split('.')
    if len(ips) != 4: return True
    for ip in ips:
        if not ip.isdigit(): return True
        if int(ip) < 0 or int(ip) > 255: return True
    return False


def send_dummy_packet(iface: str) -> None:
    scapy.sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255") / UDP(dport=9999), iface=iface)
