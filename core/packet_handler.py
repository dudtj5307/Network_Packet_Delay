from __future__ import annotations

import time
import hashlib
from collections import deque, defaultdict
from typing import TYPE_CHECKING

import scapy.all as scapy
from scapy.packet import Packet
scapy.conf.verb = 0

Ether, IP, TCP, UDP, ICMP, ARP = scapy.Ether, scapy.IP, scapy.TCP, scapy.UDP, scapy.ICMP, scapy.ARP

if TYPE_CHECKING:
    from core.process import MainProcess


class PacketHandler:
    ARP_CACHE_TTL = 10

    def __init__(self, parent: MainProcess):
        self.parent = parent
        self.arp_cache: defaultdict[str, float] = defaultdict(float)
        self.pkt_cache: deque = deque([], maxlen=2000)

    def reset(self) -> None:
        self.arp_cache.clear()
        self.pkt_cache.clear()

    # Check if same ARP has been sent recently
    def arp_cached(self, packet: Packet) -> bool:
        arp_id = f"{packet.op}{packet.hwsrc}{packet.psrc}{packet.hwdst}{packet.pdst}"
        arp_hash = hashlib.md5(arp_id.encode()).hexdigest()
        now = time.time()
        if now - self.arp_cache[arp_hash] > self.ARP_CACHE_TTL:
            self.arp_cache[arp_hash] = now
            return False
        return True

    def pkt_cached(self, packet: Packet, pkt_chksum) -> bool:
        if (packet[IP].chksum, pkt_chksum) in self.pkt_cache:
            return True
        self.pkt_cache.append((packet[IP].chksum, pkt_chksum))
        return False

    # Function called from sniff_packets
    def packet_callback(self, packet: Packet) -> None:
        parse_start_time = time.time()
        p = self.parent

        if not packet.haslayer(Ether):
            return

        # L2 Packets (ARP)
        if packet.haslayer(ARP) and p.mode_selected == "Bridging":
            if self.arp_cached(packet):
                return
            if p.widget.print_flag.get():
                print(f"[Detected] ARP {'Request' if packet.op==1 else 'Reply'} {packet.psrc} -> {packet.pdst} ",
                      flush=True)

        # L3 Packets (TCP, UDP, UDP-segments, ICMP)
        elif packet.haslayer(IP):
            if   packet.haslayer(TCP):  pkt_chksum = packet[TCP].chksum;  pkt_protocol = "TCP"
            elif packet.haslayer(UDP):  pkt_chksum = packet[UDP].chksum;  pkt_protocol = "UDP"
            elif packet[IP].proto==17:  pkt_chksum = packet[IP].frag;     pkt_protocol = "UDP-seg"
            elif packet.haslayer(ICMP): pkt_chksum = packet[ICMP].chksum; pkt_protocol = "ICMP"
            else:
                return

            if self.pkt_cached(packet, pkt_chksum):
                return

            # Route MAC Address & IP Filtering
            pkt_ip_src, pkt_ip_dst = packet[IP].src, packet[IP].dst
            if pkt_ip_src == p.ip1 and pkt_ip_dst == p.ip2:
                packet[Ether].src = p.src_mac2
                packet[Ether].dst = p.dst_mac2
            elif pkt_ip_src == p.ip2 and pkt_ip_dst == p.ip1:
                packet[Ether].src = p.src_mac1
                packet[Ether].dst = p.dst_mac1
            else:
                return

            if p.widget.print_flag.get():
                print(f"[Detected] {pkt_protocol} {pkt_ip_src} -> {pkt_ip_dst} ")
        else:
            return

        # Sending Packets to Child Process
        p.que_to_child.put((packet, parse_start_time))

        # Counter only — GUI update is handled exclusively by pkt_counts_update
        p.pkt_detect_num  += 1
        p.pkt_process_num += 1
