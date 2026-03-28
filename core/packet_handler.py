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

    def send_proxy_arp(self, packet: Packet) -> None:
        p = self.parent
        iface = packet.sniffed_on
        reply_hwsrc = p.src_mac1 if iface == p.widget.iface_selected[0] else p.src_mac2

        arp_reply = (Ether(src=reply_hwsrc, dst=packet[ARP].hwsrc) /
                     ARP(op=2,hwsrc=reply_hwsrc,       psrc=packet[ARP].pdst,
                              hwdst=packet[ARP].hwsrc, pdst=packet[ARP].psrc))
        scapy.sendp(arp_reply, iface=iface)

        if p.widget.print_flag.get():
            print(f"[Detected] ARP Request {packet[ARP].psrc} -> {packet[ARP].pdst} "
                  f"[ARP Proxy] ARP Reply {packet[ARP].pdst} is at {reply_hwsrc}", flush=True)

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

        # L2 Packets (ARP) - Proxy ARP Reply
        if p.mode_selected == "Bridging" and packet.haslayer(ARP) and packet[ARP].op == 1:
            if self.arp_cached(packet):
                return

            pkt_ip_src, pkt_ip_dst = packet[ARP].psrc, packet[ARP].pdst
            if (pkt_ip_src == p.ip1 and pkt_ip_dst == p.ip2) or (pkt_ip_src == p.ip2 and pkt_ip_dst == p.ip1):
                self.send_proxy_arp(packet)
            return

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
