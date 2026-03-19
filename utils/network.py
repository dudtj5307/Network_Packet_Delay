from __future__ import annotations

import os
import psutil
import time
import ipaddress

from collections import deque
from dataclasses import dataclass

import scapy.all as scapy
scapy.conf.verb = 0

Ether, IP, TCP, UDP, ICMP, ARP = scapy.Ether, scapy.IP, scapy.TCP, scapy.UDP, scapy.ICMP, scapy.ARP

@dataclass
class Interface:
    ip : str
    name : str
    description : str

    @property
    def display(self) -> str:
        return f"[{self.name}] {self.description} ({self.ip})"

    @classmethod
    def check_valid(cls, ip, name, description) -> Interface | None:
        try:    # IPv4 valid check
            if ipaddress.ip_address(ip).version != 4:   return None
        except ValueError:  return None
        # loopback name check
        if "loopback" in name.lower():
            return None
        return cls(ip, name, description)

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

# Child Process
def packet_delay_send(infos) -> None:
    # Process Priority Elevation
    sub_pid = psutil.Process(os.getpid())
    sub_pid.nice(psutil.HIGH_PRIORITY_CLASS)

    # Information from Main Thread
    que_from_parent, stop_event, delay_ms, iface_selected, pkt_sent_num = infos

    delay = float(delay_ms) / 1000  # ms -> 초로 변환

    # Deque for saving (packet, start time)
    pkt_deque = deque()
    while not stop_event.is_set():
        # Get Packets from Parent Process
        try:
            while True:
                pkt_deque.append(que_from_parent.get_nowait())
        except Exception:
            pass
        # Check delayed time and send
        while pkt_deque:
            pkt, start_time = pkt_deque[0]
            if time.time() - start_time >= delay:
                # Send Packets by Ethernet (Layer 2)
                if pkt.sniffed_on == iface_selected[0]: scapy.sendp(pkt, iface=iface_selected[1]);
                elif pkt.sniffed_on == iface_selected[1]: scapy.sendp(pkt, iface=iface_selected[0]);
                pkt_deque.popleft()
                # Sent Number Update
                with pkt_sent_num.get_lock():
                    pkt_sent_num.value += 1
            else:
                break

def send_dummy_packet(iface: str) -> None:
    scapy.sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255") / UDP(dport=9999), iface=iface)
