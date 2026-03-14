import os
import psutil
import time
from collections import deque

import scapy.all as scapy

Ether, IP, TCP, UDP, ICMP, ARP = scapy.Ether, scapy.IP, scapy.TCP, scapy.UDP, scapy.ICMP, scapy.ARP

def get_src_mac(interface):
    return scapy.get_if_hwaddr(interface)

def get_dst_mac(interface, dst_ip):
    try:
        ans, _ = scapy.arping(iface=interface, net=dst_ip, timeout=1, verbose=False)
        for sent, received in ans:
            return received.hwsrc
        print(f"Could not find MAC Address for {dst_ip}")
        return None
    except Exception as e:
        print(f"Can't send ARP for {dst_ip}. Exception : {e}")
        return None

def invalid_ip(ip_str):
    ips = ip_str.strip().split('.')
    if len(ips) != 4: return True
    for ip in ips:
        if not ip.isdigit(): return True
        if int(ip) < 0 or int(ip) > 255: return True
    return False

# Input Validation
def input_validation(self):
    try:
        # Check Validation - Interface Selecting Box
        if "" in self.iface_selected:
            raise ValueError("InterfaceError")
        # Check Validation -
        if invalid_ip(self.ip1_entry.get()) or invalid_ip(self.ip2_entry.get()):
            raise ValueError("IPAddressError")
        if float(self.delay_entry.get()) < 0:
            raise ValueError("DelayTimeError")

    except ValueError as error:
        error_type = str(error)
        if error_type == "InterfaceError":
            messagebox.showerror("Network Interface Error", "Please select the Network Interface")
        elif error_type == "IPAddressError":
            messagebox.showerror("Invalid IP Address","IP Address entered in invalid format.\nex) 192.168.110.6")
        elif error_type == "DelayTimeError":
            messagebox.showerror("Delay Time Error", "Please enter a valid delay time in ms.\n(range ≥ 0)")
        return True
    return False

# Child Process
def packet_delay_send(q_pkt_from_parent, stop_event, infos):
    scapy.conf.verb = 0

    # Process Priority Elevation
    sub_pid = psutil.Process(os.getpid())
    sub_pid.nice(psutil.HIGH_PRIORITY_CLASS)

    # Information from Main Thread
    delay_ms, iface_selected, pkt_sent_num = infos

    # Delay time calculation with compensation
    delay = float(delay_ms) / 1000  # ms -> 초로 변환

    # Deque for saving (packet, start time)
    pkt_deque = deque()
    while not stop_event.is_set():
        # Get Packets from Parent Process
        try:
            while True:
                pkt_deque.append(q_pkt_from_parent.get_nowait())
        except Exception:
            pass
        # Check delayed time and send
        while pkt_deque:
            pkt, start_time = pkt_deque[0]
            if time.time() - start_time >= delay:
                # Send Packets by Ethernet (Layer 2)
                if pkt.sniffed_on == iface_selected[0]: scapy.sendp(pkt, iface=iface_selected[1]);
                if pkt.sniffed_on == iface_selected[1]: scapy.sendp(pkt, iface=iface_selected[0]);
                pkt_deque.popleft()
                # Sent Number Update
                with pkt_sent_num.get_lock():
                    pkt_sent_num.value += 1
            else:
                break
