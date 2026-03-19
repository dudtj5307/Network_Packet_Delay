import os
import psutil
import time
from datetime import datetime
from sys import exit
from collections import deque, defaultdict
import hashlib
import threading
import multiprocessing

import scapy.all as scapy
from scapy.packet import Packet

scapy.conf.verb = 0

import tkinter as tk
from tkinter import messagebox

from widget.gui_main import *

from utils.network import *

LAST_UPDATE, VERSION = "2026.03.15", "v1.5"

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
                    __main__()          packet_delay_send()
                   _ _ _ _ _ _   (PIPE)    _ _ _ _ _ _ 
   sniff()        |           |  packets  |           |  
  thread 1  --->  |   parent  |  ------>  |   child   |  sendp()
  thread 2  --->  |  process  |  <----->  |  process  |  ------>  
                  |_ _ _ _ _ _|  sentNum  |_ _ _ _ _ _|
                                  (SM)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

class MainProcess:
    def __init__(self):
        # GUI Elements
        self.widget = MainWidget(self)

        # MainProcess - Sniff Threads
        self.sniff_thread1 = None
        self.sniff_thread2 = None
        self.is_sniffing = False

        # ChildProcess for Delayed Sending
        self.child_process = None
        self.stop_event = multiprocessing.Event()       # Flag for Stopping Child Process
        self.que_to_child = multiprocessing.Queue()     # Queue for Delivering Packet to Child Process

        # Selected Mode
        self.mode_selected = "Routing"

        # IP/MAC Setting
        self.ip1, self.src_mac1, self.dst_mac1 = '', '', ''
        self.ip2, self.src_mac2, self.dst_mac2 = '', '', ''

        # Delay Time Input
        self.delay_time = 0

        # Packet Monitoring
        self.pkt_detect_num  = 0
        self.pkt_process_num = 0
        self.pkt_sent_num    = multiprocessing.Value('i',0)

        # Duplicate Packet Filter
        self.arp_cache = defaultdict(float)
        self.APR_CACHE_TTL = 10   # ARP Cache Time-to-Live

        self.pkt_cache = deque([], maxlen=2000)

        print("ⓒ 2026,LIG Nex1, YoungSuh Lee, All rights reserved.")
        print(f"Last Revision : {VERSION} Distributed on {LAST_UPDATE} ")
        print("\nInit Complete & GUI created!")

    # Start Button Pressed
    def start_sniffing(self) -> bool:
        if self.is_sniffing:
            return False

        self.mode_selected = self.widget.toggle.get_current_mode()

        # IP Address Processing
        self.ip1 = self.widget.ip1_entry.get().replace(" ","")
        self.ip2 = self.widget.ip2_entry.get().replace(" ","")
        print(f'\n[{self.ip1}] <-> [Me] <-> [{self.ip2}]\nFinding MAC Address... ')

        # Find MAC Address by ARP
        iface_selected = self.widget.iface_selected
        self.src_mac1, self.dst_mac1 = get_src_mac(iface_selected[0]), get_dst_mac(iface_selected[0], self.ip1)
        self.src_mac2, self.dst_mac2 = get_src_mac(iface_selected[1]), get_dst_mac(iface_selected[1], self.ip2)
        print(f'[Interface 1] (this) src_mac1 : {self.src_mac1}, (ip1) dst_mac1 : {self.dst_mac1}\n'
              f'[Interface 2] (this) src_mac2 : {self.src_mac2}, (ip2) dst_mac2 : {self.dst_mac2}\n')

        # MAC Address Validation
        if (self.dst_mac1 is None) or (self.dst_mac2 is None):
            messagebox.showerror("Invalid Connection", "Please check the Network Status.")
            print("MAC Address Not Found !!\n")
            return False

        self.delay_time = float(self.widget.delay_entry.get())

        # Packet Monitoring
        self.pkt_detect_num, self.pkt_process_num, self.pkt_sent_num = 0, 0, multiprocessing.Value('i',0)

        # Packet Multiprocessor Run
        if self.child_process is None or not self.child_process.is_alive():
            # Initialize
            self.stop_event.clear()
            self.que_to_child = multiprocessing.Queue()

            gui_infos = (self.que_to_child, self.stop_event, self.delay_time, iface_selected, self.pkt_sent_num)
            self.child_process = multiprocessing.Process(target=packet_delay_send, daemon=True, args=(gui_infos,))
            self.child_process.start()

        # Sniffing Thread
        self.is_sniffing = True
        self.sniff_thread1 = threading.Thread(target=self.sniff_packets, daemon=True, args=(iface_selected[0],))
        self.sniff_thread2 = threading.Thread(target=self.sniff_packets, daemon=True, args=(iface_selected[1],))
        self.sniff_thread1.start()
        self.sniff_thread2.start()
        print(f"Delayed {self.mode_selected} Started! ({datetime.now()})")

        return True

    # Stop Button Pressed
    def stop_sniffing(self) -> None:
        # Stop Sniff Thread
        self.is_sniffing = False
        self.stop_event.set()
        self.send_dummy_packets()
        self.sniff_thread1.join()
        self.sniff_thread2.join()
        print(f"Delayed {self.mode_selected} Stopped! ({datetime.now()})\n")

    # Helps sniff threads to stop right away
    def send_dummy_packets(self) -> None:
        send_dummy_packet(self.widget.iface_selected[0])
        send_dummy_packet(self.widget.iface_selected[1])

    # Function called from Sniff threads
    def sniff_packets(self, interface: str=None) -> None:
        # Routing
        if self.mode_selected == "Routing":
            bpf_filter = "tcp or udp or icmp"
            promisc_mode = False
        # Bridging
        else:
            bpf_filter = "tcp or udp or icmp or arp"
            promisc_mode = True

        # Sniffing and processing packets
        scapy.sniff(iface=interface, prn=self.packet_callback, store=False, promisc=promisc_mode,
                    filter=bpf_filter, stop_filter=lambda p: not self.is_sniffing)

    # Check if same ARP has been sent recently
    def arp_cached(self, packet: Packet) -> bool:
        # Packet Hash Value Save
        arp_id = f"{packet.op}{packet.hwsrc}{packet.psrc}{packet.hwdst}{packet.pdst}"
        arp_hash = hashlib.md5(arp_id.encode()).hexdigest()

        # ARP Cache Check TTL
        now = time.time()
        if now - self.arp_cache[arp_hash] > self.APR_CACHE_TTL:
            self.arp_cache[arp_hash] = now
            return False
        else:
            return True

    def pkt_cached(self, packet: Packet, pkt_chksum) -> bool:
        # Not to resend duplicate packet
        if (packet[IP].chksum, pkt_chksum) in self.pkt_cache:
            return True
        self.pkt_cache.append((packet[IP].chksum, pkt_chksum))
        return False

    # Function called from sniff_packets function
    def packet_callback(self, packet: Packet) -> None:
        # Record start time of parsing
        parse_start_time = time.time()

        # Ethernet Packet Process
        if not packet.haslayer(Ether):
            return

        # L2 Packets (ARP)
        if packet.haslayer(ARP) and self.mode_selected == "Bridging":
            # Check if this arp is recently sent
            if self.arp_cached(packet):
                return

            if self.widget.print_flag.get():
                print(f"[Detected] ARP {'Request' if packet.op==1 else 'Reply'} {packet.psrc} -> {packet.pdst} ",
                      flush=True)

        # L3 Packets (TCP, UDP, UDP-segments, ICMP)
        elif packet.haslayer(IP):
            if   packet.haslayer(TCP):  pkt_chksum = packet[TCP].chksum;  pkt_protocol = "TCP"
            elif packet.haslayer(UDP):  pkt_chksum = packet[UDP].chksum;  pkt_protocol = "UDP"
            elif packet[IP].proto==17:  pkt_chksum = packet[IP].frag   ;  pkt_protocol = "UDP-seg"
            elif packet.haslayer(ICMP): pkt_chksum = packet[ICMP].chksum; pkt_protocol = "ICMP"
            else:
                return

            if self.pkt_cached(packet, pkt_chksum):
                return

            # Route MAC Address & IP Filtering
            pkt_ip_src, pkt_ip_dst = packet[IP].src, packet[IP].dst
            if pkt_ip_src == self.ip1 and pkt_ip_dst == self.ip2:
                packet[Ether].src = self.src_mac2
                packet[Ether].dst = self.dst_mac2
            elif pkt_ip_src == self.ip2 and pkt_ip_dst == self.ip1:
                packet[Ether].src = self.src_mac1
                packet[Ether].dst = self.dst_mac1
            else:
                return

            if self.widget.print_flag.get():
                print(f"[Detected] {pkt_protocol} {pkt_ip_src} -> {pkt_ip_dst} ")
        else:
            return

        # Sending Packets to Child Process
        self.que_to_child.put((packet, parse_start_time))

        # Packet Monitoring Update
        self.pkt_detect_num += 1
        self.pkt_process_num += 1
        self.widget.pkt_detect_var.set(str(self.pkt_detect_num))
        self.widget.pkt_process_var.set(str(self.pkt_process_num))


if __name__ == "__main__":
    multiprocessing.freeze_support()

    if not scapy.conf.use_pcap:
        messagebox.showerror("Error", "\"Npcap\" is not installed."
                                      "\nPlease install \"Npcap\" with 'Winpcap API-compatible mode'")
        exit(1)

    # Process Priority Elevation
    main_pid = psutil.Process(os.getpid())
    main_pid.nice(psutil.HIGH_PRIORITY_CLASS)

    # Run the GUI application
    app = MainProcess()
    app.widget.root.mainloop()
