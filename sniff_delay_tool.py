import os
import psutil
import time
from sys import exit
from collections import deque, defaultdict
import hashlib
import threading
import multiprocessing

import scapy.all as scapy

import tkinter as tk
from tkinter import messagebox

from widget import widget_gui

LAST_UPDATE, VERSION = "2025.02.25", "v1.4"
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
                    __main__()          packet_delay_send()
                   _ _ _ _ _ _   (PIPE)    _ _ _ _ _ _ 
   sniff()        |           |  packets  |           |  
  thread 1  --->  |   parent  |  ------>  |   child   |  sendp()
  thread 2  --->  |  process  |  <----->  |  process  |  ------>  
                  |_ _ _ _ _ _|  sentNum  |_ _ _ _ _ _|
                                  (SM)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

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


class SniffingApp:
    def __init__(self, root):
        self.root = root

        self.sniff_thread1 = None
        self.sniff_thread2 = None
        self.is_sniffing = False

        # Multiprocessing for Delayed Sending
        self.process = None
        self.stop_event = multiprocessing.Event()       # Flag for Stopping Child Process
        self.q_pkt_to_child = multiprocessing.Queue()   # Queue for Delivering Packet to Child Process

        # Selected Mode
        self.mode_selected = "Routing"

        # Selected Interface Name 1 & 2
        self.iface_selected = ["", ""]

        # IP/MAC Setting
        self.ip1, self.src_mac1, self.dst_mac1 = '', '', ''
        self.ip2, self.src_mac2, self.dst_mac2 = '', '', ''

        # Delay Time Input
        self.delay_time = 0

        # Packet Monitoring
        self.pkt_detect_var,  self.pkt_detect_num   = tk.StringVar(), 0
        self.pkt_process_var, self.pkt_process_num  = tk.StringVar(), 0
        self.pkt_sent_var,    self.pkt_sent_num     = tk.StringVar(), multiprocessing.Value('i',0)

        self.pkt_detect_var.set(str(self.pkt_detect_num))
        self.pkt_process_var.set(str(self.pkt_process_num))
        self.pkt_sent_var.set(str(self.pkt_sent_num.value))

        # GUI Sent Number Periodic Update
        self.update_id = 0

        # Duplicate Packet Filter
        self.pkt_id_que = deque([], maxlen=2000)
        self.arp_cache = defaultdict(float)
        self.arp_ttl = 10   # ARPTime-to-Live

        # Flag for printing packets
        self.print_flag = tk.BooleanVar()
        self.print_flag.set(False)
        scapy.conf.verb = 0

        # GUI Elements
        widget_gui.create_widgets(self)

        print("ⓒ 2025,LIG Nex1-YoungSuh Lee,All rights reserved.")
        print(f"Last Revision : {LAST_UPDATE} Distribution {VERSION}")
        print("\nInit Complete & GUI created!")

    # Start Button Pressed
    def start_sniffing(self):
        if not self.is_sniffing:
            self.mode_selected = self.toggle.get_current_mode()

            # Input Validation
            error = widget_gui.check_input_validation(self)
            if error:
                return

            # IP Address Processing
            self.ip1 = self.ip1_entry.get().replace(" ","")
            self.ip2 = self.ip2_entry.get().replace(" ","")
            print(f'\n[{self.ip1}] <-> [Me] <-> [{self.ip2}]\nFinding MAC Address... ')

            # Find MAC Address by ARP
            self.src_mac1, self.dst_mac1 = get_src_mac(self.iface_selected[0]), get_dst_mac(self.iface_selected[0], self.ip1)
            self.src_mac2, self.dst_mac2 = get_src_mac(self.iface_selected[1]), get_dst_mac(self.iface_selected[1], self.ip2)
            print(f'[Interface 1] (this) src_mac1 : {self.src_mac1}, (ip1) dst_mac1 : {self.dst_mac1}\n'
                  f'[Interface 2] (this) src_mac2 : {self.src_mac2}, (ip2) dst_mac2 : {self.dst_mac2}\n')

            # MAC Address Validation
            if (self.dst_mac1 is None) or (self.dst_mac2 is None):
                messagebox.showerror("Invalid Connection", "Please check the Network Status.")
                print("MAC Address Not Found !!\n")
                return

            # Packet Multiprocessor Run
            if self.process is None or not self.process.is_alive():
                # Initialize
                self.stop_event.clear()
                self.q_pkt_to_child = multiprocessing.Queue()

                gui_infos = (self.delay_time, self.iface_selected, self.pkt_sent_num)
                self.process = multiprocessing.Process(target=packet_delay_send, daemon=True,
                                                       args=(self.q_pkt_to_child, self.stop_event, gui_infos))
                self.process.start()

            # Sniffing Thread
            self.is_sniffing = True
            self.sniff_thread1 = threading.Thread(target=self.sniff_packets, daemon=True, args=(self.iface_selected[0],))
            self.sniff_thread2 = threading.Thread(target=self.sniff_packets, daemon=True, args=(self.iface_selected[1],))
            self.sniff_thread1.start()
            self.sniff_thread2.start()

            # [Sent Number Entry] Periodic Update
            self.update_id = widget_gui.pkt_sent_entry_update(self)

            # [Button, Entry] Enable/Disable
            widget_gui.start_button_pressed(self)

            print(f"{self.mode_selected} Started!")

    # Stop Button Pressed
    def stop_sniffing(self):
        # Stop Sniff Thread
        self.is_sniffing = False

        # Stop Child Process
        if self.process and self.process.is_alive():
            self.stop_event.set()
            time.sleep(0.2)
            self.process.terminate()

        # Stop Updating <Sent Number Entry>
        if self.update_id:
            self.root.after_cancel(self.update_id)

        # [Button, Entry] Enable/Disable
        widget_gui.stop_button_pressed(self)

        print("Sniffing & Delaying Stopped!\n")

    # Function called from Sniff threads
    def sniff_packets(self, interface=None):
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
    def arp_recently_sent(self, packet):
        # Packet Hash Value Save
        arp_id = f"{packet.op}{packet.hwsrc}{packet.psrc}{packet.hwdst}{packet.pdst}"
        arp_hash = hashlib.md5(arp_id.encode()).hexdigest()

        # ARP Cache TTL Check
        now = time.time()
        if now - self.arp_cache[arp_hash] > self.arp_ttl:
            self.arp_cache[arp_hash] = now
            return False
        else:
            return True

    # Function called from sniff_packets function
    def packet_callback(self, packet):
        # Ethernet Packet Process
        if not packet.haslayer(Ether):
            return

        # L2 Packets (ARP)
        if packet.haslayer(ARP) and self.mode_selected == "Bridging":
            # Record start time of parsing
            parse_start_time = time.time()

            # Check if this arp is recently sent
            if self.arp_recently_sent(packet):
                return
            pkt_protocol = "ARP"

            if self.print_flag.get():
                print(f"[Detected] {pkt_protocol} {packet.psrc} -> {packet.pdst} "
                      f"{'Request' if packet.op==1 else 'Reply'}  ", flush=True)

        # L3 Packets (TCP, UDP, UDP-segments, ICMP)
        elif packet.haslayer(IP):
            if   packet.haslayer(TCP):  pkt_chksum = packet[TCP].chksum;  pkt_protocol = "TCP"
            elif packet.haslayer(UDP):  pkt_chksum = packet[UDP].chksum;  pkt_protocol = "UDP"
            elif packet[IP].proto==17:  pkt_chksum = packet[IP].frag   ;  pkt_protocol = "UDP-seg"
            elif packet.haslayer(ICMP): pkt_chksum = packet[ICMP].chksum; pkt_protocol = "ICMP"
            else:
                return
            # Record start time of parsing
            parse_start_time = time.time()

            # Not to resend duplicate packet
            if (packet[IP].chksum, pkt_chksum) in self.pkt_id_que:
                return
            self.pkt_id_que.append((packet[IP].chksum, pkt_chksum))

            # Packet IP filtering
            pkt_ip1, pkt_ip2 = packet[IP].src, packet[IP].dst
            if (pkt_ip1, pkt_ip2) not in [(self.ip1, self.ip2), (self.ip2, self.ip1)]:
                return

            # Route MAC Address
            if packet[IP].dst == self.ip1:
                packet[Ether].src = self.src_mac1
                packet[Ether].dst = self.dst_mac1
            elif packet[IP].dst == self.ip2:
                packet[Ether].src = self.src_mac2
                packet[Ether].dst = self.dst_mac2

            if self.print_flag.get():
                print(f"[Detected] {pkt_protocol} {pkt_ip1} -> {pkt_ip2} ")
        else:
            return

        # Sending Packets to Child Process
        self.q_pkt_to_child.put((packet, parse_start_time))

        # Packet Monitoring Update
        self.pkt_detect_num += 1
        self.pkt_process_num += 1
        self.pkt_detect_var.set(str(self.pkt_detect_num))
        self.pkt_process_var.set(str(self.pkt_detect_num))


# Called when closing 'SniffingApp'
def app_closing():
    app.stop_sniffing()
    root.destroy()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = SniffingApp(root)
    # Window Title
    root.title(f"Delayed Packet Router {VERSION}")

    root.protocol("WM_DELETE_WINDOW", app_closing)


    if not scapy.conf.use_pcap:
        messagebox.showerror("Error", "\"Npcap\" is not installed."
                                      "\nPlease install \"Npcap\" with 'Winpcap API-compatible mode'")
        exit(1)

    # Process Priority Elevation
    main_pid = psutil.Process(os.getpid())
    main_pid.nice(psutil.HIGH_PRIORITY_CLASS)

    # Run the GUI application
    root.mainloop()
