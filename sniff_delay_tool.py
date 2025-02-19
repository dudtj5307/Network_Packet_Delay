import time
from sys import exit
from collections import deque, OrderedDict
import hashlib
import threading
import multiprocessing as mp

import scapy.all as scapy

import tkinter as tk
from tkinter import messagebox

from widget import widget_gui

Ether, IP, TCP, UDP, ICMP, ARP = scapy.Ether, scapy.IP, scapy.TCP, scapy.UDP, scapy.ICMP, scapy.ARP
IP_FLAG_MF = 1     # [IP] Flag : More Fragments (0 0 1)

def get_src_mac(dst_ip):
    # 대상 IP로 가는 경로의 인터페이스를 가져옴
    interface = scapy.conf.route.route(dst_ip)[0]
    return scapy.get_if_hwaddr(interface)

def get_dst_mac(ip):
    try:
        ans, _ = scapy.arping(ip, timeout=2, verbose=False)
        for sent, received in ans:
            return received.hwsrc
        print(f"Could not find MAC Address for {ip}")
        return None
    except Exception as e:
        print(f"Can't send ARP for {ip}. Exception : {e}")
        return None


def packet_multiprocessor(mp_que, stop_event, infos):
    scapy.conf.verb = 0
    # Information from Main Thread
    delay_ms, selected_interface, sent_que = infos

    # Delay time calculation with compensation
    delay = float(delay_ms) / 1000  # ms -> 초로 변환

    # Deque for saving (packet, start time)
    packets_deque = deque()
    while not stop_event.is_set():
        # Get Packets from mp_queue
        try:
            recvCount = 0
            while True and recvCount < 5:
                # pkt, start_time = mp_que.get_nowait()
                packets_deque.append(mp_que.get_nowait())
                recvCount += 1
        except Exception:
            pass
        # Send packet after delay time
        sentCount = 0
        while packets_deque and sentCount < 5:
            pkt, start_time = packets_deque[0]
            if time.time() - start_time >= delay:
                # Send Packets by Ethernet (Layer 2)
                if pkt.sniffed_on == selected_interface[0]: scapy.sendp(pkt, iface=selected_interface[1]);
                if pkt.sniffed_on == selected_interface[1]: scapy.sendp(pkt, iface=selected_interface[0]);
                packets_deque.popleft()
                sentCount += 1
            else:
                break
        if sentCount > 0:
            sent_que.put(sentCount)
        time.sleep(0.00001)


class SniffingApp:
    def __init__(self, root):
        self.root = root

        self.sniff_thread1 = None
        self.sniff_thread2 = None
        self.is_sniffing = False

        # Multiprocessing for Delayed Sending
        self.process = None
        self.stop_event = mp.Event()
        self.mp_queue = mp.Queue()
        self.sent_queue = mp.Queue()

        # Selected Mode
        self.mode_selected = "Routing"

        # Selected Interface Name 1 & 2
        self.selected_interface = ["", ""]

        # IP Setting for analysis
        self.ip1, self.ip2 = '', ''
        self.src_mac1, self.src_mac2 = '', ''
        self.dst_mac1, self.dst_mac2 = '', ''

        # Delay Time Setting
        self.delay_time = 0

        # Packet Monitoring
        self.pkt_detect_num, self.pkt_process_num, self.pkt_sent_num = 0, 0, 0
        self.pkt_detect_var, self.pkt_process_var, self.pkt_sent_var = tk.StringVar(), tk.StringVar(), tk.StringVar()

        self.pkt_detect_var.set(str(self.pkt_detect_num))
        self.pkt_process_var.set(str(self.pkt_process_num))
        self.pkt_sent_var.set(str(self.pkt_sent_num))

        # Duplicate Packet Filter
        self.pkt_id_que = deque([], maxlen=2000)
        self.arp_cache = OrderedDict()
        self.arp_ttl = 10               # Time-to-Live

        # Flag for printing packets
        self.print_flag = tk.BooleanVar()
        self.print_flag.set(False)
        scapy.conf.verb = 0

        # GUI Elements
        widget_gui.create_widgets(self)

        print("ⓒ 2025,LIG Nex1-YoungSuh Lee,All rights reserved.")
        print("Last Revision : 2025.02.19 Distribution version 1.3")
        print("\nInit Complete & GUI created!")

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

            # Find MAC Address by processing ARP
            self.src_mac1, self.src_mac2 = get_src_mac(self.ip1), get_src_mac(self.ip2)
            self.dst_mac1, self.dst_mac2 = get_dst_mac(self.ip1), get_dst_mac(self.ip2)
            print(f'[Interface 1] (this) src_mac1 : {self.src_mac1}, (ip1) dst_mac1 : {self.dst_mac1}\n'
                  f'[Interface 2] (this) src_mac2 : {self.src_mac2}, (ip2) dst_mac2 : {self.dst_mac2}\n')
            if (self.dst_mac2 is None) or (self.dst_mac2 is None):
                messagebox.showerror("Invalid Connection", "Please check the Network Status.")
                print("MAC Address Not Found !!\n")
                return

            # Packet Multiprocessor
            if self.process is None or not self.process.is_alive():
                # Initialize
                self.stop_event.clear()
                self.mp_queue = mp.Queue()
                self.sent_queue = mp.Queue()

                gui_infos = (self.delay_time, self.selected_interface, self.sent_queue)
                self.process = mp.Process(target=packet_multiprocessor,
                                          args=(self.mp_queue, self.stop_event, gui_infos), daemon=True)
                self.process.start()

                # Sent Packet from Multiprocessor
                self.update_id = widget_gui.pkt_sent_update(self)

            # Sniffing Thread
            self.is_sniffing = True
            self.sniff_thread1 = threading.Thread(target=self.sniff_packets, daemon=True, args=(self.selected_interface[0],))
            self.sniff_thread2 = threading.Thread(target=self.sniff_packets, daemon=True, args=(self.selected_interface[1],))
            self.sniff_thread1.start()
            self.sniff_thread2.start()

            # 입력칸/버튼 활성화, 비활성화
            widget_gui.start_button_pressed(self)

            print(f"{self.mode_selected} Started!")

    def stop_sniffing(self):
        self.is_sniffing = False

        if self.process and self.process.is_alive():
            self.stop_event.set()  # 이벤트 플래그를 세워 프로세스에게 종료 신호 전달
            time.sleep(0.2)
            self.process.terminate()

            self.root.after_cancel(self.update_id)

        # 입력칸/버튼 활성화, 비활성화
        widget_gui.stop_button_pressed(self)

        print("Sniffing & Delaying Stopped!\n")

    def sniff_packets(self, interface=None):
        # Routing
        if self.mode_selected == "Routing":
            bpf_filter = "tcp or udp or icmp"
            packet_callback = self.packet_routing
            promisc_mode = False
        # Bridging
        else:
            bpf_filter = "tcp or udp or icmp or arp"
            packet_callback = self.packet_bridging
            promisc_mode = True

        # Sniffing and processing packets
        scapy.sniff(iface=interface, prn=packet_callback, store=False,
                    filter=bpf_filter, stop_filter=lambda p: not self.is_sniffing, promisc=promisc_mode)

    def packet_bridging(self, packet):
        # ARP Packets
        if packet.haslayer(ARP):

            # For compensating time delay
            parse_start_time = time.time()

            # Packet Hash Save
            arp_id = f"{packet.op}{packet.hwsrc}{packet.psrc}{packet.hwdst}{packet.pdst}"
            arp_hash = hashlib.md5(arp_id.encode()).hexdigest()

            # ARP Cache TTL Check
            now = time.time()
            for key in list(self.arp_cache.keys()):
                if now - self.arp_cache[key] > self.arp_ttl:
                    del self.arp_cache[key]
            if arp_hash in self.arp_cache:
                return
            self.arp_cache[arp_hash] = now

            self.pkt_detect_num += 1
            self.pkt_detect_var.set(self.pkt_detect_num)

            if (self.print_flag.get()):
                print(f"[Detected] ARP {packet.psrc} -> {packet.pdst} {'Request' if packet.op==1 else 'Reply'}")

            # Handover to Packet Multiprocessor
            self.mp_queue.put((packet, parse_start_time))
            self.pkt_process_num += 1
            self.pkt_process_var.set(self.pkt_process_num)

        # TCP/UDP/ICMP Packet - send without changing MAC Address
        else:
            self.packet_routing(packet, change_MAC=False)


    def packet_routing(self, packet, change_MAC=True):
        if (not packet.haslayer(Ether)) or (not packet.haslayer(IP)):
            return
        if   packet.haslayer(TCP):  pkt_chksum = packet[TCP].chksum;  pkt_protocol = "TCP"
        elif packet.haslayer(UDP):  pkt_chksum = packet[UDP].chksum;  pkt_protocol = "UDP"
        elif packet[IP].proto==17:  pkt_chksum = packet[IP].frag   ;  pkt_protocol = "UDP-seg"
        elif packet.haslayer(ICMP): pkt_chksum = packet[ICMP].chksum; pkt_protocol = "ICMP"
        else:
            return

        # For compensating time delay
        parse_start_time = time.time()

        # Not to resend duplicate packet
        if (packet[IP].chksum, pkt_chksum) in self.pkt_id_que:
            return
        self.pkt_id_que.append((packet[IP].chksum, pkt_chksum))

        # IP src/dst parsing
        pkt_ip1, pkt_ip2 = packet[IP].src, packet[IP].dst
        # if (self.print_flag.get()):
        #     s1, s2 = pkt_ip1.split('.'), pkt_ip2.split('.')
        #     print(f"Packet {s1[0]:>3}.{s1[1]:>3}.{s1[2]:>3}.{s1[3]:>3} > "
        #                             f"{s2[0]:>3}.{s2[1]:>3}.{s2[2]:>3}.{s2[3]:>3}")

        # Packet Processing for Target IPs
        if (pkt_ip1, pkt_ip2) in [(self.ip1, self.ip2), (self.ip2, self.ip1)]:
            self.pkt_detect_num += 1
            self.pkt_detect_var.set(self.pkt_detect_num)

            if (self.print_flag.get()):
                print(f"[Detected] {pkt_protocol} {pkt_ip1} -> {pkt_ip2}")

            # Route MAC Address
            if change_MAC:
                if packet[IP].dst == self.ip1:
                    packet[Ether].src = self.src_mac1
                    packet[Ether].dst = self.dst_mac1
                elif packet[IP].dst == self.ip2:
                    packet[Ether].src = self.src_mac2
                    packet[Ether].dst = self.dst_mac2

            # Handover to Packet Multiprocessor
            self.mp_queue.put((packet, parse_start_time))
            self.pkt_process_num += 1
            self.pkt_process_var.set(self.pkt_process_num)


# Closing App
def app_closing():
    app.stop_sniffing()  # 모든 Task 취소
    root.destroy()

if __name__ == "__main__":
    mp.freeze_support()
    root = tk.Tk()
    root.title("Packet Sniffer")
    root.protocol("WM_DELETE_WINDOW", app_closing)

    app = SniffingApp(root)

    if not scapy.conf.use_pcap:
        messagebox.showerror("Error", "\"Npcap\" is not installed."
                                      "\nPlease install \"Npcap\" with 'Winpcap API-compatible mode'")
        exit(1)

    # Run the GUI application
    root.mainloop()
