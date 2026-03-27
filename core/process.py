import multiprocessing
import threading
from datetime import datetime

import scapy.all as scapy
from tkinter import messagebox
scapy.conf.verb = 0

from core.constants import VERSION, LAST_UPDATE
from core.packet_handler import PacketHandler
from core.delay_sender import packet_delay_send
from utils.network import get_src_mac, get_dst_mac, send_dummy_packet
from widget.gui_main import MainWidget


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
        self.pkt_sent_num    = multiprocessing.Value('i', 0)
        self.pkt_sent_bytes  = multiprocessing.Value('q', 0)  # Total bytes sent (for KB/s calc)

        # Packet Handler (duplicate detection + callback)
        self.pkt_handler = PacketHandler(self)

        print("ⓒ 2026,LIG Nex1, YoungSuh Lee, All rights reserved.")
        print(f"Last Revision : {VERSION} Distributed on {LAST_UPDATE} ")
        print("\nInit Complete & GUI created!")

    # Start Button Pressed
    def start_sniffing(self) -> bool:
        if self.is_sniffing:
            return False

        self.mode_selected = self.widget.toggle.get_current_mode()

        # IP Address Processing
        self.ip1 = self.widget.ip1_entry.get().replace(" ", "")
        self.ip2 = self.widget.ip2_entry.get().replace(" ", "")
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

        # Packet Monitoring Reset
        self.pkt_detect_num, self.pkt_process_num = 0, 0
        self.pkt_sent_num   = multiprocessing.Value('i', 0)
        self.pkt_sent_bytes = multiprocessing.Value('q', 0)
        self.pkt_handler.reset()

        # Packet Multiprocessor Run
        if self.child_process is None or not self.child_process.is_alive():
            self.stop_event.clear()
            self.que_to_child = multiprocessing.Queue()

            gui_infos = (self.que_to_child, self.stop_event, self.delay_time, iface_selected,
                         self.pkt_sent_num, self.pkt_sent_bytes)
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
        self.is_sniffing = False
        self.stop_event.set()
        # sendp + join을 별도 스레드에서 수행 → 메인(GUI) 스레드 블로킹 방지
        threading.Thread(target=self._teardown_threads, daemon=True).start()

    def _teardown_threads(self) -> None:
        self._send_dummy_packets()
        self.sniff_thread1.join()
        self.sniff_thread2.join()
        print(f"Delayed {self.mode_selected} Stopped! ({datetime.now()})\n")

    def _send_dummy_packets(self) -> None:
        send_dummy_packet(self.widget.iface_selected[0])
        send_dummy_packet(self.widget.iface_selected[1])

    # Function called from Sniff threads
    def sniff_packets(self, interface: str = None) -> None:
        if self.mode_selected == "Routing":
            bpf_filter = "tcp or udp or icmp"
            promisc_mode = False
        else:
            bpf_filter = "tcp or udp or icmp or arp"
            promisc_mode = True

        scapy.sniff(iface=interface, prn=self.pkt_handler.packet_callback, store=False, promisc=promisc_mode,
                    filter=bpf_filter, stop_filter=lambda p: not self.is_sniffing)
