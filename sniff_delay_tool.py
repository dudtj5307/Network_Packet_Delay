import scapy.all as scapy
import asyncio
import threading
import tkinter as tk
from tkinter import messagebox
import time
from collections import deque

import widget_gui
from sys import exit

Ether, IP, TCP, UDP, ICMP = scapy.Ether, scapy.IP, scapy.TCP, scapy.UDP, scapy.ICMP

class SniffingApp:
    def __init__(self, root):
        self.root = root
        # self.task_list = []

        self.sniff_thread = None
        self.is_sniffing = False

        # 이벤트 루프를 별도의 스레드에서 실행하기 위한 설정
        self.loop = None
        self.loop_thread = None

        # Selected Interface Name 1 & 2
        self.interface_selected = ["", ""]

        # IP Setting for analysis
        self.ip1, self.ip2 = '', ''
        self.src_mac1, self.src_mac2 = '', ''
        self.dst_mac1, self.dst_mac2 = '', ''

        # Delay Time Setting
        self.delay_time = 0

        # Packet Monitoring
        self.pkt_detect_num = 0
        self.pkt_process_num = 0
        self.pkt_sent_num = 0
        self.last_pkt_hash = ""
        self.pkt_idq = deque([], maxlen=2000)

        # Flag for printing packets
        self.print_flag = tk.BooleanVar()
        self.print_flag.set(False)
        scapy.conf.verb = 0

        # GUI Elements
        widget_gui.create_widgets(self)

        print("\nInit Complete & GUI created!")

    def start_event_loop(self):
        """이벤트 루프를 별도의 스레드에서 실행"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def start_sniff_packets(self):
        # Sniffing and processing packets
        scapy.sniff(iface=self.interface_selected,prn=self.packet_callback, store=0,
                    stop_filter=lambda p: not self.is_sniffing, promisc=True)

    def packet_callback(self, packet):
        if (not packet.haslayer(Ether)) or (not packet.haslayer(IP)):
            return
        if   packet.haslayer(TCP):  pkt_chksum = packet[TCP].chksum;
        elif packet.haslayer(UDP):  pkt_chksum = packet[UDP].chksum;
        elif packet.haslayer(ICMP): pkt_chksum = packet[ICMP].chksum;
        else:
            return

        # For compensating time delay
        parse_start_time= time.time()

        # Not to resend duplicate packet
        if (packet[IP].id, pkt_chksum) in self.pkt_idq:
            return
        self.pkt_idq.append((packet[IP].id, pkt_chksum))

        # IP src/dst parsing
        pkt_ip1, pkt_ip2 = packet[IP].src, packet[IP].dst
        if (self.print_flag.get()):
            s1, s2 = pkt_ip1.split('.'), pkt_ip2.split('.')
            print(f"Packet {s1[0]:>3}.{s1[1]:>3}.{s1[2]:>3}.{s1[3]:>3} > "
                         f"{s2[0]:>3}.{s2[1]:>3}.{s2[2]:>3}.{s2[3]:>3} detected!")

        # Packet Processing for Target IPs
        if (pkt_ip1, pkt_ip2) in [(self.ip1, self.ip2), (self.ip2, self.ip1)]:
            self.pkt_detect_num += 1
            self.pkt_detect_var.set(self.pkt_detect_num)

            if (self.print_flag.get()):
                print(f"[Processing] {pkt_ip1} -> {pkt_ip2} packet!")

            # Route MAC Address
            if packet[IP].dst == self.ip1:
                packet[Ether].src = self.src_mac1
                packet[Ether].dst = self.dst_mac1
            elif packet[IP].dst == self.ip2:
                packet[Ether].src = self.src_mac2
                packet[Ether].dst = self.dst_mac2

            # Asynchronous Function Run
            if self.loop and self.loop.is_running():
                asyncio.run_coroutine_threadsafe(self.send_packet_with_delay(packet, parse_start_time), self.loop)

    async def send_packet_with_delay(self, packet, start_time):
        self.pkt_process_num += 1
        self.pkt_process_var.set(self.pkt_process_num)

        # Delay time calculation with compensation
        delay = float(self.delay_time) / 1000  # ms -> 초로 변환
        compensation = time.time() - start_time
        compensated_delay = max(0, delay - compensation)
        # Asynchronous Delay
        if compensated_delay != 0:
            await asyncio.sleep(compensated_delay)

        # Send Packets by L2
        if packet[IP].dst == self.ip1: scapy.sendp(packet, iface=self.interface_selected[0])
        if packet[IP].dst == self.ip2: scapy.sendp(packet, iface=self.interface_selected[1])

        if (self.print_flag.get()):
            print(f"[Sent] Packet sent after delay!\n")

        self.pkt_process_num -= 1
        self.pkt_sent_num += 1
        self.pkt_process_var.set(self.pkt_process_num)
        self.pkt_sent_var.set(self.pkt_sent_num)

    def get_src_mac(self, dst_ip):
        # 대상 IP로 가는 경로의 인터페이스를 가져옴
        interface = scapy.conf.route.route(dst_ip)[0]
        return scapy.get_if_hwaddr(interface)

    def get_dst_mac(self, ip):
        try:
            ans, _ = scapy.arping(ip, timeout=2, verbose=False)
            for sent, received in ans:
                return received.hwsrc
            print(f"Could not find MAC Address for {ip}")
            return None
        except Exception as e:
            print(f"Can't send ARP for {ip}. Exception : {e}")
            return None

    def start_sniffing(self):
        if not self.is_sniffing:
            # Verification - Interface Selecting Box
            if "" in self.interface_selected:
                messagebox.showerror("Network Interface Error", "Please select the Network Interface")
                return

            # Verification - Delay Time Input
            try:
                self.delay_time = float(self.delay_entry.get())
                if self.delay_time < 0:
                    raise ValueError("Delay time must be a positive number.")
            except ValueError:
                messagebox.showerror("Delay Time Error", "Please enter a valid delay time in ms.")
                return

            # IP 주소 입력 처리
            self.ip1 = self.ip1_entry.get().replace(" ","")
            self.ip2 = self.ip2_entry.get().replace(" ","")
            print(f'\nFinding MAC Address... \n{self.ip1} <-> Me <-> {self.ip2}')

            # Mac 주소 가져오기
            self.src_mac1, self.src_mac2 = self.get_src_mac(self.ip1), self.get_src_mac(self.ip2)
            self.dst_mac1, self.dst_mac2 = self.get_dst_mac(self.ip1), self.get_dst_mac(self.ip2)

            print(f'[Interface 1] (this) src_mac1 : {self.src_mac1}, (ip1) dst_mac1 : {self.dst_mac1}\n'
                  f'[Interface 2] (this) src_mac2 : {self.src_mac2}, (ip2) dst_mac2 : {self.dst_mac2}\n')
            if (self.dst_mac2 is None) or (self.dst_mac2 is None):
                messagebox.showerror("Invalid Connection", "Please check the Network Status.")
                print("MAC Address Not Found !!\n")
                return

            # 이벤트 루프 스레드 시작
            if self.loop_thread is None:
                self.loop_thread = threading.Thread(target=self.start_event_loop, daemon=True)
                self.loop_thread.start()

            # Sniffing Process 시작
            self.is_sniffing = True
            self.sniff_thread = threading.Thread(target=self.start_sniff_packets, daemon=True)
            self.sniff_thread.start()

            # 입력칸/버튼 활성화, 비활성화
            widget_gui.start_button_pressed(self)

            print("Sniffing & Delaying Started!")

    def stop_sniffing(self):
        self.is_sniffing = False

        # 입력칸/버튼 활성화, 비활성화
        widget_gui.stop_button_pressed(self)

        print("Sniffing & Delaying Stopped!\n")


# App 종료 시 처리
def app_closing():
    app.stop_sniffing()  # 모든 Task 취소
    root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Packet Sniffer")

    root.protocol("WM_DELETE_WINDOW", app_closing)

    app = SniffingApp(root)

    if not scapy.conf.use_pcap:
        messagebox.showerror("오류", "npcap이 설치되어 있지 않습니다.\n프로그램을 실행하려면 npcap 을 설치해야 합니다.")
        exit(1)

    # Run the GUI application
    root.mainloop()
