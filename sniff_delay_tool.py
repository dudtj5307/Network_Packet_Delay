import scapy.all as scapy
import asyncio
import threading
import tkinter as tk
from tkinter import messagebox
import hashlib
import time
from collections import deque

import widget_gui

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

        # Network Interface 저장 변수
        self.interfaces1 = tk.StringVar()
        self.interfaces2 = tk.StringVar()
        self.selected_if = []
        self.selected_if1 = ""
        self.selected_if2 = ""

        # Delay Time Setting
        self.delay_time = 0

        # IP Setting for analysis
        self.ip1, self.ip2 = '', ''
        self.src_mac1, self.src_mac2 = '', ''
        self.dst_mac1, self.dst_mac2 = '', ''

        # Packet Monitoring
        self.pkt_detect_num = 0
        self.pkt_process_num = 0
        self.pkt_sent_num = 0
        self.last_pkt_hash = ""
        self.pkt_idq = deque([], maxlen=2000)

        # Flag for printing packets
        self.print_flag = tk.BooleanVar()
        self.print_flag.set(False)

        # GUI Elements
        widget_gui.create_widgets(self)

        print("\nInit Complete & GUI created!")

    def start_event_loop(self):
        """이벤트 루프를 별도의 스레드에서 실행"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def sniff_packets(self):
        # Sniffing and processing packets
        scapy.sniff(iface=self.selected_if,prn=self.packet_callback, store=0,
                    stop_filter=lambda p: not self.is_sniffing, promisc=True)

    def packet_callback(self, packet):
        if (not packet.haslayer(Ether)) or (not packet.haslayer(IP)):
            return

        pkt_text = packet.summary()
        # 해쉬 중복값 검사
        current_pkt_hash = hashlib.md5(pkt_text.encode()).hexdigest()
        if current_pkt_hash == self.last_pkt_hash:
            return
        self.last_pkt_hash = current_pkt_hash

        if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP)):
            # Not to resend duplicate packet
            if packet[IP].id in self.pkt_idq:
                return
            self.pkt_idq.append(packet[IP].id)

            parse_time_start = time.time()
            try:
                pkt_ip1, pkt_ip2 = packet[IP].src, packet[IP].dst
            except ValueError:
                print("Error parsing packet:", pkt_text)
                return

            # Printing all detected packets
            if (self.print_flag.get()):
                s1, s2 = pkt_ip1.split('.'), pkt_ip2.split('.')
                print(f"Packet {s1[0]:>3}.{s1[1]:>3}.{s1[2]:>3}.{s1[3]:>3} > "
                             f"{s2[0]:>3}.{s2[1]:>3}.{s2[2]:>3}.{s2[3]:>3} detected!")

            # IP1과 IP2에 대해 각각 패킷을 처리
            if (pkt_ip1, pkt_ip2) in [(self.ip1, self.ip2), (self.ip2, self.ip1)]:
                self.pkt_detect_num += 1
                self.pkt_detect_var.set(self.pkt_detect_num)

                if (self.print_flag.get()):
                    print(f"[Processing] {pkt_ip1} -> {pkt_ip2} packet!")
                if self.loop and self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(self.send_packet_with_delay(packet, parse_time_start), self.loop)
            # else:
            #     if self.loop and self.loop.is_running():
            #         asyncio.run_coroutine_threadsafe(self.send_packet_with_delay(packet, parse_time_start), self.loop)

    async def send_packet_with_delay(self, packet, time_start):
        self.pkt_process_num += 1
        self.pkt_process_var.set(self.pkt_process_num)

        if packet[IP].dst == self.ip1:
            packet[Ether].src = self.src_mac1
            packet[Ether].dst = self.dst_mac1
        elif packet[IP].dst == self.ip2:
            packet[Ether].src = self.src_mac2
            packet[Ether].dst = self.dst_mac2

        # 지연 시간 (ms) 후 패킷 전송
        delay = float(self.delay_entry.get()) / 1000  # ms -> 초로 변환
        compensation = time.time() - time_start
        compensated_delay = max(0.001, delay - compensation)
        await asyncio.sleep(compensated_delay)  # 비동기적 지연

        # 패킷 보내기 (전송은 스니핑한 패킷을 재전송)

        if packet[IP].dst == self.ip1:
            scapy.sendp(packet, iface=self.selected_if[0])
        if packet[IP].dst == self.ip2:
            scapy.sendp(packet, iface=self.selected_if[1])
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
        ans, _ = scapy.arping(ip, timeout=2, verbose=False)
        for sent, received in ans:
            return received.hwsrc
        print(f"Could not find MAC Address for {ip}")
        return None

    def start_sniffing(self):
        if not self.is_sniffing:
            # Interface Selecting Box Verification
            if self.selected_if1 == "" or self.selected_if2 == "":
                messagebox.showerror("Network Interface Error", "Please select the Network Interface")
                return

            # 지연 시간 입력 처리
            try:
                self.delay_time = float(self.delay_entry.get())
                if self.delay_time <= 0:
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

            print(f'(this) src_mac1 : {self.src_mac1}, (ip1) dst_mac1 : {self.dst_mac1}\n'
                  f'(this) src_mac2 : {self.src_mac2}, (ip2) dst_mac2 : {self.dst_mac2}\n')
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
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()

            # 입력칸/버튼 활성화, 비활성화
            widget_gui.start_button_pressed(self)

            print("Sniffing & Delaying Started!")

    def stop_sniffing(self):
        self.is_sniffing = False

        # 입력칸/버튼 활성화, 비활성화
        widget_gui.stop_button_pressed(self)

        print("Sniffing & Delaying Stopped!")

    def update_interfaces(self, event=None):
        interfaces1, interfaces2 = [], []
        for iface in scapy.conf.ifaces:
            iface_name = iface
            try:                   iface_ip = scapy.conf.ifaces[iface].ip
            except AttributeError: iface_ip = "N/A"  # IP 주소를 가져올 수 없는 경우 처리
            interfaces1.append((iface_name, iface_ip))
            interfaces2.append((iface_name, iface_ip))
        self.interface_combobox1['values'] = interfaces1  # ComboBox 목록 업데이트
        self.interface_combobox2['values'] = interfaces2  # ComboBox 목록 업데이트
        self.interfaces1 = interfaces1
        self.interfaces2 = interfaces2

    def select_interface1(self, event):
        selected_idx = self.interface_combobox1.current()
        self.interface_combobox1.set(self.interfaces1[selected_idx])
        # if selected_idx == 0: self.selected_if1 = scapy.get_if_list()
        # else:                 self.selected_if1 = self.interfaces2[selected_idx][0]
        self.selected_if1 = self.interfaces2[selected_idx][0]
        print("Interface 1 Selected :", self.selected_if1)
        self.selected_if = [self.selected_if1, self.selected_if2]

    def select_interface2(self, event):
        selected_idx = self.interface_combobox2.current()
        self.interface_combobox2.set(self.interfaces2[selected_idx])
        # if selected_idx == 0: self.selected_if2 = scapy.get_if_list()
        # else:                 self.selected_if2 = self.interfaces2[selected_idx][0]
        self.selected_if2 = self.interfaces2[selected_idx][0]
        print("Interface 2 Selected :", self.selected_if2)
        self.selected_if = [self.selected_if1, self.selected_if2]

# App 종료 시 처리
def app_closing():
    app.stop_sniffing()  # 모든 Task 취소
    root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Packet Sniffer")

    root.protocol("WM_DELETE_WINDOW", app_closing)

    app = SniffingApp(root)

    # Run the GUI application
    root.mainloop()
