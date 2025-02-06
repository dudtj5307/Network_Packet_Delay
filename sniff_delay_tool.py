import scapy.all as scapy
import asyncio
import threading
import tkinter as tk
from tkinter import messagebox
import hashlib
import widget_gui


class SniffingApp:
    def __init__(self, root):
        self.root = root
        self.task_list = []

        self.sniff_thread = None
        self.is_sniffing = False

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)  # 이벤트 루프 설정

        # Network Interface 저장 변수
        self.interfaces = tk.StringVar()
        self.selected_if = [('all interfaces','')]

        # Delay Time Setting
        self.delay_time = 0

        # IP Setting for analysis
        self.ip1, self.ip2 = '', ''

        # Packet Monitoring
        self.pkt_detect_num = 0
        self.pkt_process_num = 0
        self.pkt_sent_num = 0
        self.last_pkt_hash = ""

        # Flag for printing packets
        self.print_flag = tk.BooleanVar()
        self.print_flag.set(False)

        # GUI Elements
        widget_gui.create_widgets(self)

        # Network Interface Update
        # self.update_interfaces()
        # if self.interfaces:
        #     self.interface_combobox.current(0)

        print("\nInit Complete & GUI created!")

    def sniff_packets(self):
        # Sniffing and processing packets
        scapy.sniff(iface=self.selected_if,prn=self.packet_callback, store=0, stop_filter=lambda p: not self.is_sniffing, promisc=True)

    def packet_callback(self, packet):
        # 패킷 출력
        # print(packet)
        # print(packet.summary())
        pkt_text = packet.summary()
        # 해쉬 중복값 검사
        current_pkt_hash = hashlib.md5(pkt_text.encode()).hexdigest()
        if current_pkt_hash == self.last_pkt_hash:
            return
        self.last_pkt_hash = current_pkt_hash

        # Protocol(TCP/UDP), IP, Port Parsing
        if ("Ether / IP /" in pkt_text) and (">" in pkt_text) and (":" in pkt_text):
            pkt_text_list = pkt_text.split(" ")
            if len(pkt_text_list) < 8: return
            pkt_protocol = pkt_text_list[4]
            try:
                # IP:Port 형식인지 확인
                pkt_ip1, pkt_port1 = pkt_text_list[5].split(":") if ":" in pkt_text_list[5] else (pkt_text_list[5], None)
                pkt_ip2, pkt_port2 = pkt_text_list[7].split(":") if ":" in pkt_text_list[7] else (pkt_text_list[7], None)
            except ValueError:
                print("Error parsing packet:", pkt_text)
                return

            # Printing all detected packets
            if (self.print_flag.get()):
                s1, s2 = pkt_ip1.split('.'), pkt_ip2.split('.')
                # print(f"Packet {pkt_ip1} -> {pkt_ip2} detected!")
                print(f"Packet {s1[0]:>3}.{s1[1]:>3}.{s1[2]:>3}.{s1[3]:>3} > "
                             f"{s2[0]:>3}.{s2[1]:>3}.{s2[2]:>3}.{s2[3]:>3} detected!")

            # IP1과 IP2에 대해 각각 패킷을 처리
            if (pkt_ip1, pkt_ip2) in [(self.ip1, self.ip2), (self.ip2, self.ip1)]:
                self.pkt_detect_num += 1
                self.pkt_detect_var.set(self.pkt_detect_num)

                print(f"\n[Processing] {pkt_ip1} -> {pkt_ip2} packet!")
                task = self.loop.run_until_complete(self.send_packet_with_delay(packet))
                self.task_list.append(task)
            else:
                scapy.send(packet, verbose=False)
        else:
            scapy.send(packet, verbose=False)

    async def send_packet_with_delay(self, packet):
        self.pkt_process_num += 1
        self.pkt_process_var.set(self.pkt_process_num)

        # 지연 시간 (ms) 후 패킷 전송
        delay = float(self.delay_entry.get()) / 1000  # ms -> 초로 변환
        await asyncio.sleep(delay)  # 비동기적 지연

        # 패킷 보내기 (전송은 스니핑한 패킷을 재전송)
        scapy.send(packet)
        print(f"[Sent] Packet sent after delay!")

        self.pkt_process_num -= 1
        self.pkt_sent_num += 1
        self.pkt_process_var.set(self.pkt_process_num)
        self.pkt_sent_var.set(self.pkt_sent_num)


    def start_sniffing(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()

            # 지연 시간 입력 처리
            try:
                self.delay_time = float(self.delay_entry.get())
                if self.delay_time <= 0:
                    raise ValueError("Delay time must be a positive number.")
            except ValueError:
                messagebox.showerror("Invalid Input", "Please enter a valid delay time in ms.")
                self.stop_sniffing()

            # IP 주소 입력 처리
            self.ip1 = self.ip1_entry.get()
            self.ip2 = self.ip2_entry.get()

            # 입력칸/버튼 활성화, 비활성화
            widget_gui.start_button_pressed(self)

            # 비동기 이벤트 루프를 계속 실행
            self.loop.create_task(self.run_sniffing())
            print("\nSniffing & Delaying Started!")

    def stop_sniffing(self):
        self.is_sniffing = False
        # if self.sniff_thread is not None:
        #     self.sniff_thread.join()  # sniff 스레드가 종료될 때까지 기다리기

        for task in self.task_list:
            if task and not task.done():  # 완료되지 않은 작업만 취소
                task.cancel()
                print(f"Task {task} cancelled.")
        self.task_list = []  # 작업 리스트 초기화

        # 입력칸/버튼 활성화, 비활성화
        widget_gui.stop_button_pressed(self)

        print("Sniffing & Delaying Stopped!")

    async def run_sniffing(self):
        # 패킷 스니핑은 계속해서 돌아가야 하므로 별도의 루프에서 실행
        while self.is_sniffing:
            await asyncio.sleep(0.1)  # 1ms마다 확인

    def update_interfaces(self, event=None):
        # Network Interface Combox Update
        # interfaces = scapy.get_if_list()
        # print(interfaces)

        interfaces = [('all interfaces','')]
        for iface in scapy.conf.ifaces:
            iface_name = iface
            try:
                iface_ip = scapy.conf.ifaces[iface].ip
            except AttributeError:
                iface_ip = "N/A"  # IP 주소를 가져올 수 없는 경우 처리
            interfaces.append((iface_name, iface_ip))

        self.interface_combobox['values'] = interfaces  # ComboBox 목록 업데이트
        self.interfaces = interfaces

    def select_interface(self, event):
        selected_idx = self.interface_combobox.current()
        self.interface_combobox.set(self.interfaces[selected_idx])

        if selected_idx == 0:
            self.selected_if = scapy.get_if_list()
        else:
            self.selected_if = self.interfaces[selected_idx][0]
        print("Interface Selected :", self.selected_if)

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
