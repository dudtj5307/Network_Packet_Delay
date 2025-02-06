import tkinter as tk
from tkinter import ttk, Frame

# DEFAULT_IP_ADDRESS_1 = '10.30.7.66'
# DEFAULT_IP_ADDRESS_2 = '10.30.253.157'
DEFAULT_IP_ADDRESS_1 = '192.168.110.6'
DEFAULT_IP_ADDRESS_2 = '192.168.111.6'

class LabeledEntry():
    def __init__(self, root):
        self.label = tk.Label(root)
        self.entry = tk.Entry(root, justify="center")

        self.label.grid(row=0, column=0, padx=10, pady=10)
        self.entry.grid(row=0, column=1, padx=10, pady=10)



def create_widgets(self):
    # 창 제목
    self.root.title("Packet Sniffer with Delay")
    # 기본 창 크기 설정
    self.root.geometry("600x220")
    self.root.resizable(False, False)

    # ------------------------------------ Frame 1 ------------------------------------- #
    frame1 = tk.Frame(self.root)
    frame1.pack()

    self.interface_label = tk.Label(frame1, text="Network Interface")
    self.interface_label.grid(row=0, column=0, padx=10, pady=10)

    # Network Interface ComboBox
    self.interface_combobox = ttk.Combobox(frame1, textvariable=self.interfaces, width=58)
    # self.interface_combobox.pack(padx=10, pady=10)
    self.interface_combobox.grid(row=0, column=1, padx=10, pady=10)

    self.interface_combobox.bind("<Button-1>", self.update_interfaces)
    self.interface_combobox.bind("<<ComboboxSelected>>", self.select_interface)

    # ------------------------------------ Frame 2 ------------------------------------- #
    frame2 = tk.Frame(self.root)
    frame2.pack()

    # IP1 입력란
    self.ip1_label = tk.Label(frame2, text="Enter IP1 Address")
    self.ip1_label.grid(row=0, column=0, padx=10, pady=10)

    self.ip1_entry = tk.Entry(frame2, justify="center")
    self.ip1_entry.grid(row=0, column=1, padx=10, pady=10)
    self.ip1_entry.insert(0, DEFAULT_IP_ADDRESS_1)

    # IP2 입력란
    self.ip2_label = tk.Label(frame2, text="Enter IP2 Address")
    self.ip2_label.grid(row=1, column=0, padx=10, pady=10)

    self.ip2_entry = tk.Entry(frame2, justify="center")
    self.ip2_entry.grid(row=1, column=1, padx=10, pady=10)
    self.ip2_entry.insert(0, DEFAULT_IP_ADDRESS_2)

    # Delay Time 입력란
    self.delay_label = tk.Label(frame2, text="Delay Time (ms):")
    self.delay_label.grid(row=2, column=0, padx=10, pady=10)

    self.delay_entry = tk.Entry(frame2, justify="center")
    self.delay_entry.grid(row=2, column=1, padx=10, pady=10)
    self.delay_entry.insert(0, "300")

    # Start 버튼
    self.start_button = tk.Button(frame2, text="Start", command=self.start_sniffing, width=10)
    self.start_button.grid(row=3, column=0, padx=10, pady=10)

    # Stop 버튼
    self.stop_button = tk.Button(frame2, text="Stop", command=self.stop_sniffing, width=10, state=tk.DISABLED)
    self.stop_button.grid(row=3, column=1, padx=10, pady=10)

    # Detected Packet  No.
    self.pkt_detect_label = tk.Label(frame2, text="Detected Count")
    self.pkt_detect_label.grid(row=0, column=2, padx=10, pady=10)

    self.pkt_detect_var = tk.StringVar()
    self.pkt_detect_entry = tk.Entry(frame2, justify="center", state="readonly", textvariable=self.pkt_detect_var)
    self.pkt_detect_entry.grid(row=0, column=3, padx=10, pady=10)

    self.pkt_detect_var.set(self.pkt_detect_num)

    # Processing Packet No.
    self.pkt_process_label = tk.Label(frame2, text="Processing Count")
    self.pkt_process_label.grid(row=1, column=2, padx=10, pady=10)

    self.pkt_process_var = tk.StringVar()
    self.pkt_process_entry = tk.Entry(frame2, justify="center", state="readonly", textvariable=self.pkt_process_var)
    self.pkt_process_entry.grid(row=1, column=3, padx=10, pady=10)

    self.pkt_process_var.set(self.pkt_process_num)

    # Sent Packet No.
    self.pkt_sent_label = tk.Label(frame2, text="Sent Count")
    self.pkt_sent_label.grid(row=2, column=2, padx=10, pady=10)

    self.pkt_sent_var = tk.StringVar()
    self.pkt_sent_entry = tk.Entry(frame2, justify="center", state="readonly", textvariable=self.pkt_sent_var)
    self.pkt_sent_entry.grid(row=2, column=3, padx=10, pady=10)

    self.pkt_sent_var.set(self.pkt_sent_num)

    # Print Packets Checkbox
    self.print_checkbox = tk.Checkbutton(frame2, text="Print Packets", anchor="e", variable=self.print_flag)
    self.print_checkbox.grid(row=3, column=2, padx=10, pady=10)

# 입력칸/버튼 활성화, 비활성화
def start_button_pressed(self):
    self.ip1_entry.config(state=tk.DISABLED)
    self.ip2_entry.config(state=tk.DISABLED)
    self.delay_entry.config(state=tk.DISABLED)
    self.start_button.config(state=tk.DISABLED)
    self.stop_button.config(state=tk.NORMAL)
    self.interface_combobox.config(state=tk.DISABLED)

# 입력칸/버튼 활성화, 비활성화
def stop_button_pressed(self):
    self.ip1_entry.config(state=tk.NORMAL)
    self.ip2_entry.config(state=tk.NORMAL)
    self.delay_entry.config(state=tk.NORMAL)
    self.start_button.config(state=tk.NORMAL)
    self.stop_button.config(state=tk.DISABLED)
    self.interface_combobox.config(state=tk.NORMAL)