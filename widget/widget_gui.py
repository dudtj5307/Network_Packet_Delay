import os, sys

import scapy.all as scapy
from scapy.arch import get_windows_if_list

import tkinter as tk
from tkinter import ttk, Frame, messagebox

from widget.toggleSwitch import ToggleSwitch

DEFAULT_IP_ADDRESS_1 = '192.168.110.6'
DEFAULT_IP_ADDRESS_2 = '192.168.111.6'

class LabeledEntry():
    def __init__(self, root):
        self.label = tk.Label(root)
        self.entry = tk.Entry(root, justify="center")

        self.label.grid(row=0, column=0, padx=10, pady=10)
        self.entry.grid(row=0, column=1, padx=10, pady=10)

def create_widgets(self):
    # Window Title
    self.root.title("Delayed Packet Router")
    # Window Size
    self.root.geometry("610x260")
    self.root.resizable(False, False)
    # Icon directory
    icon_path = os.path.join(sys._MEIPASS if getattr(sys, 'frozen', False) else os.getcwd(), 'widget', 'sniff_delay_tool.ico')
    self.root.iconbitmap(icon_path)

    # ------------------------------------ Frame 1 ------------------------------------- #
    frame1 = Frame(self.root)
    frame1.pack()

    self.toggle = ToggleSwitch(frame1, width=70, height=18)
    self.toggle.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    # For temporary implementation
    # self.toggle.disable()      # TBD

    # Network Interface 1
    self.interface_label = tk.Label(frame1, text="Network Interface 1")
    self.interface_label.grid(row=1, column=0, padx=10, pady=5)

    self.interface_combobox1 = ttk.Combobox(frame1, textvariable=self.selected_interface[0], width=60, state="readonly")
    self.interface_combobox1.grid(row=1, column=1, padx=10, pady=5)

    # Network Interface 2
    self.interface_label2 = tk.Label(frame1, text="Network Interface 2")
    self.interface_label2.grid(row=2, column=0, padx=10, pady=7)

    self.interface_combobox2 = ttk.Combobox(frame1, textvariable=self.selected_interface[1], width=60, state="readonly")
    self.interface_combobox2.grid(row=2, column=1, padx=10, pady=7)

    # Function Binding
    self.interface_combobox1.bind("<Button-1>", lambda event: update_interfaces(self, self.interface_combobox1))
    self.interface_combobox1.bind("<<ComboboxSelected>>", lambda event: select_interface(self, 1, event))

    self.interface_combobox2.bind("<Button-1>", lambda event: update_interfaces(self, self.interface_combobox2))
    self.interface_combobox2.bind("<<ComboboxSelected>>", lambda event: select_interface(self, 2, event))

    # ------------------------------------ Frame 2 ------------------------------------- #
    frame2 = Frame(self.root)
    frame2.pack()

    # IP 1
    self.ip1_label = tk.Label(frame2, text="Enter IP1 Address")
    self.ip1_label.grid(row=0, column=0, padx=10, pady=7)

    self.ip1_entry = tk.Entry(frame2, justify="center")
    self.ip1_entry.grid(row=0, column=1, padx=10, pady=7)
    self.ip1_entry.insert(0, DEFAULT_IP_ADDRESS_1)

    # IP 2
    self.ip2_label = tk.Label(frame2, text="Enter IP2 Address")
    self.ip2_label.grid(row=1, column=0, padx=10, pady=7)

    self.ip2_entry = tk.Entry(frame2, justify="center")
    self.ip2_entry.grid(row=1, column=1, padx=10, pady=7)
    self.ip2_entry.insert(0, DEFAULT_IP_ADDRESS_2)

    # Delay Time
    self.delay_label = tk.Label(frame2, text="Delay Time (ms)")
    self.delay_label.grid(row=2, column=0, padx=10, pady=7)

    self.delay_entry = tk.Entry(frame2, justify="center")
    self.delay_entry.grid(row=2, column=1, padx=10, pady=7)
    self.delay_entry.insert(0, "300")

    # Start Button
    self.start_button = tk.Button(frame2, text="Start", command=self.start_sniffing, width=10)
    self.start_button.grid(row=3, column=0, padx=10, pady=10)

    # Stop Button
    self.stop_button = tk.Button(frame2, text="Stop", command=self.stop_sniffing, width=10, state=tk.DISABLED)
    self.stop_button.grid(row=3, column=1, padx=10, pady=10)

    # Detected Packet No.
    self.pkt_detect_label = tk.Label(frame2, text="Detected Count")
    self.pkt_detect_label.grid(row=0, column=2, padx=10, pady=7)

    self.pkt_detect_entry = tk.Entry(frame2, justify="center", state="readonly", textvariable=self.pkt_detect_var)
    self.pkt_detect_entry.grid(row=0, column=3, padx=10, pady=7)

    # Processing Packet No.
    self.pkt_process_label = tk.Label(frame2, text="Processing Count")
    self.pkt_process_label.grid(row=1, column=2, padx=10, pady=7)

    self.pkt_process_entry = tk.Entry(frame2, justify="center", state="readonly", textvariable=self.pkt_process_var)
    self.pkt_process_entry.grid(row=1, column=3, padx=10, pady=7)

    # Sent Packet No.
    self.pkt_sent_label = tk.Label(frame2, text="Sent Count")
    self.pkt_sent_label.grid(row=2, column=2, padx=10, pady=7)

    self.pkt_sent_entry = tk.Entry(frame2, justify="center", state="readonly", textvariable=self.pkt_sent_var)
    self.pkt_sent_entry.grid(row=2, column=3, padx=10, pady=7)

    # Print Packets Checkbox
    self.print_checkbox = tk.Checkbutton(frame2, text="Print Log", anchor="e", variable=self.print_flag)
    self.print_checkbox.grid(row=3, column=2, padx=10, pady=10)

def invalid_ip(ip_str):
    ips = ip_str.strip().split('.')
    if len(ips) != 4: return True
    for ip in ips:
        if not ip.isdigit(): return True
        if int(ip) < 0 or int(ip) > 255: return True
    return False

# Input Validation
def check_input_validation(self):
    try:
        # Check Validation - Interface Selecting Box
        if "" in self.selected_interface:
            raise ValueError("InterfaceError")
        # Check Validation - IP Address Format
        if invalid_ip(self.ip1_entry.get()) or invalid_ip(self.ip2_entry.get()):
            raise ValueError("IPAddressError")
        # Check Validation - Delay Time Input
        self.delay_time = float(self.delay_entry.get())
        if self.delay_time < 0:
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

# Start Button Pressed
def start_button_pressed(self):
    self.ip1_entry.config(state=tk.DISABLED)
    self.ip2_entry.config(state=tk.DISABLED)
    self.delay_entry.config(state=tk.DISABLED)
    self.start_button.config(state=tk.DISABLED)
    self.stop_button.config(state=tk.NORMAL)
    self.interface_combobox1.config(state=tk.DISABLED)
    self.interface_combobox2.config(state=tk.DISABLED)
    # Packet Counter Reset
    self.pkt_detect_num, self.pkt_process_num, self.pkt_sent_num = 0, 0, 0
    self.pkt_detect_var.set(str(self.pkt_detect_num))
    self.pkt_process_var.set(str(self.pkt_process_num))
    self.pkt_sent_var.set(str(self.pkt_sent_num))
    # Toggle Button Disable
    self.toggle.disable()

# Stop Button Pressed
def stop_button_pressed(self):
    self.ip1_entry.config(state=tk.NORMAL)
    self.ip2_entry.config(state=tk.NORMAL)
    self.delay_entry.config(state=tk.NORMAL)
    self.start_button.config(state=tk.NORMAL)
    self.stop_button.config(state=tk.DISABLED)
    self.interface_combobox1.config(state="readonly")
    self.interface_combobox2.config(state="readonly")
    # Toggle Button Enable
    self.toggle.enable()

# ComboBox Opened
def update_interfaces2(self, self_combox, event=None):
    # Update Network Interface
    self.interfaces = []
    for iface in scapy.conf.ifaces:
        iface_name = iface
        print(iface_name)
        try:
            iface_ip = scapy.conf.ifaces[iface].ip
            iface_ds = scapy.conf.ifaces[iface].description
            if iface_ip.replace(" ","") == "": continue
        except AttributeError: continue
        self.interfaces.append([[iface_ip, iface_ds],iface_name])
    # Update ComboBox List
    self_combox['values'] = list(zip(*self.interfaces))[0]


# ComboBox Opened
def update_interfaces(self, self_combox, event=None):
    # Update Network Interface
    self.interfaces = []
    for iface in get_windows_if_list():
        if len(iface['ips']) == 0:              continue
        if "loopback" in iface['name'].lower(): continue

        iface_name        = f"{iface['name']}"
        iface_description = f"{iface['name']} {iface['description']}"
        for ip in iface['ips']:
            if(all(map(lambda x: x.isdecimal(), ip.split('.')))):
                iface_ip = ip
                self.interfaces.append([[iface_ip, iface_description], iface_name])

    # Update ComboBox List
    self_combox['values'] = list(zip(*self.interfaces))[0]

# ComboBox Selected
def select_interface(self, num, event):
    if num == 1: self_if_combobox = self.interface_combobox1
    else:        self_if_combobox = self.interface_combobox2

    selected_idx = self_if_combobox.current()
    self_if_combobox.set(self_if_combobox['values'][selected_idx])
    self_if_selected = self.interfaces[selected_idx][1]
    self.selected_interface[num-1] = self_if_selected

    print(f"Interface {num} Selected :", self.interfaces[selected_idx][0])

# Sent Packet Number Update
def pkt_sent_update(self):
    if self.stop_event.is_set(): return

    # Get Sent Count from Multiprocess Queue
    count = 0
    try:
        while True:
            count += self.q_sentNum_to_parent.get_nowait()
    except Exception: pass

    # Update Packet Monitoring
    self.pkt_process_num -= count
    self.pkt_process_var.set(self.pkt_process_num)
    self.pkt_sent_num += count
    self.pkt_sent_var.set(self.pkt_sent_num)
    return self.root.after(100, pkt_sent_update, self)