import tkinter as tk
from tkinter import ttk, Frame

import scapy.all as scapy

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
    self.root.geometry("610x255")
    self.root.resizable(False, False)

    # ------------------------------------ Frame 1 ------------------------------------- #
    frame1 = tk.Frame(self.root)
    frame1.pack()

    # Network Interface 1
    self.interface_label = tk.Label(frame1, text="Network Interface 1")
    self.interface_label.grid(row=0, column=0, padx=10, pady=10)

    self.interface_combobox1 = ttk.Combobox(frame1, textvariable=self.interface_selected[0], width=60)
    self.interface_combobox1.grid(row=0, column=1, padx=10, pady=10)

    # Network Interface 2
    self.interface_label2 = tk.Label(frame1, text="Network Interface 2")
    self.interface_label2.grid(row=1, column=0, padx=10, pady=10)

    self.interface_combobox2 = ttk.Combobox(frame1, textvariable=self.interface_selected[1], width=60)
    self.interface_combobox2.grid(row=1, column=1, padx=10, pady=10)

    # Function Binding
    self.interface_combobox1.bind("<Button-1>", update_interfaces(self, self.interface_combobox1))
    self.interface_combobox1.bind("<<ComboboxSelected>>", lambda event: select_interface(self, 1, event))

    self.interface_combobox2.bind("<Button-1>", update_interfaces(self, self.interface_combobox2))
    self.interface_combobox2.bind("<<ComboboxSelected>>", lambda event: select_interface(self, 2, event))

    # ------------------------------------ Frame 2 ------------------------------------- #
    frame2 = tk.Frame(self.root)
    frame2.pack()

    # IP 1
    self.ip1_label = tk.Label(frame2, text="Enter IP1 Address")
    self.ip1_label.grid(row=0, column=0, padx=10, pady=10)

    self.ip1_entry = tk.Entry(frame2, justify="center")
    self.ip1_entry.grid(row=0, column=1, padx=10, pady=10)
    self.ip1_entry.insert(0, DEFAULT_IP_ADDRESS_1)

    # IP 2
    self.ip2_label = tk.Label(frame2, text="Enter IP2 Address")
    self.ip2_label.grid(row=1, column=0, padx=10, pady=10)

    self.ip2_entry = tk.Entry(frame2, justify="center")
    self.ip2_entry.grid(row=1, column=1, padx=10, pady=10)
    self.ip2_entry.insert(0, DEFAULT_IP_ADDRESS_2)

    # Delay Time
    self.delay_label = tk.Label(frame2, text="Delay Time (ms)")
    self.delay_label.grid(row=2, column=0, padx=10, pady=10)

    self.delay_entry = tk.Entry(frame2, justify="center")
    self.delay_entry.grid(row=2, column=1, padx=10, pady=10)
    self.delay_entry.insert(0, "300")

    # Start Button
    self.start_button = tk.Button(frame2, text="Start", command=self.start_sniffing, width=10)
    self.start_button.grid(row=3, column=0, padx=10, pady=10)

    # Stop Button
    self.stop_button = tk.Button(frame2, text="Stop", command=self.stop_sniffing, width=10, state=tk.DISABLED)
    self.stop_button.grid(row=3, column=1, padx=10, pady=10)

    # Detected Packet No.
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
    self.print_checkbox = tk.Checkbutton(frame2, text="Print Log", anchor="e", variable=self.print_flag)
    self.print_checkbox.grid(row=3, column=2, padx=10, pady=10)


# Start Button Pressed
def start_button_pressed(self):
    self.ip1_entry.config(state=tk.DISABLED)
    self.ip2_entry.config(state=tk.DISABLED)
    self.delay_entry.config(state=tk.DISABLED)
    self.start_button.config(state=tk.DISABLED)
    self.stop_button.config(state=tk.NORMAL)
    self.interface_combobox1.config(state=tk.DISABLED)
    self.interface_combobox2.config(state=tk.DISABLED)

# Stop Button Pressed
def stop_button_pressed(self):
    self.ip1_entry.config(state=tk.NORMAL)
    self.ip2_entry.config(state=tk.NORMAL)
    self.delay_entry.config(state=tk.NORMAL)
    self.start_button.config(state=tk.NORMAL)
    self.stop_button.config(state=tk.DISABLED)
    self.interface_combobox1.config(state=tk.NORMAL)
    self.interface_combobox2.config(state=tk.NORMAL)

# ComboBox Opened
def update_interfaces(self, self_combox, event=None):
    self.interfaces = []
    for iface in scapy.conf.ifaces:
        iface_name = iface
        try:
            iface_ds = scapy.conf.ifaces[iface].description
            iface_ip = scapy.conf.ifaces[iface].ip
            if iface_ip.replace(" ","") == "": continue
        except AttributeError: continue
        self.interfaces.append([[iface_ip, iface_ds],iface_name])
    # Update ComboBox List
    self_combox['values'] = list(zip(*self.interfaces))[0]

# ComboBox Selected
def select_interface(self, num, event):
    if num == 1:
        self_if_combobox = self.interface_combobox1
    else:
        self_if_combobox = self.interface_combobox2

    selected_idx = self_if_combobox.current()
    self_if_combobox.set(self_if_combobox['values'][selected_idx])
    self_if_selected = self.interfaces[selected_idx][1]
    self.interface_selected[num-1] = self_if_selected

    print(f"Interface {num} Selected :", self.interfaces[selected_idx][0])
