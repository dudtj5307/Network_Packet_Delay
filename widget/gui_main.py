import os, sys
import multiprocessing

import scapy.all as scapy
from scapy.arch import get_windows_if_list

import tkinter as tk
from tkinter import ttk, Frame, messagebox

from sniff_delay_tool import VERSION
from widget.gui_switch import ToggleSwitch
from utils.network import *

DEFAULT_IP_ADDRESS_1 = '192.168.45.1'
DEFAULT_IP_ADDRESS_2 = '192.168.45.1'

class MainWidget:
    def __init__(self, parent):
        self.parent = parent

        self.root = tk.Tk()

        # Selected Mode
        self.mode_selected = "Routing"      # Selected Mode

        # Selected Interface
        self.iface_selected = ["", ""]
        self.iface_combobox = [None, None]

        # Packet Monitoring
        self.pkt_detect_var  = tk.StringVar(value="0")
        self.pkt_process_var = tk.StringVar(value="0")
        self.pkt_sent_var    = tk.StringVar(value="0")

        # GUI Sent Number Periodic Update
        self.update_id = 0

        # Flag for printing packets
        self.print_flag = tk.BooleanVar()
        self.print_flag.set(False)

        self.gui_setup()

        # Called when closing 'SniffingApp'
        self.root.protocol("WM_DELETE_WINDOW", self.app_closing)

    def gui_setup(self):
        self.root.title(f"Delayed Packet Router {VERSION}")
        self.root.geometry("610x260")
        self.root.resizable(False, False)
        # Icon Setting
        run_path = sys._MEIPASS if getattr(sys, 'frozen', False) else os.getcwd()
        icon_path = os.path.join(run_path, 'widget', 'sniff_delay_tool.ico')
        self.root.iconbitmap(icon_path)

        # ------------------------------------ Frame 1 ------------------------------------- #
        frame1 = Frame(self.root)
        frame1.pack()

        # Toggle Switch for mode selection
        self.toggle = ToggleSwitch(frame1, width=70, height=18) ;
        self.toggle.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Network Interface 1
        self.iface_label = tk.Label(frame1, text="Network Interface 1")
        self.iface_label.grid(row=1, column=0, padx=10, pady=5)

        self.iface_combobox[0] = ttk.Combobox(frame1, width=60, state="readonly")
        self.iface_combobox[0].grid(row=1, column=1, padx=10, pady=5)

        # Network Interface 2
        self.iface_label2 = tk.Label(frame1, text="Network Interface 2")
        self.iface_label2.grid(row=2, column=0, padx=10, pady=7)

        self.iface_combobox[1] = ttk.Combobox(frame1, width=60, state="readonly")
        self.iface_combobox[1].grid(row=2, column=1, padx=10, pady=7)

        # Function Binding
        self.iface_combobox[0].bind("<Button-1>", lambda event: self.update_interfaces(0))
        self.iface_combobox[0].bind("<<ComboboxSelected>>", lambda event: self.select_interface(0, event))

        self.iface_combobox[1].bind("<Button-1>", lambda event: self.update_interfaces(1))
        self.iface_combobox[1].bind("<<ComboboxSelected>>", lambda event: self.select_interface(1, event))

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
        self.start_button = tk.Button(frame2, text="Start", command=self.start_button_pressed, width=10)
        self.start_button.grid(row=3, column=0, padx=10, pady=10)

        # Stop Button
        self.stop_button = tk.Button(frame2, text="Stop", command=self.stop_button_pressed, width=10, state=tk.DISABLED)
        self.stop_button.grid(row=3, column=1, padx=10, pady=10)

        # Detected Packet No.
        self.pkt_detect_label = tk.Label(frame2, text="Detected Packets")
        self.pkt_detect_label.grid(row=0, column=2, padx=10, pady=7)

        self.pkt_detect_entry = tk.Entry(frame2, justify="center", state="readonly", textvariable=self.pkt_detect_var)
        self.pkt_detect_entry.grid(row=0, column=3, padx=10, pady=7)

        # Processing Packet No.
        self.pkt_process_label = tk.Label(frame2, text="Processing Packets")
        self.pkt_process_label.grid(row=1, column=2, padx=10, pady=7)

        self.pkt_process_entry = tk.Entry(frame2, justify="center", state="readonly", textvariable=self.pkt_process_var)
        self.pkt_process_entry.grid(row=1, column=3, padx=10, pady=7)

        # Sent Packet No.
        self.pkt_sent_label = tk.Label(frame2, text="Sent Packets")
        self.pkt_sent_label.grid(row=2, column=2, padx=10, pady=7)

        self.pkt_sent_entry = tk.Entry(frame2, justify="center", state="readonly", textvariable=self.pkt_sent_var)
        self.pkt_sent_entry.grid(row=2, column=3, padx=10, pady=7)

        # Print Packets Checkbox
        self.print_checkbox = tk.Checkbutton(frame2, text="Print Log", anchor="e", variable=self.print_flag)
        self.print_checkbox.grid(row=3, column=2, padx=10, pady=10)

    def start_button_pressed(self) -> None:
        # Input Validation
        if self.input_validation():
            return
        # Start Sniffing
        if not self.parent.start_sniffing():
            return
        # GUI Disable & Initialize
        self.iface_combobox[0].config(state=tk.DISABLED)
        self.iface_combobox[1].config(state=tk.DISABLED)
        self.ip1_entry.config(state=tk.DISABLED)
        self.ip2_entry.config(state=tk.DISABLED)
        self.delay_entry.config(state=tk.DISABLED)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        # Packet Monitoring Number
        self.pkt_detect_var.set("0")
        self.pkt_process_var.set("0")
        self.pkt_sent_var.set("0")
        self.toggle.disable()

        # [Sent Number Entry] Periodic Update
        self.update_id = self.pkt_counts_update()

    def stop_button_pressed(self) -> None:
        # Stop Sniffing
        self.parent.stop_sniffing()
        # GUI Enable
        self.iface_combobox[0].config(state="readonly")
        self.iface_combobox[1].config(state="readonly")
        self.ip1_entry.config(state=tk.NORMAL)
        self.ip2_entry.config(state=tk.NORMAL)
        self.delay_entry.config(state=tk.NORMAL)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.toggle.enable()

        # Stop Updating <Sent Number Entry>
        if self.update_id:
            self.root.after_cancel(self.update_id)

    # Input Validation
    def input_validation(self):
        try:
            # Check Validation - Interface Selecting Box
            if "" in self.iface_selected:
                raise ValueError("InterfaceError")
            # Check Validation -
            if invalid_ip(self.ip1_entry.get()) or invalid_ip(self.ip2_entry.get()):
                raise ValueError("IPAddressError")
            if float(self.delay_entry.get()) < 0:
                raise ValueError("DelayTimeError")

        except ValueError as error:
            error_type = str(error)
            if error_type == "InterfaceError":
                messagebox.showerror("Network Interface Error", "Please select the Network Interface")
            elif error_type == "IPAddressError":
                messagebox.showerror("Invalid IP Address", "IP Address entered in invalid format.\nex) 192.168.110.6")
            elif error_type == "DelayTimeError":
                messagebox.showerror("Delay Time Error", "Please enter a valid delay time in ms.\n(range ≥ 0)")
            return True
        return False

    # ComboBox List Expanded
    def update_interfaces(self, index):
        # Update Network Interface
        self.iface_list = []
        for interface in get_windows_if_list():
            for ip in interface['ips']:
                iface = Interface.check_valid(ip, interface['name'], interface['description'])
                if iface is not None:
                    self.iface_list.append(iface)

        # Update ComboBox List
        self.iface_combobox[index]['values'] = [iface.display for iface in self.iface_list]

    # ComboBox Item Selected
    def select_interface(self, if_num, event):
        idx_selected = self.iface_combobox[if_num].current()

        iface = self.iface_list[idx_selected]
        self.iface_combobox[if_num].set(iface.display)
        self.iface_selected[if_num] = iface.name
        print(f"Interface {if_num + 1} Selected :", iface.display)

    # Sent Packet Number Update
    def pkt_counts_update(self):
        if self.parent.stop_event.is_set():
            return
        # Get Sent Number from 'self.pkt_sent_num' (Shared Memory)
        with self.parent.pkt_sent_num.get_lock():
            self.pkt_process_var.set(self.parent.pkt_process_num - self.parent.pkt_sent_num.value)
            self.pkt_sent_var.set(self.parent.pkt_sent_num.value)

        # Update Packet Monitoring
        return self.root.after(100, self.pkt_counts_update)  # Update Every 100 ms

    def app_closing(self):
        self.parent.stop_sniffing()
        self.root.destroy()



