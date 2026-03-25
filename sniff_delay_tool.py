import os
import psutil
import multiprocessing
from sys import exit

import scapy.all as scapy
scapy.conf.verb = 0

from tkinter import messagebox

from core.process import MainProcess

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
                __main__()          packet_delay_send()
               _ _ _ _ _ _   (PIPE)    _ _ _ _ _ _
 sniff()      |           |  packets  |           |
thread 1  --> |   parent  |  ------>  |   child   |  sendp()
thread 2  --> |  process  |  <----->  |  process  |  ------>
              |_ _ _ _ _ _|  sentNum  |_ _ _ _ _ _|
                                (SM)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

if __name__ == "__main__":
    multiprocessing.freeze_support()

    if not scapy.conf.use_pcap:
        messagebox.showerror("Error", "\"Npcap\" is not installed."
                                      "\nPlease install \"Npcap\" with 'Winpcap API-compatible mode'")
        exit(1)

    # Process Priority Elevation
    main_pid = psutil.Process(os.getpid())
    main_pid.nice(psutil.HIGH_PRIORITY_CLASS)

    # Run the GUI application
    app = MainProcess()
    app.widget.root.mainloop()
