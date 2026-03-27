import os
import psutil
import time
from collections import deque

import scapy.all as scapy
scapy.conf.verb = 0


# Child Process
def packet_delay_send(infos) -> None:
    # Process Priority Elevation
    sub_pid = psutil.Process(os.getpid())
    sub_pid.nice(psutil.HIGH_PRIORITY_CLASS)

    # Information from Main Thread
    que_from_parent, stop_event, delay_ms, iface_selected, pkt_sent_num, pkt_sent_bytes = infos

    delay = float(delay_ms) / 1000  # ms -> 초로 변환

    # Deque for saving (packet, start time)
    pkt_deque = deque()
    while not stop_event.is_set():
        # Get Packets from Parent Process
        try:
            while True:
                pkt_deque.append(que_from_parent.get_nowait())
        except Exception:
            pass
        # Check delayed time and send
        while pkt_deque:
            pkt, start_time = pkt_deque[0]
            if time.time() - start_time >= delay:
                # Send Packets by Ethernet (Layer 2)
                pkt_len = len(pkt)
                if   pkt.sniffed_on == iface_selected[0]: scapy.sendp(pkt, iface=iface_selected[1])
                elif pkt.sniffed_on == iface_selected[1]: scapy.sendp(pkt, iface=iface_selected[0])
                pkt_deque.popleft()
                # Sent Number & Bytes Update
                with pkt_sent_num.get_lock():
                    pkt_sent_num.value += 1
                with pkt_sent_bytes.get_lock():
                    pkt_sent_bytes.value += pkt_len
            else:
                break
