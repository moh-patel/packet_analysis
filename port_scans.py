#!/usr/bin/env python
import dpkt
import socket
from dpkt.tcp import TCP
import matplotlib.pyplot as plt
import matplotlib.dates as md
import datetime
from datetime import timedelta
import time


def get_tslst(filename):
    # from pprint import pprint
    f = open("C:\\Users\\mpate\\OneDrive\\Desktop\\Pen Testinng\\Malware and Exploit Analysis\\Assignment\\kali\\" + filename, "rb")
    pcap = dpkt.pcap.Reader(f)
    tslst = []
    dportlst = []
    stslst = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        
        # @manishkk you're likely hitting a non-TCP packet (e.g. an ARP or ICMP). You can try the following (untested)
        if isinstance(tcp, TCP):
            tslst.append(ts)
            stslst.append(str(datetime.datetime.utcfromtimestamp(ts)))
            dportlst.append(tcp.dport)
            
    f.close()
    return tslst


def get_milliseconds(tslst):
    return [((i - tslst[0])) * 1000 for i in tslst]


f_tcp_connect = 'nmap -sT victim.pcap'
f_half_open = 'nmap -sS victim.pcap'
f_fin = 'nmap -sF victim.pcap'
f_xmas = 'nmap -sX victim.pcap'
f_null = 'nmap -sN victim.pcap'

tslst_tcp_connect = get_milliseconds(get_tslst(f_tcp_connect))
tslst_half_open = get_milliseconds(get_tslst(f_half_open))
tslst_fin = get_milliseconds(get_tslst(f_fin))
tslst_xmas = get_milliseconds(get_tslst(f_xmas))
tslst_null = get_milliseconds(get_tslst(f_null))


plt.plot(tslst_tcp_connect, range(1, len(tslst_tcp_connect) + 1),
         label='TCP connect')
plt.plot(tslst_half_open, range(1, len(tslst_half_open) + 1),
         label='half_open')
plt.plot(tslst_fin, range(1, len(tslst_fin) + 1),
         label='FIN')
plt.plot(tslst_xmas, range(1, len(tslst_xmas) + 1),
         label='XMAS')
plt.plot(tslst_null, range(1, len(tslst_null) + 1),
         label='NULL')
plt.legend()

plt.xlabel('time elapsed (milliseconds)')
plt.ylabel('packet number')

# ymin,y
plt.ylim(ymin=0)
plt.xlim(xmin=0)



plt.show()
