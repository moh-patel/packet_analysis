#!/usr/bin/env python
import dpkt
import socket
from dpkt.tcp import TCP
import matplotlib.pyplot as plt
import matplotlib.dates as md
import datetime
from datetime import timedelta
import time


def roundup(x):
    # return int(math.ceil(x / 10.0)) * 10
    rem = x % 10
    if rem < 5:
        return int(x/10) * 10
    return int((x + 10) / 10) * 10


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

    print(tslst[-1], stslst[-1])
    # tslst[-1] = tslst[-1] - tslst[0]
    # print(time.strftime("%H:%M:%S:{}".format(
    #     tslst[-1] % 1000), time.gmtime(tslst[-1]/1000.0)))
    f.close()
    return(tslst)


def roundup_10_millisecond(tslst):
    # # multiply by 1000 gives milliseconds
    return [roundup(((i - tslst[0]) + 0.01) * 1000) for i in tslst]



# counts number of packets sent every 10 milliseconds and returns a dictionary for number of packets sent every 10 seconds
def get_dict_tslst(tslst):
    return {i: tslst.count(i) for i in tslst}


f_tcp_connect = 'nmap -sT victim.pcap'
f_half_open = 'nmap -sS victim.pcap'
f_fin = 'nmap -sF victim.pcap'
f_xmas = 'nmap -sX victim.pcap'
f_null = 'nmap -sN victim.pcap'

dict_tslst_tcp_connect = get_dict_tslst(
    roundup_10_millisecond(get_tslst(f_tcp_connect)))
dict_tslst_half_open = get_dict_tslst(
    roundup_10_millisecond(get_tslst(f_half_open)))
dict_tslst_fin = get_dict_tslst(roundup_10_millisecond(get_tslst(f_fin)))
dict_tslst_xmas = get_dict_tslst(roundup_10_millisecond(get_tslst(f_xmas)))
dict_tslst_null = get_dict_tslst(roundup_10_millisecond(get_tslst(f_null)))


# dictTslst = {i: tslst.count(i) for i in tslst}

plt.plot(dict_tslst_tcp_connect.keys(), dict_tslst_tcp_connect.values(),
         label='TCP connect')
plt.plot(dict_tslst_half_open.keys(), dict_tslst_half_open.values(),
         label='Half Open')
plt.plot(dict_tslst_fin.keys(), dict_tslst_fin.values(),
         label='FIN')
plt.plot(dict_tslst_xmas.keys(), dict_tslst_xmas.values(),
         label='XMAS')
plt.plot(dict_tslst_null.keys(), dict_tslst_null.values(),
         label='NULL')
plt.legend()
# plt.plot(tslst, range(1, len(dportlst) + 1),
#          color='#5a7d9a', label='Python')
# ax = plt.gca()
# xfmt = md.DateFormatter('%f')
# ax.xaxis.set_major_formatter(xfmt)
plt.xlabel('Time Elapsed (milliseconds)')
plt.ylabel('Number of packets sent every 10 milliseconds')

plt.ylim(ymin=0)
plt.xlim(xmin=0)
# # get the highest value of number of packet sent
# maximum = dictTslst[max(dictTslst, key=dictTslst.get)]

# plt.xlim([0, tslst[-1] + tslst[-1] * 0.1])
# plt.ylim([0, maximum + (maximum * 0.1)])

plt.show()
