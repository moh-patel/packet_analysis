import numpy as np
from matplotlib import pyplot as plt
import dpkt
import matplotlib.pyplot as plt
from dpkt.tcp import TCP
import datetime
import socket


def get_streams(pcap):

    streams = {}

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        # for packet in tcp:
        #    print(type(packet))
        # print(type(tcp.dport))
        # @manishkk you're likely hitting a non-TCP packet (e.g. an ARP or ICMP). You can try the following (untested)
        if isinstance(tcp, TCP):
            # gathers the streams of the packets
            if socket.inet_ntoa(ip.src) == "192.168.56.109":
                if (tcp.sport, tcp.dport) in streams:
                    streams[tcp.sport, tcp.dport].append(eth)
                else:
                    streams[tcp.sport, tcp.dport] = [eth]
            elif socket.inet_ntoa(ip.src) == "192.168.56.102":
                if (tcp.dport, tcp.sport) in streams:
                    streams[tcp.dport, tcp.sport].append(eth)
    return streams


def get_flags(tcp):
    flags = list()

    if tcp.flags & dpkt.tcp.TH_ACK != 0:
        flags.append('ACK')
    if tcp.flags & dpkt.tcp.TH_SYN != 0:
        flags.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST != 0:
        flags.append('RST')
    if tcp.flags & dpkt.tcp.TH_FIN != 0:
        flags.append('FIN')
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
        flags.append('PSH')
    if tcp.flags & dpkt.tcp.TH_URG != 0:
        flags.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE != 0:
        flags.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR != 0:
        flags.append('CWR')
    if(len(flags) == 0):
        flags.append('NULL')
    return flags


def get_all_flags(streams):

    all_flags = list()
    for port, packets in streams.items():
        stream_flags = [get_flags(i.data.data) for i in packets]
        all_flags.append(stream_flags)
    return all_flags


def detect_TCP_connect(all_flags):
    # records the number of packets that complete a three way handshake and followed by RST/ACK
    three_way_handshake = 0
    # records if SYN sent, followed by RST,ACK
    reset_ack = 0
    unknown = 0
    for flags in all_flags:
        # print(flags)
        if len(flags) == 2:
            if flags[0] == ['SYN'] and ('ACK' and 'RST' in flags[1]):
                reset_ack += 1
            else:
                unknown += 1
        elif len(flags) == 4:
            # print(flags)
            if ('SYN' in flags[0]) and ('ACK' and 'SYN' in flags[1]) and 'ACK' in flags[2] and ('ACK' and 'RST' in flags[3]):
                three_way_handshake += 1
            else:
                # print(flags)
                unknown += 1
        else:
            unknown += 1
    # assuming at least 4 ports are open on the target machine, this should be changed if less/more ports are opened
    if reset_ack > three_way_handshake and three_way_handshake > 4:
        return True, three_way_handshake, reset_ack, unknown
    return False, three_way_handshake, reset_ack, unknown


def detect_half_open(all_flags):
    # records the half open scan
    half_open = 0
    reset_ack = 0
    unknown = 0

    for flags in all_flags:
        # print(flags)
        if len(flags) == 2:
            if flags[0] == ['SYN'] and ('ACK' and 'RST' in flags[1]):
                reset_ack += 1
            else:
                unknown += 1
        elif len(flags) == 3:
            # print(flags)
            if ('SYN' in flags[0]) and ('ACK' and 'SYN' in flags[1]) and ('RST' in flags[2]):
                half_open += 1
            else:
                print(flags)
                unknown += 1
        else:
            unknown += 1
    # assuming at least 4 ports are open on the target machine, this should be changed if less/more ports are opened
    if reset_ack > half_open and half_open > 4:
        return True, half_open, reset_ack, unknown
    return False, half_open, reset_ack, unknown


def detect_FIN(all_flags):
    # records when port responds to FIN
    response_FIN = 0
    no_response_FIN = 0
    unknown = 0

    print(len(all_flags))
    for flags in all_flags:
        # print(flags)
        if len(flags) == 2:
            if 'FIN' in flags[0] and ('ACK' and 'RST' in flags[1]):
                response_FIN += 1
            else:
                unknown += 1

        elif len(flags) == 1:
            if ('FIN' in flags[0]):
                no_response_FIN += 1
            else:
                unknown += 1
        else:
            unknown += 1
    # assuming at least 4 ports are open on the target machine, this should be changed if less/more ports are opened
    if response_FIN > no_response_FIN and no_response_FIN > 4:
        return True, no_response_FIN, response_FIN, unknown
    return False, no_response_FIN, response_FIN, unknown


def detect_XMAS(all_flags):
    # records when port responds to FIN
    response = 0
    no_response = 0
    unknown = 0

    print(len(all_flags))
    for flags in all_flags:
        # print(flags)
        if len(flags) == 2:
            if ('FIN' and 'PSH' and 'URG' in flags[0]) and ('ACK' and 'RST' in flags[1]):
                response += 1
            else:
                unknown += 1

        elif len(flags) == 1:
            if ('FIN' and 'PSH' and 'URG' in flags[0]):
                no_response += 1
            else:
                unknown += 1
        else:
            unknown += 1
    # assuming at least 4 ports are open on the target machine, this should be changed if less/more ports are opened
    if response > no_response and no_response > 4:
        return True, no_response, response, unknown
    return False, no_response, response, unknown


def detect_NULL(all_flags):
    # records when port responds to FIN
    response = 0
    no_response = 0
    unknown = 0

    print(len(all_flags))
    for flags in all_flags:
        # print(flags)
        if len(flags) == 2:
            if ('NULL' in flags[0]) and ('ACK' and 'RST' in flags[1]):
                response += 1
            else:
                unknown += 1

        elif len(flags) == 1:
            if ('NULL' in flags[0]):
                no_response += 1
            else:
                unknown += 1
        else:
            unknown += 1
    # assuming at least 4 ports are open on the target machine, this should be changed if less/more ports are opened
    if response > no_response and no_response > 4:
        return True, no_response, response, unknown
    return False, no_response, response, unknown


# reading port connect scan
f = open("C:\\Users\\mpate\\OneDrive\\Desktop\\Pen Testinng\\Malware and Exploit Analysis\\Assignment\\kali\\nmap -sT victim.pcap", "rb")
pcap = dpkt.pcap.Reader(f)

streams = get_streams(pcap)
all_flags = get_all_flags(streams)
tcp_connect = detect_TCP_connect(all_flags)
f.close()


f = open("C:\\Users\\mpate\\OneDrive\\Desktop\\Pen Testinng\\Malware and Exploit Analysis\\Assignment\\kali\\nmap -sS victim.pcap", "rb")
pcap = dpkt.pcap.Reader(f)

streams = get_streams(pcap)

all_flags = get_all_flags(streams)
half_open = detect_half_open(all_flags)

f.close()


f = open("C:\\Users\\mpate\\OneDrive\\Desktop\\Pen Testinng\\Malware and Exploit Analysis\\Assignment\\kali\\nmap -sF victim.pcap", "rb")
pcap = dpkt.pcap.Reader(f)

streams = get_streams(pcap)

all_flags = get_all_flags(streams)
fin = detect_FIN(all_flags)

f.close()

f = open("C:\\Users\\mpate\\OneDrive\\Desktop\\Pen Testinng\\Malware and Exploit Analysis\\Assignment\\kali\\nmap -sX victim.pcap", "rb")
pcap = dpkt.pcap.Reader(f)
streams = get_streams(pcap)
all_flags = get_all_flags(streams)
xmas = detect_XMAS(all_flags)
f.close()


f = open("C:\\Users\\mpate\\OneDrive\\Desktop\\Pen Testinng\\Malware and Exploit Analysis\\Assignment\\kali\\nmap -sN victim.pcap", "rb")
pcap = dpkt.pcap.Reader(f)
streams = get_streams(pcap)
all_flags = get_all_flags(streams)
null = detect_NULL(all_flags)
f.close()




tslst = []
dportlst = []
stslst = []

# https://matplotlib.org/3.1.1/gallery/lines_bars_and_markers/bar_stacked.html
N = 5
bar1 = [tcp_connect[1], half_open[1], fin[1], xmas[1], null[1]]
bar2 = [tcp_connect[2], half_open[2], fin[2], xmas[2], null[2]]
ind = np.arange(N)


plt1 = plt.bar(ind, bar1)
plt2 = plt.bar(ind, bar2, bottom=bar1)
plt.ylabel('Number of Packets')
plt.title('Types of Port scans')
plt.xticks(ind, ('TCP connect', 'Half-Open', 'FIN', 'XMAS', 'NULL'))
for r1, r2 in zip(plt1, plt2):
    h1 = r1.get_height()
    h2 = r2.get_height()
    plt.text(r1.get_x() + r1.get_width() / 2., h1 / 2., "%d" % h1,
             ha="center", va="center", color="white", fontsize=6, fontweight="light")
    plt.text(r2.get_x() + r2.get_width() / 2., h1 + h2 / 2., "%d" % h2,
             ha="center", va="center", color="white", fontsize=9, fontweight="light")


plt.show()


print(sorted(dportlst))

