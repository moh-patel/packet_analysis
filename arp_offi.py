from matplotlib import pyplot as plt
import numpy as np
from scapy.all import *

packets = rdpcap(
    "C:\\Users\\mpate\\OneDrive\\Desktop\\Pen Testinng\\Malware and Exploit Analysis\\Assignment\\kali\\arp_kali.pcap")

# matched IP address with MAC address on the network
IP_MAC = {
    '08:00:27:23:ff:90': '192.168.56.109',
    '08:00:27:a8:4b:ef': '192.168.56.102',
    '08:00:27:17:ae:80': '192.168.56.116',
    '08:00:27:ef:4b:a0': '192.168.56.100',
    '0a:00:27:00:00:03': '192.168.56.1'
}


attackers_mac = []


targets = {
    '08:00:27:23:ff:90': [],
    '08:00:27:a8:4b:ef': [],
    '08:00:27:17:ae:80': [],
    '08:00:27:ef:4b:a0': [],
    '0a:00:27:00:00:03': []
}


# total number of malicious ARP replies
total = 1
for packet in packets:
    if packet.haslayer(ARP):
        # checks if the ARP request claims to have an IP address, it does not have
        if IP_MAC.get(packet.src) != packet.psrc:
            # adds MAC adress as an attacker if not set
            if packet.src not in attackers_mac:
                attackers_mac.append(packet.src)
            # checks if the target machine has been sent a spoofed arp packet before
            # packet.psrc is the fake IP an ARP reply cliams to have
            # packet.dst is the attacked machine (manipulated to have wrong IP addresses)
            if len(targets[packet.dst]) == 0:
                targets.get(packet.dst).append([packet.psrc])
                targets.get(packet.dst)[-1].append(1)
            # if the malicious packet has been sent before it updates the value
            elif packet.psrc in targets[packet.dst][:]:
                targets[packet.dst][1] += 1
            print('Forged IP address', packet.psrc)
            print('Manipulate Target', packet.dst)
            print(total)
            total += 1

# print(packets[0][Ether].src)


# print((packets[6].show()))

print(targets)

# detect duplicate packets as packets are sent to the attacking machine before being sent (MITM)
ubuntu_kali = 0
kali_meta = 0
meta_kali = 0
kali_ubuntu = 0
for packet in packets:
    if packet.haslayer(TCP):
        if packet.src == '08:00:27:17:ae:80' and packet.dst == '08:00:27:23:ff:90' and packet[IP].src == '192.168.56.116' and packet[IP].dst == '192.168.56.102':
            ubuntu_kali += 1
        elif packet.src == '08:00:27:23:ff:90' and packet.dst == '08:00:27:a8:4b:ef' and packet[IP].src == '192.168.56.116' and packet[IP].dst == '192.168.56.102':
            kali_meta += 1
        elif packet.src == '08:00:27:a8:4b:ef' and packet.dst == '08:00:27:23:ff:90' and packet[IP].src == '192.168.56.102' and packet[IP].dst == '192.168.56.116':
            meta_kali += 1
        elif packet.src == '08:00:27:23:ff:90' and packet.dst == '08:00:27:17:ae:80' and packet[IP].src == '192.168.56.102' and packet[IP].dst == '192.168.56.116':
            kali_ubuntu += 1

print(ubuntu_kali, kali_meta, meta_kali, kali_ubuntu)


# fig, ax = plt.subplots()

# x = np.arange(len(targets.keys()))
# width = 0.35

# ip1 = list(targets.values())[1:]
# ip1 = [next(iter(i)) for i in ip1]

# ip2 = list(targets.values)
# print(ip1)
# rects1 = ax.bar(x - width/2, ip1, width, label='IP1')
# rects1 = ax.bar(x - width/2, targets.values().keys(), width, label='IP1')
