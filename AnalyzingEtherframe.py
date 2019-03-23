from typing import List, Any
from scapy.all import *
from scapy.layers.l2 import Ether

print(scapy.all.time.ctime())

packetCount = 0


def catchPacket(filterstr, list):
    def packet_callback(packet: scapy.all.scapy.packet):
        global packetCount
        macFrame = '捕获到第' + str(packetCount) + '个以太帧 \n' \
                   + '目的MAC ' + packet[Ether].dst + '\n' \
                   + '源MAC ' + packet[Ether].src + '\n' \
                   + '协议类型 ' + hex(packet[Ether].type) + '\n' \
                   + scapy.all.hexdump(packet[Ether].payload,dump=True) +'\n\n'
        # print('捕获到第'+str(packetCount)+'个以太帧')
        # print('目的MAC %s' % packet[Ether].dst)
        # print('源MAC %s' % packet[Ether].src)
        # print('协议类型 %s' % hex(packet[Ether].type))
        # print(scapy.all.hexdump(packet[Ether].payload))
        #print(macFrame)
        list.append(macFrame)
        packetCount += 1

    scapy.all.sniff \
        (filter=filterstr, iface='Qualcomm Atheros AR956x Wireless Network Adapter', prn=packet_callback, count=5)