import struct
from scapy import *
import scapy.all
import scapy.compat


def IP_headchecksum(IP_head):
    check_sum = 0
    head_lenth = len(IP_head)
    if head_lenth % 2 == 1:
        IP_head += b"\0"
    i = 0
    while i < head_lenth:
        temp = struct.unpack('!H', IP_head[i:i + 2])[0]
        #print("%04x" % temp)
        check_sum = check_sum + temp
        i = i + 2
    # 将高16bit与低16bit相加
    check_sum = (check_sum >> 16) + (check_sum & 0xffff)

    return ~check_sum & 0xffff


def IPAnalyzer(resultlist):
    def packet_callback(packet: scapy.all.scapy.packet):
        for data in packet:
            '打印IP数据报的基本信息 最后一项为首部校验和'
            resultlist.append(data.sprintf("%.time% %-15s,IP.src% -> %-15s,IP.dst% %IP.chksum% \n"))
            #清空抓取的IP报的首部校验和 使用内置模块验证校验和
            data.chksum=0
            x = scapy.compat.raw(data)
            ipString = "".join("%02x" % scapy.compat.orb(x) for x in x)
            ipbytes = bytearray.fromhex(ipString)
            checksum_self = IP_headchecksum(ipbytes)

            resultlist.append("验证计算机IP首部的校验和是："+ str(checksum_self)+"\n")


        return

    scapy.all.sniff(filter='ip', iface='Qualcomm Atheros AR956x Wireless Network Adapter', prn=packet_callback,
                    count=5)
