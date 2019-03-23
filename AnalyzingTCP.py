import scapy.all
def TCPAnalyzer(resultlist):
    def packet_callback(packet: scapy.all.scapy.packet):
        for data in packet:
            '打印IP数据报的基本信息 最后一项为首部校验和'
            resultlist.append(data.sprintf("IP: %-15s,IP.src% -> %-15s,IP.dst%\n"))
            '打印TCP数据包基本信息'
            resultlist.append(data.sprintf("TCP:srcPORT %TCP.sport% -> dstPORT %TCP.dport%\n"))
            resultlist.append(data.sprintf("%Raw.load%\n\n"))
        return

    scapy.all.sniff(filter='tcp', iface='Qualcomm Atheros AR956x Wireless Network Adapter', prn=packet_callback,
                    count=5)