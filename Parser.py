import csv
from scapy.all import *

def parse_dict(dct):
    IRC_mal = ['192.168.2.112-131.202.243.84',
               '192.168.5.122-198.164.30.2',
               '192.168.2.110-192.168.5.122',
               '192.168.4.118-192.168.5.122',
               '192.168.2.113-192.168.5.122',
               '192.168.1.103-192.168.5.122',
               '192.168.4.120-192.168.5.122',
               '192.168.2.112-192.168.2.110',
               '192.168.2.112-192.168.4.120',
               '192.168.2.112-192.168.1.103',
               '192.168.2.112-192.168.2.113',
               '192.168.2.112-192.168.4.118',
               '192.168.2.112-192.168.2.109',
               '192.168.2.112-192.168.2.105',
               '192.168.1.105-192.168.5.122']
    rest_mal = ['147.32.84.180',
                '147.32.84.170',
                '147.32.84.150',
                '147.32.84.140',
                '147.32.84.130',
                '147.32.84.160',
                '10.0.2.15',
                '192.168.106.141',
                '192.168.106.131',
                '172.16.253.130',
                '172.16.253.131',
                '172.16.253.129',
                '172.16.253.240',
                '172.29.0.109',
                '10.37.130.4',
                '172.16.253.132',
                '192.168.248.165']
    for x in dct:
        name_2 = '-'.join([y for y in reversed(x.split('-'))])
        if x in IRC_mal or name_2 in IRC_mal or x.split('-')[0] in rest_mal or x.split('-')[1] in rest_mal:
            is_malware = 1
        else:
            is_malware = 0
        all_connections = dct[x][0] + dct[x][1]
        flow_duration = max([y.time for y in all_connections]) - min([y.time for y in all_connections]) 
        tot_fwd_packets = len(dct[x][0])
        tot_bwd_packets = len(dct[x][1])
        tot_len_fwd_packets = sum([y.len for y in dct[x][0]])
        tot_len_bwd_packets = sum([y.len for y in dct[x][1]])
        if tot_fwd_packets > 0:
            fwd_packet_len_max = max([y.len for y in dct[x][0]])
            fwd_packet_len_min = min([y.len for y in dct[x][0]])
        else:
            fwd_packet_len_max = 0
            fwd_packet_len_min = 0
        if tot_bwd_packets > 0:
            bwd_packet_len_max = max([y.len for y in dct[x][1]])
            bwd_packet_len_min = min([y.len for y in dct[x][1]])
        else:
            bwd_packet_len_max = 0
            bwd_packet_len_min = 0
        if flow_duration != 0:
            flow_byts_per_s = (tot_len_fwd_packets + tot_len_bwd_packets) / flow_duration
            flow_packets_per_s = (tot_fwd_packets + tot_bwd_packets) / flow_duration
            fwd_packet_per_s = tot_fwd_packets / flow_duration
            bwd_packet_per_s = tot_bwd_packets / flow_duration
        else:
            flow_byts_per_s = 0
            flow_packets_per_s = 0
            fwd_packet_per_s = 0
            bwd_packet_per_s = 0
        bwd_to_fwd_ratio = tot_bwd_packets / tot_fwd_packets
        packet_len_min = min([y.len for y in all_connections])
        packet_len_max = max([y.len for y in all_connections])
        packet_size_avarage = sum([y.len for y in all_connections]) / len(all_connections)
        yield [flow_duration, tot_fwd_packets, tot_bwd_packets, tot_len_fwd_packets, tot_len_bwd_packets,
               fwd_packet_len_max, fwd_packet_len_min, bwd_packet_len_max, bwd_packet_len_min, flow_byts_per_s,
               flow_packets_per_s, fwd_packet_per_s, bwd_packet_per_s, bwd_to_fwd_ratio, packet_len_min,
               packet_len_max, packet_size_avarage, is_malware]
'''
['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
 'Fwd Pkt Len Min', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkts/s', 
 'Bwd Pkts/s', 'Bwd/Fwd Ratio', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Size Avg', 'Malware']
'''


def parse_pcap(pcap_file, csv_file):
    packets = []
    all_connects = dict()
  #  sniff(offline=pcap_file, count=10000, prn=lambda pkt: packets.append(pkt))
    packets = [x for x in PcapReader(pcap_file)]
    file = open(csv_file, 'a+', newline='')
    writer = csv.writer(file)
    if os.path.getsize('Botnet-Testing.csv') == 0:
        writer.writerow(['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
                         'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Flow Byts/s',
                         'Flow Pkts/s', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Bwd/Fwd Ratio', 'Pkt Len Min', 'Pkt Len Max',
                         'Pkt Size Avg', 'Malware'])
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        if 'src' not in packet['IP'].fields.keys() or 'dst' not in packet['IP'].fields.keys():
            continue
        name_1 = packet['IP'].src + '-' + packet['IP'].dst
        name_2 = packet['IP'].dst + '-' + packet['IP'].src
        if name_1 not in all_connects and name_2 not in all_connects:
            all_connects[name_1] = [[], []]
        if name_1 in all_connects:
            all_connects[name_1][0].append(packet['IP'])
        else:
            all_connects[name_2][1].append(packet['IP'])
    for row in parse_dict(all_connects):
        writer.writerow(row)


if __name__ == '__main__':
    pcap_file = "testDset-with iscx.pcap"
    csv_file = "Botnet-test-with-iscx.csv"
    parse_pcap(pcap_file, csv_file)
