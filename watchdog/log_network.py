from scapy.all import *
import socket
import os
import json
import logging
import time
from datetime import datetime
from elasticsearch import Elasticsearch 
import socket

es=Elasticsearch([{'host':'52.152.170.162','port':9200}])

def getPacketDirection(packet):
    if packet.haslayer(Ether) and packet[Ether].src.lower()==get_if_hwaddr(conf.iface).lower():
        return "incoming"
    else:
        return "outgoing"


def getTcpData(tcp_packet):
    packet_dump = tcp_packet.show(dump=True)
    packet_dump_line_list = packet_dump.split('\n')[1:12]
    packet_dump_dict = {}
    for line in packet_dump_line_list:
        key, value = line.split('=')
        packet_dump_dict[key.strip()] = value.strip()
    return packet_dump_dict


def getIpData(ip_packet):
    packet_dump = ip_packet.show(dump=True)
    packet_dump_line_list = packet_dump.split('\n')[1:13]
    packet_dump_dict = {}
    for line in packet_dump_line_list:
        key, value = line.split('=')
        packet_dump_dict[key.strip()] = value.strip()
    return packet_dump_dict

def getUdpData(udp_packet):
    packet_dump = udp_packet.show(dump=True)
    packet_dump_line_list = packet_dump.split('\n')[1:5]
    packet_dump_dict = {}
    for line in packet_dump_line_list:
        key, value = line.split('=')
        packet_dump_dict[key.strip()] = value.strip()
    return packet_dump_dict

def log_packet(packet):
    packet_dict = {}
    if IP in packet:
        ip = IP(packet)
        packet_dict.update(getIpData(ip))

    if TCP in packet:
        tcp = TCP(packet)
        packet_dict.update(getTcpData(tcp))

    if UDP in packet:
        udp = UDP(packet)
        packet_dict.update(getUdpData(udp))

    packet_dict["timestamp"] = str(datetime.fromtimestamp(time.time()))
    packet_dict["server"] = str(socket.gethostname())
    packet_dict["direction"] = getPacketDirection(packet)
    res = es.index(index='logs',doc_type='logs',body=packet_dict)

def start_logger():
    print("logger started")
    sniff(prn = log_packet)