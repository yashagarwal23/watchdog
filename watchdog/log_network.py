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


def getTcpData(packet):
    packet_dump_dict = {}
    packet_dump_dict['sport'] = packet[TCP].sport
    packet_dump_dict['dport'] = packet[TCP].dport
    packet_dump_dict['seq'] = packet[TCP].seq
    packet_dump_dict['ack'] = packet[TCP].ack
    packet_dump_dict['dataofs'] = packet[TCP].dataofs
    packet_dump_dict['reserved'] = packet[TCP].reserved
    packet_dump_dict['window'] = packet[TCP].window
    packet_dump_dict['chksum'] = packet[TCP].chksum
    packet_dump_dict['urgptr'] = packet[TCP].urgptr
    return packet_dump_dict


def getIpData(packet):
    packet_dump_dict = {}
    packet_dump_dict['version'] = packet[IP].version
    packet_dump_dict['ihl'] = packet[IP].ihl
    packet_dump_dict['tos'] = packet[IP].tos
    packet_dump_dict['len'] = packet[IP].len
    packet_dump_dict['id'] = packet[IP].id
    packet_dump_dict['frag'] = packet[IP].frag
    packet_dump_dict['ttl'] = packet[IP].ttl
    packet_dump_dict['chksum'] = packet[IP].chksum
    packet_dump_dict['src'] = packet[IP].src
    packet_dump_dict['dst'] = packet[IP].dst
    return packet_dump_dict

def getUdpData(packet):
    packet_dump_dict = {}
    packet_dump_dict['sport'] = packet[UDP].sport
    packet_dump_dict['dport'] = packet[UDP].dport
    packet_dump_dict['chksum'] = packet[UDP].chksum
    packet_dump_dict['len'] = packet[UDP].len
    return packet_dump_dict


def log_packet(packet):
    packet_dict = {}
    if IP in packet:
        packet_dict.update(getIpData(packet))

    if TCP in packet:
        packet_dict.update(getTcpData(packet))

    if UDP in packet:
        packet_dict.update(getUdpData(packet))

    packet_dict["timestamp"] = str(datetime.fromtimestamp(time.time()))
    packet_dict["server"] = str(socket.gethostname())
    packet_dict["direction"] = getPacketDirection(packet)
    res = es.index(index='logs',doc_type='logs',body=packet_dict)

def start_logger():
    print("logger started")
    sniff(prn = log_packet)