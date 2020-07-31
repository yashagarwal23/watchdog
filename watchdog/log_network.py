from scapy.all import *
import socket
import os
import json
import logging
import time
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

packet_logger = logging.getLogger("packet_logger")

log_file_name = "watchdog\packets.log"
fmt = '%(message)s'
handler = TimedRotatingFileHandler(log_file_name, when="midnight", interval=1)
handler.suffix = "%Y%m%d"
packet_logger.addHandler(handler)

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


def log_packet(packet):
    if IP in packet and TCP in packet:
        ip = IP(packet)
        tcp = TCP(packet)
        packet_dict = getIpData(ip)
        packet_dict.update(getTcpData(tcp))
        packet_dict["timestamp"] = str(datetime.fromtimestamp(time.time()))
        json_string = json.dumps(packet_dict)
        packet_logger.warning(json_string)

def start_logger():
    print("logger started")
    sniff(prn = log_packet)