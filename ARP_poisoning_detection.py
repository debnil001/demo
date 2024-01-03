# from scapy.all import *
# import sys
# from mac_vendor_lookup import MacLookup
# from prettytable import PrettyTable

# class NetworkScanner:
#     def __init__(self,hosts):
#         self.alive={}
#         for host in hosts:
#             self.host = host
#             self.create_packet()
#             self.send_packet()
#             self.get_alive()
#             self.print_alive()

#     def create_packet(self):
#         layer2 = Ether(dst="ff:ff:ff:ff:ff:ff")
#         layer3 = ARP(pdst=self.host)
#         packet=layer2 / layer3
#         self.packet=packet
    
#     def send_packet(self):
#         ans,unans=srp(self.packet,timeout=1,verbose=False)

#         if ans:
#             self.ans=ans
#         else:
#             print("No Host is up")
#             sys.exit()
#     def get_alive(self):
#         for sent,recv in self.ans:
#             self.alive[recv.psrc] = recv.hwsrc
#     def print_alive(self):
#         table=PrettyTable(["IP","MAC","VENDOR"])
#         for ip,mac in self.alive.items():
#             try:
#                 table.add_row([ip,mac,MacLookUp().lookup(mac)])
#             except:
#                 table.add_row([ip,mac,"Unknown"])
#         print(table)

# print("Enter hosts")
# hosts=[h for h in input().split(" ")]
# NetworkScanner(hosts)

import scapy.all as scapy
import os
import platform

# Function to get the MAC address associated with an IP from the ARP cache
def get_mac(ip):
    try:
        if platform.system() == "Windows":
            # Use the 'arp' command on Windows to fetch the MAC address
            result = os.popen(f"arp -a {ip}").read()
            mac = result.split()[10] # original mac address entry corresponding to the given IP address
        return mac
    except Exception as e:
        print("Error: " + str(e))

# continuously sniff ARP packets and detect ARP poisoning attacks
def sniff_arp_packets():
    while True:
        try:
            print("ARP poisoning detection is capturing packets")
            arp_packet = scapy.sniff(filter="arp", count=1, store=1) #sniff on ARP packets
            arp_request = arp_packet[0]
            target_ip = arp_request.psrc # get the IP address for which ARP reply was received
            sender_mac = arp_request.hwsrc # get the MAC address for which ARP reply was received
            actual_mac = get_mac(target_ip)

            if sender_mac != actual_mac:
                print(f"Possible ARP Poisoning Attack Detected: {target_ip} is at {sender_mac} but should be at {actual_mac}")
        except KeyboardInterrupt:
            print("Detection stopped")
# Start ARP packet sniffing
sniff_arp_packets()