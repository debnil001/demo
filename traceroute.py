# import sys
# from scapy.all import IP, ICMP, sr1

# def traceroute(destination, max_hops):
#     for ttl in range(1, max_hops + 1):
#         # Create an ICMP packet with the specified TTL
#         packet = IP(dst=destination, ttl=ttl) / ICMP()

#         # Send the packet and receive a response (or not) within the timeout
#         response = sr1(packet, verbose=0, timeout=1)

#         if response is None:
#             # No response within the timeout, print '*'
#             print(f"{ttl}: *")
#         elif response.haslayer(ICMP):
#             if response[ICMP].type == 0:
#                 # ICMP Echo Reply, we reached the destination
#                 print(f"{ttl}: {response.src} (Destination Reached)")
#                 sys.exit(0)
#             elif response[ICMP].type == 11:
#                 # ICMP Time Exceeded, intermediate router
#                 print(f"{ttl}: {response.src}")
#         else:
#             # Other ICMP packet types or unexpected responses
#             print(f"{ttl}: Unknown Response")

# if __name__ == "__main__":
#     if len(sys.argv) != 3:
#         print("Usage: python traceroute.py <destination_ip> <max_hops>")
#         sys.exit(1)

#     destination_ip = sys.argv[1]
#     max_hops = int(sys.argv[2])

#     print(f"Traceroute to {destination_ip}, max hops: {max_hops}\n")
#     traceroute(destination_ip, max_hops)


from scapy.all import *

def traceroute(destination, max_hops):
    for ttl in range(1, max_hops + 1):
        packet = IP(dst=destination, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=0, timeout=1)

        if reply is None:
            # No response received within the timeout
            print(f"{ttl}: *")
        elif reply.haslayer(ICMP):
            if reply.getlayer(ICMP).type == 0:
                # ICMP Echo Reply received, we reached the destination
                print(f"{ttl}: {reply.src} (Destination Reached)")
                break
            elif reply.getlayer(ICMP).type == 11:
                # ICMP Time Exceeded, print the intermediate router's IP address
                print(f"{ttl}: {reply.src}")
        else:
            # Unhandled packet type
            print(f"{ttl}: Unknown packet type")

if __name__ == "__main__":
    destination = input("Enter the destination IP address: ")
    max_hops = int(input("Enter the maximum number of hops: "))

    traceroute(destination, max_hops)
