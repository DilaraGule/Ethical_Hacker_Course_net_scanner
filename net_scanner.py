import scapy.all as scapy
import optparse


def get_user_input():
    parse = optparse.OptionParser()
    parse.add_option("-i", "--ipaddress", dest="ip_address", help="Enter IP Address")

    (user_input, arguments) = parse.parse_args()

    if not user_input.ip_address:
        print("Enter IP Address")

    return user_input


def scan_my_network(ip):
    # Create ARP Request
    arp_request = scapy.ARP(pdst=ip)
    # scapy.ls(scapy.ARP())

    # Broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined = broadcast/arp_request      # iki paketi tek paket yapti

    # Response
    (answered_list, unanswered_list) = scapy.srp(combined, timeout=1)   # paket gonderimi(cevap verilenler/verilmeyenler return edilir.)
    answered_list.summary()


user_ip_address = get_user_input()
scan_my_network(user_ip_address.ip_address)
