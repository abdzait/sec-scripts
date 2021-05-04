#!/usr/bin/env python

import scapy.all as scapy

import optparse


def get_arguments():
    parser = optparse.OptionParser()
    # "optparse" is created as an instance of the option parser class which is an object that can handle parsing
    # we're giving "parser" the arguments that it can expect from users
    parser.add_option("--ip", dest="ip", help="IP range to scan... ")
    # dst is the name where the value of the interface is going to be stored.

    # we're going to tell this child to parse the arguments that it gets from the user.
    # "options"  this is what contains the values that the user
    # inputs to access the value for the interface name and the mac address
    # "arguments" variable is going to contain the arguments.
    (options, arguments) = parser.parse_args()

    # way to check and make sure that the user entered a value for the interface and also entered
    # a value for the Mac
    if not options.ip:
        parser.error("[-] please specify an ip range  , use --help for more info")
    return options

    # interface = options.interface
    # new_mac = options.new_mac


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # an instance of an ARP packet object made by scapy
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Ethernet object for us from scapy using a class that's implemented by scapy
    # ff:ff:... broadcast mac address
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # new packet which is th combination of two packets ; scapy allow us to do that
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    # srp send the packet that we give it and receive the response
    # verbose to less output
    # [0] is to chose the first element only which is the answered list

    clients_list = []
    for element in answered_list:
      client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
      clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\t MAC address\n-----------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.ip)
print_result(scan_result)

