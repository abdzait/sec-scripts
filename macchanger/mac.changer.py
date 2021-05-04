#!/usr/bin/env python

import subprocess
# module contains number of functions that allow you to run system commands
import optparse
# optparse is the name of the module that allows us to get arguments from the user and parse them and use them within
# our code.
import re
# module to handle regular expression


# function to parse the user input and return to meet the arguments and the values
# entered by the user.
def get_arguments():
    parser = optparse.OptionParser()
    # "optparse" is created as an instance of the option parser class which is an object that can handle parsing
    # we're giving "parser" the arguments that it can expect from users
    parser.add_option("-i", "--interface", dest="interface", help="interface to change its MAC address...")
    # dst is the name where the value of the interface is going to be stored.
    parser.add_option("-m", "--MAC", dest="new_mac", help="new MAC address")

    # we're going to tell this child to parse the arguments that it gets from the user.
    # "options"  this is what contains the values that the user
    # inputs to access the value for the interface name and the mac address
    # "arguments" variable is going to contain the arguments.
    (options, arguments) = parser.parse_args()

    # way to check and make sure that the user entered a value for the interface and also entered
    # a value for the Mac
    if not options.interface:
        parser.error("[-] please specify an interface , use --help for more info")
    elif not options.new_mac:
        parser.error("[-] please specify a new MAC , use --help for more info")
    return options

    # interface = options.interface
    # new_mac = options.new_mac


def change_mac(interface, new_mac):
    print("[+] changing mac address for " + interface + " to new_mac " + new_mac)
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

    # "call " This function allows to run system commands but it runs the command in the foreground.
    # It doesn't run it in the background it doesn't run it in a different thread and it waits for the command
    # to finish executing before it moves to the next line.
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    # print(ifconfig_result)
    mac_address_change_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    # checking if this variable actually got the mac address value.
    # If it did then will get a printed
    # Otherwise we're gonna say sorry I couldn't read the MAC address.
    if mac_address_change_result:
        # usually if there is more than one match in this trend these will be placed into a number of
        # groups and you can iterate through them by saying 0 1 to 3.
        return mac_address_change_result.group(0)
    else:
        print("[-] sorry , could not read MAC address ..  ")


options = get_arguments()
current_mac = get_current_mac(options.interface)
print("current MAC = " + str(current_mac))
change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC address was successfully changed to  " + current_mac)
else:
    print("[-] MAC address did not get changed ")





