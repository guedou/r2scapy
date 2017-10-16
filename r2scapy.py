# Copyright (C) 2017 Guillaume Valadon <guillaume@valadon.net>

"""
r2scapy - a radare2 plugin that decodes packets with Scapy
"""

from __future__ import print_function


from scapy.all import conf
import r2lang
import r2pipe


R2P = r2pipe.open()


def r2scapy(_):
    """Build the plugin"""

    def process(command):
        """Process commands prefixed with 'scapy'"""

        if not command.startswith("scapy"):
            return 0

        # Parse arguments
        tmp = command.split(" ")
        if len(tmp) < 3:
            print("Usage: scapy protocol address [length]")
            return 1

        protocol = tmp[1]
        address = tmp[2]
        if len(tmp) >= 4:
            length = tmp[3]
        else:
            length = None

        # Retrieve data from radare2
        if length:
            command = "p8 %s @ %s" % (length, address)
        else:
            command = "p8 @ %s" % address
        data = R2P.cmd(command)

        # Look for a valid Scapy layer
        layer = [l for l in conf.layers if l.__name__ == protocol]
        if not layer:
            print("Error: '%s' is not a valid Scapy layer !" % protocol)
            return 1

        # Decode the packet
        print(layer[0](data.decode("hex")).command())


    return {"name": "r2scapy",
            "licence": "GPLv3",
            "desc": "decode packets with Scapy",
            "call": process}


# Register the plugin
if not r2lang.plugin("core", r2scapy):
    print("An error occurred while registering r2scapy !")
