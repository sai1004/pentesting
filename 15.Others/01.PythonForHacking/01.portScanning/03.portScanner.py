#!/usr/bin/python


from socket import *

import optparse

from threading import *

from termcolor import colored


""" This is 3 function"""

def connScan(tgtHost, tgtPort):
    try:
        sock = socket(AF_INET,SOCK_STREAM)
        sock.connect((tgtHost,tgtPort))
        print(" [+] port {} tcp is Open".format(tgtPort))

    except:
        print(" [-] port {} tcp is Closed".format(tgtPort))

    finally:
        sock.close()

""" This is 2 function"""


def portScan(tgtHost, tgtPorts):
  
    try:
        tgtIP = gethostbyname(tgtHost)

    except:
        print("Unknown Host {} ".format(tgtHost))


    try:
        tgtName = gethostbyaddr(tgtIP)
        print(" [+] Scan Results For " + tgtName[0])
    except:
        print(" [+] Scan Results For " + tgtIP)
    setdefaulttimeout(1)

    for tgtPort in tgtPorts:
        t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()

""" This is main function"""

def main():

    parser = optparse.OptionParser('Usage Of Program: ' + '-H <traget host> -p <target port>')

    parser.add_option('-H', dest='tgtHost', type='string',help='specify target host')

    parser.add_option('-p', dest='tgtPort', type='string',help='specify target ports seperated by comma')

    (options, args) = parser.parse_args()

    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')

    if (tgtHost == None) | (tgtPorts[0] == None):
        print(parser.usage)
        exit(0)

    portScan(tgtHost,tgtPorts)


if __name__ == '__main__':
    main()
