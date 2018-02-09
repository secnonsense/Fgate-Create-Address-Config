#!/usr/bin/python

#This script accepts a file holding a list of IP addresses (one per line) as an argument & then contructs fortigate address
#objects and a group object including all of the address objects.  Objects are named as FILENAME_IPADDRESS and
#the group is named as FILENAME_Group, so name your file accordingly.  Then the output file named -
#add_addresses_FILENAME can be used as a script to add the objects to the Fortigate directly.  The input file
#will accept cidr notation and convert into appropriate net mask (using cidr_to_netmask - stolen from stackoverflow)
#lack of cidr notation will be treated as a /32.

import sys
import socket
import struct

if len(sys.argv) < 2:
    print "\nThis script is used to to convert a file with a list of IP's into a Fortigate Config script."
    print "\nUsage: ./create_address_file.py IPFILE\n"
    quit()

def cidr_to_netmask(cidr):
    network, net_bits = cidr.split('/')
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return network, netmask

object=[]
with open(sys.argv[1]) as infile:
    data = infile.readlines()
data = [x.strip() for x in data] 

infile.close()

fname=str(sys.argv[1])

with open('add_address_' + fname, 'w') as outfile:
    outfile.write('config firewall address\n')
   
    for address in data:
        net=address
        nmask='255.255.255.255'
        if '/' in address:
            net,nmask=cidr_to_netmask(address) 
        object.append('"' + fname + '_' + address + '"')
        outfile.write('edit ' + object[-1] + '\n')
        outfile.write('set subnet ' + net + ' ' + nmask + '\n')
        outfile.write('next\n')
        

    outfile.write('end\n')

    outfile.write('config firewall addrgrp\n')
    outfile.write('edit ' + fname + '_Group\n')
    outfile.write('set member ')
    for value in object:
        outfile.write(" " + value)
    outfile.write('\nnext\n') 
    outfile.write('end\n')

outfile.close()