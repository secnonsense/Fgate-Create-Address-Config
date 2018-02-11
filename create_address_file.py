#!/usr/bin/python

#This script accepts a file holding a list of IP addresses (one per line) as an argument & then constructs fortigate address
#objects and a group object including all of the address objects.  Objects are named as FILENAME_IPADDRESS and
#the group is named as FILENAME_Group, so name your file accordingly.  Then the output file named -
#add_addresses_FILENAME can be used as a script to add the objects to the Fortigate directly.  The input file
#will accept cidr notation and convert into appropriate net mask. Lack of cidr notation will be treated as /32


import sys

def cidr_to_mask(value):
    
    def convert(binary):
        binmask=int('11111111',2) - int(binary,2)
        return binmask
   
    def bitcalc(base):
        binary=''
        bits = base - int(cidr)
        if bits > 0:
            for x in range (0,bits):
                binary = binary + '1'
        else:
            binary='0'
        return binary
    
    net, cidr = value.split('/')
    
    if int(cidr)/4 < 2:
        oct2 = oct3 = oct4 = 0
        octbase=8
        bi=bitcalc(octbase)
        oct1 = convert(bi)
    elif int(cidr)/4 < 4:
        oct1 = 255 
        oct3 = oct4 = 0
        octbase=16
        bi=bitcalc(octbase)
        oct2 = convert(bi) 
    elif int(cidr)/4 < 6:
        oct2 = oct1 = 255 
        oct4 = 0
        octbase=24
        bi=bitcalc(octbase)
        oct3 = convert(bi)
    elif int(cidr)/4 <= 8:
        oct2 = oct3 = oct1 = 255
        octbase=32
        bi=bitcalc(octbase)
        oct4 = convert(bi)  
    
    smask=str(oct1) + '.' + str(oct2) + '.' + str(oct3) + '.' + str(oct4)
    return net, smask


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
        cidrval=''
        nmask='255.255.255.255'
        if '/' in address:
            cidrval='_' + address.split('/')[-1]
            net,nmask=cidr_to_mask(address) 
        object.append('"' + fname + '_' + net + cidrval + '"')
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