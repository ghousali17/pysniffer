#!/usr/bin/python
# -*- coding: utf-8 -*-
import pcap
import sys
import socket
from BasicPacketInfo import BasicPacketInfo
from BasicFlow import BasicFlow
from FlowGenerator import FlowGenerator
from struct import *

print ('lets go!')

# creates sniffer!

sniffer = pcap.pcap(name='6.pcap', promisc=True, immediate=True,
                    timeout_ms=50)

# initialises address structure helps in printing

addr = lambda pkt, offset: ':'.join(str(ord(pkt[i])) for i in
                                    range(offset, offset + 4))
print ('Sniffer built successfully..')

# loop that process packet as soon as they are caught by sniffer

flow_log = {}
count = 0


# This function creates a Basic packet info structure from raw IP packets (Ethernet layer is already discarded)

def getIpv4Info(ts, pkt):

    packetInfo = None

    # extracts ip header only

    ip_hdr = pkt[0:20]
    iph = unpack('!BBHHHBBH4s4s', ip_hdr)

    version_ihl = iph[0]
    version = version_ihl >> 4  # converts version into string convertible format
    
    ihl = version_ihl & 0xF  # version gives us ipl
    #print ('Version:{}'.format(version))
    pktHeaderLength = ihl * 4  # ipl is in that weird form so we convert it into bytes

    pktLength = iph[2]  # ihl + datlen
    protocol = iph[6]

    if protocol == 6:
        tcp_hdr = pkt[pktHeaderLength:pktHeaderLength + 20]
        tcph = unpack('!HHLLBBHHH', tcp_hdr)

                 # calculates TCP segment and header length

        tcp_offset = tcph[4] >> 4
        segmentHeaderLength = tcp_offset * 4
        segmentLength = pktLength - (pktHeaderLength + segmentHeaderLength)

                # set src,dst,srcPort,dstPort,protocol,timestamp

        packetInfo = BasicPacketInfo(
                    iph[8],
                    iph[9],
                    tcph[0],
                    tcph[1],
                    protocol,
                    ts,
                    1,
                    )
        packetInfo.setTCPWindow(tcph[6])
        packetInfo.setFlags(tcph[5])
        packetInfo.setPayloadBytes(segmentLength)
        packetInfo.setHeaderBytes(segmentHeaderLength) 
        packetInfo = None  
         
    elif protocol == 17:
                        # print '\n' + str(packetInfo.getTimestamp())

        udp_hdr = pkt[pktHeaderLength:pktHeaderLength + 8]
        udph = unpack('!HHHH', udp_hdr)
        packetInfo = BasicPacketInfo(iph[8],iph[9],udph[0],udph[1],protocol,ts,1)
        packetInfo.setPayloadBytes(udph[2]-8)
        #print("Size:{}".format(udph[2]-8))
        packetInfo.setHeaderBytes(8)
        #packetInfo = None 
        #x = checksum(udp_hdr)
        #if x !=0:
            #print("checksum:::::::::{}".format(checksum(ip_hdr)))
            #packetInfo = None
        
        


                

    return packetInfo
    

def getIpv6Info(ts, pkt):
    print("Got ipv6")
    packetInfo = None
    pktHeaderLength = 40
    ip_hdr = pkt[0:40]

    iph = unpack('!BHsHBB16s16s', ip_hdr)
    # converts version into string convertible format

    payloadLength = iph[3]  # ihl + datlen
    protocol = iph[4]
    
    if protocol == 6:
        tcp_hdr = pkt[pktHeaderLength:pktHeaderLength + 20]
        tcph = unpack('!HHLLBBHHH', tcp_hdr)

        tcp_offset = tcph[4] >> 4
        segmentHeaderLength = tcp_offset * 4
        segmentLength = payloadLength - segmentHeaderLength
        packetInfo = BasicPacketInfo(
                    iph[6],
                    iph[7],
                    tcph[0],
                    tcph[1],
                    protocol,
                    ts,
                    1,
                    )
        packetInfo.setTCPWindow(tcph[6])
        packetInfo.setFlags(tcph[5])
        packetInfo.setPayloadBytes(segmentLength)
        packetInfo.setHeaderBytes(segmentHeaderLength)
        packetInfo =  None
    elif protocol == 17:
        udp_hdr = pkt[pktHeaderLength:pktHeaderLength + 8]
        udph = unpack('!HHHH', udp_hdr)
        packetInfo = BasicPacketInfo(iph[6],iph[7],udph[0],udph[1],protocol,ts,1)
        '''print('TS:{}'.format(ts))
        print ('Payload:{}'.format(iph[3]))
        print ('NH:{}'.format(iph[4]))
        print ('Hop:{}'.format(iph[5]))
        print ('SRC:{}'.format(socket.inet_ntop(10,iph[6])))
        print ('DEST:{}'.format(socket.inet_ntop(10,iph[7])))
        print ('Length of SRC:{}'.format(len(iph[6])))
        print ('SRCPORT:{}'.format(udph[0]))
        print ('DSTPORT:{}'.format(udph[1]))
        print()'''

        packetInfo.setPayloadBytes(udph[2]-8)
        packetInfo.setHeaderBytes(8)
        
    
    


    
    return packetInfo

#b = 4 , s = 8 , h =16 
def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1] )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    #s = s + (s >> 16);
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s
 


flowGen = FlowGenerator(True, 120000000, 5000000)
count = 0
for (ts, pkt) in sniffer:
    pkt = pkt[sniffer.dloff:]  # remove link layer data
    #if count == 0:
    #    st = ts
    #    ts = 0
    #    count = 10
    #else:
    #    ts = ts - st

    ip_hdr = pkt[0:20]
    iph = unpack('!BBHHHBBH4s4s', ip_hdr)

    version_ihl = iph[0]
    version = version_ihl >> 4
    packetInfo = None
    if version == 4:
        #x = checksum([bytes(iph[0])])
        x = checksum(ip_hdr)
        if x != 0:
            print("checksum{}".format(checksum(ip_hdr)))

        packetInfo = getIpv4Info(ts, pkt)
    #else:
        #print("Rejection")
    


    # true,120000000L, 5000000L

    flowGen.addPacket(packetInfo)

print ('Printing our list!')


flowGen.listBasic()

            