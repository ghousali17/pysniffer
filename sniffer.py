import pcap, sys, socket 
from BasicPacketInfo import BasicPacketInfo
from BasicFlow import BasicFlow
from FlowGenerator import FlowGenerator
from struct import *

print('lets go!')

#creates sniffer!
sniffer = pcap.pcap(name='2.pcap', promisc=True, immediate=True, timeout_ms=50)


#initialises address structure helps in printing
addr = lambda pkt, offset: ':'.join(str(ord(pkt[i])) for i in range(offset, offset + 4))
print('Sniffer built successfully..')


#loop that process packet as soon as they are caught by sniffer
flow_log = {}
count = 0
#This function creates a Basic packet info structure from raw IP packets (Ethernet layer is already discarded)
def getIpv4Info(ts,pkt):

    packetInfo = None
    #extracts ip header only
    ip_hdr = pkt[0:20] 
    iph = unpack('!BBHHHBBH4s4s', ip_hdr) 

    version_ihl =  iph[0]
    version = version_ihl >> 4  #converts version into string convertible format
    ihl = version_ihl & 0xF    #version gives us ipl
    pktHeaderLength = ihl * 4   #ipl is in that weird form so we convert it into bytes
    

    pktLength = iph[2] #ihl + datlen
    protocol = iph[6] 




    if protocol == 6:
        tcp_hdr = pkt[pktHeaderLength:pktHeaderLength + 20]
        tcph = unpack('!HHLLBBHHH',tcp_hdr)
         #calculates TCP segment and header length
        tcp_offset = (tcph[4] >> 4)
        segmentHeaderLength = tcp_offset * 4 
        segmentLength = pktLength - (pktHeaderLength + segmentHeaderLength)

        #set src,dst,srcPort,dstPort,protocol,timestamp 
        packetInfo = BasicPacketInfo(iph[8],iph[9],tcph[0],tcph[1],protocol,ts,1)  
        packetInfo.setTCPWindow(tcph[6])
        packetInfo.setFlags(tcph[5])
        packetInfo.setPayloadBytes(segmentLength)
        packetInfo.setHeaderBytes(segmentHeaderLength)
       
        #print '\n' + str(packetInfo.getTimestamp())
       
    elif protocol == 17:
        udp_hdr = pkt[pktHeaderLength:pktHeaderLength + 8]
        udph = unpack('!HHHH', udp_hdr)
        #packetInfo = BasicPacketInfo(iph[8],iph[9],udph[0],udph[1],protocol,ts,1)  
        

    return packetInfo


flowGen = FlowGenerator(True, 120000000, 5000000)
    
for ts, pkt in sniffer:
    pkt = pkt[sniffer.dloff:] #remove link layer data
    if count == 0:
        st = ts
        ts = 0 
        count = 10 
    else:
        ts = ts - st
    '''
    ip_hdr = pkt[0:20] #extracts ip header only
    iph = unpack('!BBHHHBBH4s4s', ip_hdr) #unpack ip header string to form a cool array
    version_ihl =  iph[0]
    version = version_ihl >> 4  #converts version into string convertible format
    ihl = version_ihl & 0xF    #version gives us ipl
    pktHeaderLength = ihl * 4   #ipl is in that weird form so we convert it into bytes
    ttl = iph[5] #ttl for ip packet
    ip_len = iph[2] #ihl + datlen

    protocol = iph[6] #protocol bytes of upper layyer.
    s_addr = socket.inet_ntoa(iph[8])  #int_ntoa
    d_addr = socket.inet_ntoa(iph[9])

    #using RFC protocol numbers to determine the protocol employed at he transport layer
    '''
    packetInfo = getIpv4Info(ts,pkt)
    #true,120000000L, 5000000L
    flowGen.addPacket(packetInfo)
    if packetInfo != None:
        #packetInfo.printTcp()
        if packetInfo.getFlowId() in flow_log:
            flow_log[packetInfo.getFlowId()].addPacket(packetInfo)
        else:
            flow_log[packetInfo.getFlowId()] = BasicFlow(True, packetInfo)
            flow_log[packetInfo.getFlowId()].firstPacket(packetInfo)
    
print ('Printing our list!')
for key,val in flow_log.items():        
    val.printStat()
     
flowGen.listBasic()