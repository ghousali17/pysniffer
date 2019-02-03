import pcap, sys, socket
from struct import *

print('lets go!')

#creates sniffer!
sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)


#initialises address structure helps in printing
addr = lambda pkt, offset: ':'.join(str(ord(pkt[i])) for i in range(offset, offset + 4))
print('Sniffer built successfully..')



class Flow():
    def __init__(self, iph, tcp_hdr, flow_id):
        
#IP parameters of the flow
        self.id = flow_id
        self.src_ip = iph[8]
        self.dst_ip = iph[9]
        self.proto = iph[6]

        version_ihl =  iph[0]
        version = version_ihl >> 4  #converts version into string convertible format
        ihl = version_ihl & 0xF    #version gives us ipl
        iph_length = ihl * 4   #ipl is in that weird form so we convert it into bytes
        ttl = iph[5] #ttl for ip packet
        ip_len = iph[2] #ihl + datlen
        protocol = iph[6] #protocol bytes of upper layyer.
        
        
        tcph = unpack('!HHLLBBHHH',tcp_hdr)
        
#Transport layer parameters of the flow 
        
        self.src_port = tcph[0]
        self.dst_port = tcph[1]


    def print_flow(self):
        print 'Flow ID' + str(self.id)
        print 'Protocol : ' + str(self.proto) + ' Source Address : ' + str(socket.inet_ntoa(self.src_ip)) + ' Destination Address : ' + str(socket.inet_ntoa(self.dst_ip))
        print 'SRC PORT : ' + str(self.src_port) + ' DST PORT : ' + str(self.dst_port)






count = 0
#loop that process packet as soon as they are caught by sniffer
flow_log = {}

for ts, pkt in sniffer:
    count = count + 1


    pkt = pkt[sniffer.dloff:] #remove link layer data

    ip_hdr = pkt[0:20] #extracts ip header only

    iph = unpack('!BBHHHBBH4s4s', ip_hdr) #unpack ip header string to form a cool array

    version_ihl =  iph[0]
    version = version_ihl >> 4  #converts version into string convertible format
    ihl = version_ihl & 0xF    #version gives us ipl

    iph_length = ihl * 4   #ipl is in that weird form so we convert it into bytes

    ttl = iph[5] #ttl for ip packet
    ip_len = iph[2] #ihl + datlen

    protocol = iph[6] #protocol bytes of upper layyer.
    s_addr = socket.inet_ntoa(iph[8])  #int_ntoa
    d_addr = socket.inet_ntoa(iph[9])

    #using RFC protocol numbers to determine the protocol employed at he transport layer
    



    if protocol == 1:
        #print 'Version : ' + str(version) + ' IP Header Length : ' + str(iph_length) + ' Total length : ' + str(ip_len) + ' TTL : ' + str(ttl) + ' Protocol : ' + 'ICMP' + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
        lol = 5
    elif protocol == 17:
       # print 'Version : ' + str(version) + ' IP Header Length : ' + str(iph_length) + ' Total length : ' + str(ip_len) + ' TTL : ' + str(ttl) + ' Protocol : ' + 'UDP' + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
        udp_hdr = pkt[iph_length:iph_length + 8]
        udph = unpack('!HHHH', udp_hdr)   
      #  print 'SRC PORT : ' + str(udph[0]) + ' DST PORT : ' + str(udph[1])

    elif protocol == 6:
        print 'Version : ' + str(version) + ' IP Header Length : ' + str(iph_length) + ' Total length : ' + str(ip_len) + ' TTL : ' + str(ttl) + ' Protocol : ' + 'TCP' + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
        tcp_hdr = pkt[iph_length:iph_length + 20]
        #tcph = unpack('!HHLLBBHHH',tcp_hdr)
        #print 'SRC PORT : ' + str(tcph[0]) + ' DST PORT : ' + str(tcph[1])       
        flow = Flow(iph, tcp_hdr, count)
        flow.print_flow()
        flow_log[str(count)] = flow
    else:
        lol = 10 
        #print 'Version : ' + str(version) + ' IP Header Length : ' + str(iph_length) + ' Total length : ' + str(ip_len) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

    if count == 10:
        break 

    print ('Printing our list!')
    for key,val in flow_log.items():
        print key
        val.print_flow()