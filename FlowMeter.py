#!/usr/bin/python
import pcap
import sys
import socket
from Sniffer import Sniffer
from BasicPacketInfo import BasicPacketInfo
from BasicFlow import BasicFlow
from FlowGenerator import FlowGenerator
from FlowProcessor import FlowProcessor

from struct import *


class FlowMeter():

	def capture_file(self):
		flow_log = {}
		count = 0
		#flowGen = new FlowGenerator(true,120000000L, 5000000L);
		flowGen = FlowGenerator(True,120000000, 5000000)
		flowProc = FlowProcessor()
		ip6count = 0
		ip4count = 0
		ip4udp = 0
		ip4tcp = 0
		ip4weird = 0
		weirdcount = 0
		preprocess = Sniffer(10)
		packetInfo = None
		header = 0 
		sniffer = pcap.pcap(name='6.pcap', promisc=True, immediate=True,timeout_ms=12000000000)

	# initialises address structure helps in printing
		addr = lambda pkt, offset: ':'.join(str(ord(pkt[i])) for i in
                                    range(offset, offset + 4))
		print ('Sniffer built successfully..')

	# loop that process packet as soon as they are caught by sniffer
		for (ts, pkt) in sniffer:
			ts = ts * 1000000

			count = count + 1
			pkt = pkt[sniffer.dloff:]  # remove link layer data
		
			ip_hdr = pkt[0:20]
			iph = unpack('!BBHHHBBH4s4s', ip_hdr)
		
			version_ihl = iph[0]
			version = version_ihl >> 4
		
			packetInfo = None

			if version == 4:
				ip4count = ip4count + 1 
				packetInfo = flowProc.getIpv4Info(ts, pkt)

				if packetInfo.getProtocol() == 17:
					ip4udp = ip4udp + 1 
				elif packetInfo.getProtocol() == 6:
					ip4tcp = ip4tcp + 1

			elif version == 6:
				ip6count = ip6count + 1
				packetInfo = flowProc.getIpv6Info(ts, pkt)
			else:
				weirdcount = weirdcount + 1
	
			flowGen.addPacket(packetInfo)
	
		print ('Printing our list!')
		flowGen.listBasic()
		print('IPV6 packets:' + str(ip6count))
		print('IPV4 packets:' + str(ip4count))
		print (' of which udp:' + str(ip4udp))
		print (' of which tcp:' + str(ip4tcp))
		#print (' of which other:' + str(ip4weird))
		print('Weird packets:' + str(weirdcount))
		print('Total packets:' + str(count))

flowmeter = FlowMeter()
flowmeter.capture_file()