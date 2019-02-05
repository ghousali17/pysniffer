#!/usr/bin/python
# -*- coding: utf-8 -*-

from BasicPacketInfo import BasicPacketInfo
from statSummary import summaryStatistics
import socket


class BasicFlow:

    Act_data_pkt_forward = 0

    def __init__(self, bidirectional, packetInfo):
        self.__count = 1

        # non-static

        self.__Act_data_pkt_forward = 0
        self.__Init_Win_bytes_forward = -1
        self.__Init_Win_bytes_backward = -1

        self.initParameters()
        self.__flowStartTime = 0
        self.__isBidirectional = bidirectional
        self.__src = packetInfo.getSrc()
        self.__dst = packetInfo.getDst()
        self.__srcPort = packetInfo.getSrcPort()
        self.__dstPort = packetInfo.getDstPort()
        self.firstPacket(packetInfo)
        

    def initParameters(self):
        self.__forward = None
        self.__backward = None
        self.__flowIAT = summaryStatistics()
        self.__forwardIAT = summaryStatistics()
        self.__backwardIAT = summaryStatistics()
        self.__flowActive = summaryStatistics()
        self.__flowIdle = summaryStatistics()
        self.__flowLengthStats = summaryStatistics()
        self.__fwdPktStats = summaryStatistics()
        self.__bwdPktStats = summaryStatistics()
        self.__flagCounts = None

        # initFlags();

        self.__forwardBytes = 0
        self.__backwardBytes = 0
        self.__startActiveTime = 0
        self.__endActiveTime = 0
        self.__src = None
        self.__dst = None
        self.__fPSH_cnt = 0
        self.__bPSH_cnt = 0
        self.__fURG_cnt = 0
        self.__bURG_cnt = 0
        self.__fHeaderBytes = 0
        self.__bHeaderBytes = 0

    def addPacket(self):
        self.__count = self.__count + 1

    def printStat(self):
    	'''
        print '\nStart Time: {}'.format(self.__flowStartTime)
        print 'Last Time: {}'.format(self.__flowLastSeen)
        print 'Protocol: {}'.format(self.__protocol)
        print 'forward HBytes: {}'.format(self.__fHeaderBytes)
        print 'forward Bytes: {}'.format(self.__forwardBytes)
        print 'backward HBytes: {}'.format(self.__bHeaderBytes)
        print 'backward Bytes: {}'.format(self.__backwardBytes)
        print 'Flow ID: {}'.format(self.__flowId)
		'''
    def printFinalStat(self):
    	if len(self.__src) == 16:
    		print ('{}'.format(self.__flowId))        
    		print ('{}:::{}:::{}:::{}:::{}:::{}:::{}:::{}:::{}'.format(socket.inet_ntop(10,self.__src),
                self.__srcPort, socket.inet_ntop(10,self.__dst),
                self.__dstPort, self.__protocol,self.__fwdPktStats.getCount(), self.__bwdPktStats.getCount(),self.__fwdPktStats.getSum(),self.__bwdPktStats.getSum()))


    	else:
    		print ('{}'.format(self.__flowId))        
    		print ('{}:::{}:::{}:::{}:::{}:::{}:::{}:::{}:::{}'.format(socket.inet_ntoa(self.__src),
                self.__srcPort, socket.inet_ntoa(self.__dst),
                self.__dstPort, self.__protocol,self.__fwdPktStats.getCount(), self.__bwdPktStats.getCount(),self.__fwdPktStats.getSum(),self.__bwdPktStats.getSum()))

    def firstPacket(self, packetInfo):

        # 1,2,3

        self.__flowStartTime = packetInfo.getTimestamp()
        self.__flowLastSeen = packetInfo.getTimestamp()
        self.__startActiveTime = packetInfo.getTimestamp()
        self.__endActiveTime = packetInfo.getTimestamp()
        self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
        

        if self.__src == None:
            self.__src = packetInfo.getSrc()
            self.srcPort = packetInfo.getSrcPort()

        if self.__dst == None:
            self.__dst = packetInfo.getDst()
            self.dstPort = packetInfo.getDstPort()

        if self.__src == packetInfo.getSrc():

            self.__min_seg_size_forward = packetInfo.getHeaderBytes()
            Init_Win_bytes_forward = packetInfo.getTCPWindow()
            self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
            self.__fwdPktStats.addValue(packetInfo.getPayloadBytes())
            self.__fHeaderBytes = packetInfo.getHeaderBytes()
            self.__forwardLastSeen = packetInfo.getTimestamp()
            self.__forwardBytes += packetInfo.getPayloadBytes()

             # this.backward.add(packet);

            if packetInfo.hasFlagPSH():
                self.__fPSH_cnt += 1

            if packetInfo.hasFlagURG():
                self.__fURG_cnt += 1
        else:

            Init_Win_bytes_backward = packetInfo.getTCPWindow()
            self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
            self.__bwdPktStats.addValue(packetInfo.getPayloadBytes())
            self.__bHeaderBytes = packetInfo.getHeaderBytes()
            self.__backwardLastSeen = packetInfo.getTimestamp()
            self.__backwardBytes += packetInfo.getPayloadBytes()

            # this.backward.add(packet);

            if packetInfo.hasFlagPSH():
                self.__fPSH_cnt += 1

            if packetInfo.hasFlagURG():
                self.__fURG_cnt += 1

        # (2/2)

        self.__protocol = packetInfo.getProtocol()
        self.__flowId = packetInfo.getFlowId()

    def addPacket(self, packetInfo):
        currentTimestamp = packetInfo.getTimestamp()

        if self.__isBidirectional:

            self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
            if self.__src == packetInfo.getSrc():
                if packetInfo.getPayloadBytes() >= 1:
                    self.__Act_data_pkt_forward += 1

                self.__fwdPktStats.addValue(packetInfo.getPayloadBytes())
                self.__fHeaderBytes += packetInfo.getHeaderBytes()

                # 4

                self.__forwardBytes += packetInfo.getPayloadBytes()

                # 5

                self.__forwardLastSeen = currentTimestamp
            else:

                # self.__min_seg_size_forward =

                self.__bwdPktStats.addValue(packetInfo.getPayloadBytes())
                self.__Init_Win_bytes_backward = \
                    packetInfo.getTCPWindow()
                self.__bHeaderBytes += packetInfo.getHeaderBytes()

                # 3

                self.__backwardBytes += packetInfo.getPayloadBytes()

                # 4

                self.__backwardLastSeen = currentTimestamp
        else:

            if packetInfo.getPayloadBytes >= 1:
                self.__Act_data_pkt_forward += 1
            self.__fwdPktStats.addValue(packetInfo.getPayloadBytes())
            self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
            self.__fHeaderBytes += packetInfo.getHeaderBytes()

            # 4

            self.__forwardBytes += packetInfo.getPayloadBytes()
            self.__forwardIAT.addValue(currentTimestamp
                    - self.__forwardLastSeen)
            self.__forwardLastSeen = currentTimestamp

            # 6

        self.__flowIAT.addValue(packetInfo.getTimestamp()
                                - self.__flowLastSeen)
        self.__flowLastSeen = currentTimestamp

    def getFlowStartTime(self):
        return self.__flowStartTime



			