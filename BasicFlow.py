#!/usr/bin/python
# -*- coding: utf-8 -*-

from BasicPacketInfo import BasicPacketInfo
from statSummary import summaryStatistics
from datetime import datetime
import socket
import time 


class BasicFlow:

    Act_data_pkt_backward = 0

    def __init__(self, *args):
        self.__count = 1

        # non-static
        #bidirectional, packetInfo, flowSrc = None, flowDst = None, flowSrcPort = None, flowDstPort= None
        #direction none function remaining!
        self.__min_seg_size_forward = -1
        self.__Act_data_pkt_forward = 0
        self.__Init_Win_bytes_forward = -1
        self.__Init_Win_bytes_backward = -1

        if len(args) == 1:
            self.initParameters()
            self.__isBidirectional = True
            self.firstPacket(args[0])

        elif len(args) == 6:
            self.initParameters()
            self.__isBidirectional = args[0]
            self.__src = args[2]
            self.__dst = args[3]
            self.__srcPort = args[4]
            self.__dstPort = args[5]
        
            self.firstPacket(args[1])
            

        elif len(args) == 2:
            self.initParameters()
            self.__isBidirectional = args[0] 
            self.firstPacket(args[1])
      
        
        
        

    def initParameters(self):
        self.__forward = []
        self.__backward = []
        self.__flowIAT = summaryStatistics()
        self.__forwardIAT = summaryStatistics()
        self.__backwardIAT = summaryStatistics()
        self.__flowActive = summaryStatistics()
        self.__flowIdle = summaryStatistics()
        self.__flowLengthStats = summaryStatistics()
        self.__fwdPktStats = summaryStatistics()
        self.__bwdPktStats = summaryStatistics()
        self.__flagCounts = None
        self.initFlags();
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


        #subflow functions use this
        self.__sfLastPacketTS=-1 
        self.__sfCount=0
        self.__sfAcHelper=-1

        #bulk flows
        self.__fbulkDuration=0
        self.__fbulkPacketCount=0
        self.__fbulkSizeTotal=0
        self.__fbulkStateCount=0
        self.__fbulkPacketCountHelper=0
        self.__fbulkStartHelper=0
        self.__fbulkSizeHelper=0
        self.__flastBulkTS=0
        self.__bbulkDuration=0
        self.__bbulkPacketCount=0
        self.__bbulkSizeTotal=0
        self.__bbulkStateCount=0
        self.__bbulkPacketCountHelper=0
        self.__bbulkStartHelper=0
        self.__bbulkSizeHelper=0
        self.__blastBulkTS=0



    
    def firstPacket(self, packetInfo):

        # 1,2,3
        self.updateFlowBulk(packetInfo)
        self.detectUpdateSubflows(packetInfo)
        self.checkFlags(packetInfo)

        self.__flowStartTime = packetInfo.getTimestamp()
        self.__flowLastSeen = packetInfo.getTimestamp()
        self.__startActiveTime = packetInfo.getTimestamp()
        self.__endActiveTime = packetInfo.getTimestamp()
        self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
        
        if self.__src == None:
            self.__src = packetInfo.getSrc()
            self.__srcPort = packetInfo.getSrcPort()

        if self.__dst == None:
            self.__dst = packetInfo.getDst()
            self.__dstPort = packetInfo.getDstPort()

        if self.__src == packetInfo.getSrc:
            
            self.__min_seg_size_forward = packetInfo.getHeaderBytes()
            self.__Init_Win_bytes_forward = packetInfo.getTCPWindow()
            self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
            self.__fwdPktStats.addValue(packetInfo.getPayloadBytes())
            self.__fHeaderBytes = packetInfo.getHeaderBytes()
            self.__forwardLastSeen = packetInfo.getTimestamp()
            self.__forwardBytes += packetInfo.getPayloadBytes()
            self.__forward.append(packetInfo)

            if packetInfo.hasFlagPSH():
                self.__fPSH_cnt += 1

            if packetInfo.hasFlagURG():
                self.__fURG_cnt += 1
        else:
            #print('Started with Rever=========================================================================')
          
            self.__Init_Win_bytes_backward = packetInfo.getTCPWindow()
            self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
            self.__bwdPktStats.addValue(packetInfo.getPayloadBytes())
            self.__bHeaderBytes = packetInfo.getHeaderBytes()
            self.__backwardLastSeen = packetInfo.getTimestamp()
            self.__backwardBytes += packetInfo.getPayloadBytes()
            self.__backward.append(packetInfo)

            if packetInfo.hasFlagPSH():
                self.__bPSH_cnt += 1

            if packetInfo.hasFlagURG():
                self.__bURG_cnt += 1

        # (2/2)

        self.__protocol = packetInfo.getProtocol()
        self.__flowId = packetInfo.getFlowId()

    def addPacket(self, packetInfo):
        currentTimestamp = packetInfo.getTimestamp()

        if self.__isBidirectional:
            #print('Flow is BI')

            self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
            if self.__src == packetInfo.getSrc():
                if packetInfo.getPayloadBytes() >= 1:
                    self.__Act_data_pkt_forward += 1

                self.__fwdPktStats.addValue(packetInfo.getPayloadBytes())
                self.__fHeaderBytes += packetInfo.getHeaderBytes()
                self.__forward.append(packetInfo)
                self.__forwardBytes += packetInfo.getPayloadBytes()
                if len(self.__forward) > 1:
                    self.__forwardIAT.addValue(currentTimestamp - self.__forwardLastSeen)

                self.__forwardLastSeen = currentTimestamp


                if self.__min_seg_size_forward != None:
                    if self.__min_seg_size_forward > packetInfo.getHeaderBytes():
                        self.__min_seg_size_forward = packetInfo.getHeaderBytes()
                else:
                    self.__min_seg_size_forward = packetInfo.getHeaderBytes()

            else:
                #print('Reverse met!')
                self.__bwdPktStats.addValue(packetInfo.getPayloadBytes())
                self.__Init_Win_bytes_backward = packetInfo.getTCPWindow()
                self.__bHeaderBytes += packetInfo.getHeaderBytes()
                self.__backward.append(packetInfo)
                self.__backwardBytes += packetInfo.getPayloadBytes()
                if len(self.__backward) > 1 :
                    self.__backwardIAT.addValue(currentTimestamp - self.__backwardLastSeen)
                self.__backwardLastSeen = currentTimestamp
        else:
            #print("================================================================================")
            if packetInfo.getPayloadBytes() >= 1:
                self.__Act_data_pkt_forward += 1
            self.__fwdPktStats.addValue(packetInfo.getPayloadBytes())
            self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())
            self.__fHeaderBytes += packetInfo.getHeaderBytes()
            self.__forward.append(packetInfo)
            self.__forwardBytes += packetInfo.getPayloadBytes()
            self.__forwardIAT.addValue(currentTimestamp
                    - self.__forwardLastSeen)
            self.__forwardLastSeen = currentTimestamp
            if self.__min_seg_size_forward != None:
                if self.__min_seg_size_forward > packetInfo.getHeaderBytes():
                    self.__min_seg_size_forward = packetInfo.getHeaderBytes()
            else:
                self.__min_seg_size_forward = packetInfo.getHeaderBytes()


        self.__flowIAT.addValue(packetInfo.getTimestamp() - self.__flowLastSeen)
        self.__flowLastSeen = packetInfo.getTimestamp()

    def getFlowStartTime(self):
        return self.__flowStartTime


#1
    def getfPktsPerSecond(self):
        duration = self.__flowLastSeen - self.__flowStartTime
        if duration == 0 :
            return 0
        else:
            return (len(self.__forward)/(duration/1000000.0))
#2
    def getbPktsPerSecond(self):
        duration = self.__flowLastSeen - self.__flowStartTime
        if duration == 0 :
            return 0
        else:
            return (len(self.__backward)/(duration/1000000.0))   
#3
    def getDownUpRatio(self):           
        if len(self.__forward) > 0:                     
            return (float(len(self.__backward)) / float(len(self.__backward)))
        else:
            return 0 
#4
    def getAvgPacketSize(self):
        if self.packetCount() > 0:
            return (self.flowLengthStats.getSum()/ self.packetCount())
        else:
            return 0
#5
    def fAvgSegmentSize(self):
        if len(self.__forward) > 0:
            return (self.__fwdPktStats.getSum()/(float(len(self.__forward))))
        else:
            return 0
#6 
    def bAvgSegmentSize(self):
        if len(self.__backward) > 0:
            return (self.__bwdPktStats.getSum()/(float(len(self.__backward))))
        else:
            return 0
#7    
    def initFlags(self):
        self.__fFIN_cnt = 0
        self.__fPSH_cnt = 0
        self.__fURG_cnt = 0
        self.__fECE_cnt = 0
        self.__fSYN_cnt = 0
        self.__fACK_cnt = 0
        self.__fCWR_cnt = 0
        self.__fRST_cnt = 0


#8
    def checkFlags(self,packetInfo):
        if packetInfo.hasFlagFIN():
            self.__fFIN_cnt += 1
        if packetInfo.hasFlagSYN():
            self.__fSYN_cnt += 1
        if packetInfo.hasFlagRST():
            self.__fRST_cnt += 1
        if packetInfo.hasFlagPSH():
            self.__fPSH_cnt += 1
        if packetInfo.hasFlagACK():
            self.__fACK_cnt += 1
        if packetInfo.hasFlagURG():
            self.__fURG_cnt += 1
        if packetInfo.hasFlagECE():
            self.__fECE_cnt += 1
        if packetInfo.hasFlagCWR():
            self.__fCWR_cnt += 1
#9
    def getSlow_fbytes(self):
        if self.__sfCount <= 0:
            return 0
        else:
            return self.__forwardBytes/sfCount
#10
    def getSflow_fpackets(self):
        if self.__sfCount <= 0:
            return 0
        else:
            return len(self.__forward)/sfCount
#11
    def getSlow_bbytes(self):
        if self.__sfCount <= 0:
            return 0
        else:
            return self.__backwardBytes/sfCount
#12
    def getSflow_bpackets(self):
        if self.__sfCount <= 0:
            return 0
        else:
            return len(self.__backward)/sfCount
#13
    def detectUpdateSubflows(self, packet):
        if self.__sfLastPacketTS == -1:
            self.__sfLastPacketTS = packet.getTimestamp()
            self.__sfAcHelper = packet.getTimestamp()
        if (packet.getTimestamp()-(self.__sfLastPacketTS)/1000000) > 1.0:
            self.__sfCount += 1
            self.__lastSFduration = packet.getTimestamp() - self.__sfAcHelper
            self.updateActiveIdleTime(packet.getTimestamp()-self.__sfLastPacketTS, 5000000)
            self.__sfAcHelper = packet.getTimestamp()
        self.__sfLastPacketTS = packet.getTimestamp()

#14
    def updateFlowBulk(self,packet):
        if self.__src == packet.getSrc():
            self.updateForwardBulk(packet,self.__blastBulkTS)
        else:
            1#self.updateBackwardBulk(packet,self.__flastBulkTS)

    def updateForwardBulk(self,packet,tsOflastBulkInOther):
        size - packet.getPayloadBytes()
        if tsOflastBulkInOther > self.__fbulkStartHelper:
            self.__fbulkStartHelper = 0
        if size <= 0:
            return 
        packet.getPayloadPacket()

        if self.__fbulkStartHelper == 0:
            self.__fbulkStartHelper = packet.getTimetamp()
            self.__fbulkPacketCountHelper = 1
            self.__fbulkSizeHelper = sizeself.__flastBulkTS = packet.getTimetamp()
        else:
            if ((packet.getTimestamp()- self.__flastBulkTS)/ 1000000) > 1.0:
                self.__fbulkStartHelper = packet.getTimestamp()
                self.__flastBulkTS = packet.getTimestamp()
                self.__fbulkPacketCountHelper = 1
                self.__fbulkSizeHelper = size
            else:
                self.__fbulkPacketCountHelper += 1
                self.__fbulkSizeHelper += size
                if self.__fbulkPacketCountHelper == 4:
                    self.__fbulkStateCount +=1
                    self.__fbulkPacketCount += fbulkPacketCountHelper
                    self.__fbulkSizeTotal += fbulkSizeHelper
                    self.__fbulkDuration += (packet.getTimestamp() - self.__fbulkStartHelper)
                elif self.__fbulkPacketCountHelper > 4:
                    self.__fbulkPacketCount += 1
                    self.__fbulkSizeTotal += size
                    self.__fbulkDuration += (packet.getTimestamp()- self.flastBulkTS)
                self.flastBulkTS = packet.getTimestamp()
            
    def getFlowDuration(self):
        return round(((self.__flowLastSeen - self.__flowStartTime)), 6)

    def getSrcPort(self):
        return self.__srcPort

    def getDstPort(self):
        return self.__dstPort

    def updateActiveIdleTime(self,currentTime, threshold):
        if currentTime - self.__endActiveTime > threshold:
            if self.__endActiveTime - self.__startActiveTime > 0:
                self.__flowActive.addValue(self.__endActiveTime - self.__startActiveTime)
            self.__flowIdle.addValue(currentTime - self.__endActiveTime)
            self.startActiveTime = currentTime
            self.__endActiveTime = currentTime
        else:
            self.__endActiveTime = currentTime

    def endActiveIdleTime(self,currentTime, threshold, flowTimeOut, isFlagEnd):
        if self.__endActiveTime - self.__startActiveTime > 0:
            self.__flowActive.addValue(self.__endActiveTime - self.__startActiveTime)
        if (not isFlagEnd) and ((flowTimeOut - (self.__endActiveTime - self.__flowStartTime))> 0):
            self.__flowIdle.addValue(flowTimeOut - (self.__endActiveTime - self.__flowStartTime)) 


    
        
        
    def dumpFileHeadings(self, sep, fileObject):
        dump = ""
        dump += str('Flow ID')
        dump += sep 
        dump += 'Src IP'
        dump += sep
        dump += 'Src Port'
        dump += sep
        dump += 'Dst IP'
        dump += sep
        dump += 'Dst Port'
        dump += sep
        dump += 'Timestamp'
        dump += sep
        dump += 'Flow Duration'
        dump += sep
        dump += 'Tot Fwd Pkts'
        dump += sep
        dump += 'Tot Bwd Pkts'
        dump += sep
        dump += 'Totlen Fwd Pkts'
        dump += sep
        dump += 'Totlen Bwd Pkts'
        dump += sep
        dump += 'Fwd Pkt Len Max'
        dump += sep
        dump += 'Fwd Pkt Len Min'
        dump += sep
        dump += 'Fwd Pkt Len Mean'
        dump += sep
        dump += 'Fwd Pkt Len Std'
        dump += sep
        dump += 'Bwd Pkt Len Max'
        dump += sep
        dump += 'Bwd Pkt Len Min'
        dump += sep
        dump += 'Bwd Pkt Len Mean'
        dump += sep
        dump += 'Bwd Pkt Len Std'
        dump += sep
        
        dump += 'Flow Byts/s'
        dump += sep
        dump += 'Flow Pkts/s'
        dump += sep

        dump += 'Flow IAT Mean'
        dump += sep
        dump += 'Flow IAT Std'
        dump += sep
        dump += 'Flow IAT Max'
        dump += sep
        dump += 'Flow IAT Min'
        dump += sep


        dump += 'Fwd IAT Tot'
        dump += sep
        dump += 'Fwd IAT Mean'
        dump += sep
        dump += 'Fwd IAT Std'
        dump += sep
        dump += 'Fwd IAT Max'
        dump += sep
        dump += 'Fwd IAT Min'
        dump += sep

        dump += 'Bwd IAT Tot'
        dump += sep
        dump += 'Bwd IAT Mean'
        dump += sep
        dump += 'Bwd IAT Std'
        dump += sep
        dump += 'Bwd IAT Max'
        dump += sep
        dump += 'Bwd IAT Min'
        dump += sep
        
        dump += 'Fwd PSH Flags'
        dump += sep
        dump += 'Bwd PSH Flags'
        dump += sep
        dump += 'Fwd URG Flags'
        dump += sep
        dump += 'Bwd URG Flags'
        dump += sep
        
        dump += 'Fwd Header Len'
        dump += sep
        dump += 'Bwd Header Len'
        dump += sep
        dump += 'Fwd Pkts/s'
        dump += sep
        dump += 'Bwd Pkts/s'
        dump += sep
        
        dump += 'Pkt Len Min'
        dump += sep
        dump += 'Pkt Len Max'
        dump += sep
        dump += 'Pkt Len Mean'
        dump += sep        
        dump += 'Pkt Len Std'
        dump += sep
        dump += 'Pkt Len Var'
        dump += sep

        fileObject.write(dump)
        fileObject.write('\n')
    
        
        


    def dumpFlowBasedFeatures(self,sep,fileObject):
        print('Dumping flow!')
        dump = ""
        dump += str(self.__flowId)
        dump += sep 
        if len(self.__src) >= 16:
            dump += socket.inet_ntop(10,self.__src)
            dump += sep
            dump += str(self.getSrcPort())
            dump += sep
            dump += socket.inet_ntop(10,self.__dst)
            dump += sep
            dump += str(self.getDstPort())
            dump += sep
        else:
            dump += socket.inet_ntoa(self.__src)
            dump += sep
            dump += str(self.getSrcPort())
            dump += sep
            dump += str(socket.inet_ntoa(self.__dst))
            dump += sep
            dump += str(self.getDstPort())
            dump += sep
        
        dump += str(datetime.utcfromtimestamp(self.__flowStartTime/1000000).strftime('%Y-%m-%d %H:%M:%S'))
        dump += sep
        dump += str(self.getFlowDuration())
        dump += sep
        dump += str(self.__fwdPktStats.getCount())
        dump += sep
        dump += str(self.__bwdPktStats.getCount())
        dump += sep
        dump += str(self.__fwdPktStats.getSum())
        dump += sep
        dump += str(self.__bwdPktStats.getSum())
        dump += sep

        if self.__fwdPktStats.getCount() > 0:
            dump += str(self.__fwdPktStats.getMax())
            dump += sep
            dump += str(self.__fwdPktStats.getMin())
            dump += sep
            dump += str(self.__fwdPktStats.getMean())
            dump += sep
            dump += str(self.__fwdPktStats.getStandardDeviation())
            dump += sep
        else:
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep

        if self.__bwdPktStats.getCount() > 0:
            dump += str(self.__bwdPktStats.getMax())
            dump += sep
            dump += str(self.__bwdPktStats.getMin())
            dump += sep
            dump += str(self.__bwdPktStats.getMean())
            dump += sep
            dump += str(self.__bwdPktStats.getStandardDeviation())
            dump += sep
        else:
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep

        dump += " " #str((self.__forwardBytes + self.__backwardBytes)/(self.getFlowDuration()/1000000))
        dump += sep
        dump += " " #str((self.__bwdPktStats.getCount()+self.__fwdPktStats.getCount())/(self.getFlowDuration()/1000000))
        dump += sep
        dump += str(self.__flowIAT.getMean()) 
        dump += sep
        dump += str(self.__flowIAT.getStandardDeviation())
        dump += sep
        dump += str(self.__flowIAT.getMax())
        dump += sep
        dump += str(self.__flowIAT.getMin())
        dump += sep

        if len(self.__forward) > 1:
            dump += str(self.__forwardIAT.getSum())
            dump += sep
            dump += str(self.__forwardIAT.getMean())
            dump += sep
            dump += str(self.__forwardIAT.getStandardDeviation())
            dump += sep
            dump += str(self.__forwardIAT.getMax())
            dump += sep
            dump += str(self.__forwardIAT.getMin())
            dump += sep
        else:
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep

        if len(self.__backward) > 1:
            dump += str(self.__backwardIAT.getSum())
            dump += sep
            dump += str(self.__backwardIAT.getMean())
            dump += sep
            dump += str(self.__backwardIAT.getStandardDeviation())
            dump += sep
            dump += str(self.__backwardIAT.getMax())
            dump += sep
            dump += str(self.__backwardIAT.getMin())
            dump += sep
        else:
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep

        dump += str(self.__fPSH_cnt)
        dump += sep
        dump += str(self.__bPSH_cnt)
        dump += sep
        dump += str(self.__fURG_cnt)
        dump += sep
        dump += str(self.__bURG_cnt)
        dump += sep

        dump += str(self.__fHeaderBytes)
        dump += sep
        dump += str(self.__bHeaderBytes)
        dump += sep
        dump += str(self.getfPktsPerSecond())
        dump += sep
        dump += str(self.getfPktsPerSecond())
        dump += sep

        if len(self.__forward) > 0 or len(self.__backward) > 0:
            dump += str(self.__flowLengthStats.getMin())
            dump += sep
            dump += str(self.__flowLengthStats.getMax())
            dump += sep
            dump += str(self.__flowLengthStats.getMean())
            dump += sep
            dump += str(self.__flowLengthStats.getStandardDeviation())
            dump += sep
            dump += str(self.__flowLengthStats.getVariance())
            dump += sep

        else:
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            dump += str("0")
            dump += sep
            
        
        #print("{}".format(dump))
        fileObject.write(dump)
        fileObject.write('\n')
    



