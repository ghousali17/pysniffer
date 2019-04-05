#!/usr/bin/python
# -*- coding: utf-8 -*-
import pcap
import sys
import socket
import struct 


def bytes_to_int(bytes):
    result = 0

    for b in bytes:
        #print('Int value:'.format (int(b)))
        result = result * 256 + int(b)
    return result

def byte_shifter(bytes):
    zero = bytes[0]
    one = bytes[1]
    two = bytes[2]
    three = bytes[3]

    result = [three,three, one, zero]
    '''result[0] = two
    result[1] = three
    result[2] = zero
    result[3] = one'''

    return result 

class BasicPacketInfo:

    def __init__(
        self,
        src,
        dst,
        srcPort,
        dstPort,
        protocol,
        timestamp,
        generator,
        ):

    # Info to generate flows from packers (8/8)
        self.__flowSrc = None
        self.__isForward = True
        self.__id = generator
        self.__src = src
        self.__dst = dst
        self.__srcPort = srcPort
        self.__dstPort = dstPort
        self.__protocol = protocol
        self.__timestamp = timestamp
        self.generateFlowId()
        self.__payloadBytes = 0
        

    # Flags (8/8)

        self.__flagFIN = False
        self.__flagPSH = False
        self.__flagURG = False
        self.__flagECE = False
        self.__flagSYN = False
        self.__flagACK = False
        self.__flagCWR = False
        self.__flagRST = False

    # Additional details (3/3)

        self.__TCPWindow = -0x01
        self.__headerBytes = 0
        self.__payloadPacket = 0

    def generateFlowId(self):
        forward = True
        #print('Length{}'.format(len(self.__src)))
        srcTemp = self.__src
        dstTemp = self.__dst
        #self.__src = byte_shifter(self.__src) #struct.pack('>L', bytes_to_int(self.__src))
        #self.__dst = byte_shifter(self.__dst) #struct.pack('>L', bytes_to_int(self.__dst))
        #print('Conversion using nto host: {} ==> {}'.format(self.__src, socket.ntohl(bytes_to_int(self.__src))))    
        #print('Conversion using host to network: {} ==> {}'.format(bytes_to_int(self.__src), socket.htonl(bytes_to_int(self.__src))))    
        temp_s = struct.pack('<I',(bytes_to_int(self.__src)))
    
       
        temp_d = struct.pack('<I',(bytes_to_int(self.__dst)))
        #self.__src = socket.htonl(bytes_to_int(self.__src))
        #self.__dst = socket.htonl(bytes_to_int(self.__dst))
       
        #len(self.__src) - 1
        #print("LOL!")
        #self.__src = temp_S
        i = 0 
        while i < len(self.__src):
            #print ('Comparison points:{} {}'.format(bytes_to_int([self.__src[i]]),format(bytes_to_int([self.__dst[i]]))))
            #print ('{} => {}'.format(self.__src[i], byte_shifter(self.__src)[i]))
            #if i >= 1:
                #print("======================================================================================")
            #print("IP:{} => Normal {} => Int{}".format(socket.inet_ntoa(self.__src),self.__src , int(self.__src[i])))
            #print("\nComparing cross endian{} => {}".format(socket.inet_ntoa(self.__src),socket.inet_ntoa(temp_s)))
            #print("Comparing cross endian{} => {}".format(socket.inet_ntoa(self.__dst),socket.inet_ntoa(temp_d)))
            
            if (self.__src[i]) != (self.__dst[i]):
            
                if (self.__src[i]) > (self.__dst[i]):  # if the difference bit of src is greater we consider it incoming
                    forward = False
                i = len(self.__src) 
            i += 1 
            #        print('Forward False!')
        
        self.__src = srcTemp
        self.__dst = dstTemp
        
        

        if forward == True:
            self.__flowSrc = self.__src
            self.__isForward = True
            self.__flowId = str(self.getSourceIp()) + '-' \
                + str(self.getDestinationIp()) + '-' \
                + str(self.__srcPort) + '-' + str(self.__dstPort) + '-' \
                + str(self.__protocol)
        else:
            #print('Setting false!')
            self.__isForward = False
            self.__flowSrc = self.__dst
            self.__flowId = str(self.getDestinationIp()) + '-' \
                + str(self.getSourceIp()) + '-' + str(self.__dstPort) \
                + '-' + str(self.__srcPort) + '-' + str(self.__protocol)
        
            
        print ('FlowID:{}'.format(self.__flowId))
        return self.__flowId

    def dumpInfo(self):
        return None

    def getPayloadPacket(self):
        self.__payloadPacket = self.__payloadPacket + 0x01
        return self.__payloadPacket
    def getFlowSrc(self):
        print('Returning:{}'.format(self.__flowSrc))
        return self.__flowSrc

    def getSourceIp(self):          
        if len(self.__src) == 16:           
            return socket.inet_ntop(10, self.__src)                 
        return socket.inet_ntoa((self.__src))
     # convert to utils format

    def getDestinationIp(self):
        if len(self.__dst) == 16:           
            return socket.inet_ntop(10, self.__dst)                 
        return socket.inet_ntoa(self.__dst)  # convert to utils format
    
        
    def getId(self):
        return self.__id

    def setId(self, Id):
        this.__id = Id

    def getSrc(self):
        return self.__src

    def setSrc(self, src):
        self.__src = src

    def getDst(self):
        return self.__dst

    def setDst(self, dst):
        self.__dst = dst

    def getSrcPort(self):
        return self.__srcPort

    def setSrcPort(self, srcPort):
        self.__srcPort = srcPort

    def getDstPort(self):
        return self.__dstPort

    def setDstPort(self, dstPort):
        self.__dstPort = dstPort

    def getProtocol(self):
        return self.__protocol

    def setProtocol(self, protocol):
        self.__protocol = protocol

    def getTimestamp(self):
        return self.__timestamp

    def setTimestamp(self, ts):
        self.__timestamp = ts

    def setFlowId(self, flowId):
        self.__flowId = flowId

    def getFlowId(self):
        return self.__flowId

    def isForwardPacket(self, src):
        return self.__src == src

    def getPayloadBytes(self):
        return self.__payloadBytes

    def setPayloadBytes(self, payloadBytes):
        self.__payloadBytes = payloadBytes

    def getHeaderBytes(self):
        return self.__headerBytes

    def setHeaderBytes(self, headerBytes):
        self.__headerBytes = headerBytes

    # flag function (1/8)

    def hasFlagFIN(self):
        return self.__flagFIN

    def setFlagFIN(self):
        self.__flagFIN = True

    def hasFlagPSH(self):
        return self.__flagPSH

    def setFlagPSH(self):
        self.__flagPSH = True

    def hasFlagURG(self):
        return self.__flagURG

    def setFlagURG(self):
        self.__flagURG = True

    def hasFlagECE(self):
        return self.__flagECE

    def setFlagSYN(self):
        self.__flagECE = True

    def hasFlagSYN(self):
        return self.__flagSYN

    def setFlagSYN(self):
        self.__flagSYN = True

    def hasFlagACK(self):
        return self.__flagACK

    def setFlagFin(self):
        self.__flagACK = True

    def hasFlagCWR(self):
        return self.__flagCWR

    def setFlagCWR(self):
        self.__flagCWR = True

    def hasFlagRST(self):
        return self.__flagRST

    def setFlagRST(self):
        self.__flagRST = True

    def getTCPWindow(self):
        self.__TCPWindow

    def setTCPWindow(self, TCPWindow):
        self.__TCPWindow = TCPWindow

    def setFlags(self, flagByte):

        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80

        if flagByte & FIN:
            self.__flagFIN = True
        if flagByte & SYN:
            self.__flagSYN = True
        if flagByte & RST:
            self.__flagRST = True
        if flagByte & PSH:
            self.__flagPSH = True
        if flagByte & ACK:
            self.__flagACK = True
        if flagByte & URG:
            self.__flagURG = True
        if flagByte & ECE:
            self.__flagECE = True
        if flagByte & CWR:
            self.__flagCWR = True

    def isForward(self):
            return self.__isForward


            