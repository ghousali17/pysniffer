#!/usr/bin/python
# -*- coding: utf-8 -*-
import pcap
import sys
import socket


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

        for i in range(len(self.__src)):
            if bytes(self.__src[i]) != bytes(self.__dst[i]):
                if bytes(self.__src[i]) > bytes(self.__dst[i]):  # if the difference bit of src is greater we consider it incoming
                    forward = False
                i = len(self.__src)

        if forward:
            self.__flowId = str(self.getSourceIp()) + '-' \
                + str(self.getDestinationIp()) + '-' \
                + str(self.__srcPort) + '-' + str(self.__dstPort) + '-' \
                + str(self.__protocol)
        else:
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

    def getSourceIp(self):
        return socket.inet_ntoa(self.__src)  # convert to utils format

    def getDestinationIp(self):
        return socket.inet_ntoa(self.__dst)

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

    '''def printTcp(self):
        print *'\n')
        print self.getTimestamp()
        print socket.inet_ntoa(self.getSrc()) + '  --> ' \
            + socket.inet_ntoa(self.getDst())
        print str(self.getSrcPort()) + '  --> ' + str(self.getDstPort())
        print 'Header: ' + str(self.getHeaderBytes())
        print 'Payload: ' + str(self.getPayloadBytes())
        print 'TCP'
        if self.__flagFIN:
            print 'FIN'
        if self.__flagSYN:
            print 'SYN'
        if self.__flagRST:
            print 'RST'
        if self.__flagPSH:
            print 'PSH'
        if self.__flagACK:
            print 'ACK'
        if self.__flagURG:
            print 'URG'
        if self.__flagECE:
            print 'ECE'
        if self.__flagCWR:
            print 'CWR'''



			