#!/usr/bin/python
# -*- coding: utf-8 -*-
import pcap
import sys
import socket
from BasicPacketInfo import BasicPacketInfo
from BasicFlow import BasicFlow
from struct import *


# All that is left is for us to figure out how can finished flows be stored and or printed

class FlowGenerator:

    def __init__(
        self,
        bidirectional,
        flowTimeout,
        activityTimeout,
        ):
        self.__bidirectional = bidirectional
        self.__flowTimeout = flowTimeout
        self.__activityTimeout = activityTimeout
        self.init()

    def init(self):
        self.__flowCount = 0 
        self.__currentFlows = {}
        self.__finishedFlowCount = 0
        self.__IpAddresses = {}

    def addPacket(self, packetInfo):
        if packetInfo == None:
            return

        currentTimestamp = packetInfo.getTimestamp()

        #print ("{}".format(currentTimestamp))
        #print ("of size {}".format(packetInfo.getPayloadBytes()))
        if packetInfo.getFlowId() in self.__currentFlows:
            #print('Flow exists:{}'.format(packetInfo.getFlowId()))
            flow = self.__currentFlows[packetInfo.getFlowId()]
            #print ('Flow: {} exists'.format(packetInfo.getFlowId()))
            if currentTimestamp - flow.getFlowStartTime() \
                > self.__flowTimeout:

                # flow count
                    # flow listener
                        # extra shit

                print ('Flow time out')
                self.__currentFlows[packetInfo.getFlowId()].dumpFlowBasedFeatures("||")
                del self.__currentFlows[packetInfo.getFlowId()]
                self.__currentFlows[packetInfo.getFlowId()] = \
                    BasicFlow(packetInfo)
            elif packetInfo.hasFlagFIN():

                # 1
                # 2

                #print ('Flow finished')

                flow.addPacket(packetInfo)
                self.__currentFlows[packetInfo.getFlowId()].dumpFlowBasedFeatures("||")
                del self.__currentFlows[packetInfo.getFlowId()]
            else:

                # 1
                # 2
                # del self.__currentFlows[packetInfo.getFlowId()]

               
                #print ('flow updated')

                # 1
                # 2 bull
                #print('Updating flow!')
                self.__currentFlows[packetInfo.getFlowId()].addPacket(packetInfo)
        else:

            #print ('Creating Flow:{}'.format(packetInfo.getFlowId()))
            self.__flowCount += 1
            self.__currentFlows[packetInfo.getFlowId()] = \
                BasicFlow(self.__bidirectional, packetInfo)

    def listBasic(self):
        #print ('final list')
        print("A total of {}".format(self.__flowCount))
        
        for (key, val) in self.__currentFlows.items():
            
           
            val.dumpFlowBasedFeatures('||')
            #if count == 5:
            #    break 



