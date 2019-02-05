from BasicPacketInfo import BasicPacketInfo
from statSummary import summaryStatistics


class BasicFlow():
	Act_data_pkt_forward = 0
	
	Init_Win_bytes_forward = -1
	Init_Win_bytes_backward = -1

	
	def __init__(self, bidirectional, packetInfo):
		self.__count = 1
		
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
		self.__bwdPktStats =  summaryStatistics()
		self.__flagCounts = None
		#initFlags();
		self.__forwardBytes = 0
		self.__backwardBytes = 0	
		self.__startActiveTime = 0
		self.__endActiveTime = 0
		self.__src = None
		self.__dst = None
		self.__fPSH_cnt=0
		self.__bPSH_cnt=0
		self.__fURG_cnt=0
		self.__bURG_cnt=0
		self.__fHeaderBytes=0
		self.__bHeaderBytes=0

	def addPacket(self):
		self.__count = self.__count + 1

	def printStat(self):
		
		print '\nStart Time: ' + str(self.__flowStartTime)
		print 'Last Time: ' + str(self.__flowLastSeen)
		print 'Protocol: ' + str(self.__protocol)
		print 'forward HBytes: ' + str(self.__fHeaderBytes)
		print 'forward Bytes: ' + str(self.__forwardBytes)
		print 'backward HBytes: ' + str(self.__bHeaderBytes)
		print 'backward Bytes: ' + str(self.__backwardBytes)
		print 'Flow ID: ' + str(self.__flowId)

	def printFinalStat(self):
		



	def firstPacket(self,packetInfo):
		self.__flowStartTime = packetInfo.getTimestamp()
		self.__flowLastSeen = packetInfo.getTimestamp()
		self.__startActiveTime = packetInfo.getTimestamp()
		self.__endActiveTime = packetInfo.getTimestamp()

		if self.__src == None:
			self.__src = packetInfo.getSrc()
			self.srcPort = packetInfo.getSrcPort()
		
		if self.__dst == None:
			self.__dst = packetInfo.getDst()
			self.dstPort = packetInfo.getDstPort()

		if self.__src == packetInfo.getSrc():
			#print 'Backward at ' + str(packetInfo.getTimestamp())
			#update forward streM
			self.__min_seg_size_forward = packetInfo.getHeaderBytes()			
			Init_Win_bytes_forward = packetInfo.getTCPWindow()			
			self.__flowLengthStats.addValue(packetInfo.getPayloadBytes())				
			self.__fwdPktStats.addValue(packetInfo.getPayloadBytes())
			self.__fHeaderBytes = packetInfo.getHeaderBytes()
			self.__forwardLastSeen = packetInfo.getTimestamp()
			self.__forwardBytes += packetInfo.getPayloadBytes()
			if packetInfo.hasFlagPSH():
				self.__fPSH_cnt +=1 

			if packetInfo.hasFlagURG():
				self.__fURG_cnt +=1
			
		else:
			#print 'Backward at ' + str(packetInfo.getTimestamp())
			#updata backward stream
			#1
			#2
			#3
			#4
			self.__bHeaderBytes = packetInfo.getHeaderBytes()
			self.__backwardLastSeen = packetInfo.getTimestamp()
			self.__backwardBytes += packetInfo.getPayloadBytes()
			if packetInfo.hasFlagPSH():
				self.__fPSH_cnt +=1 

			if packetInfo.hasFlagURG():
				self.__fURG_cnt +=1
			


		#(2/2)
		self.__protocol = packetInfo.getProtocol()
		self.__flowId = packetInfo.getFlowId()
		

	def addPacket(self,packetInfo):		
		currentTimestamp = packetInfo.getTimestamp()

		if self.__isBidirectional:
			#1
			if self.__src == packetInfo.getSrc():
				if packetInfo.getPayloadBytes() >= 1:
					lol = 1
					#2
				#3
				self.__fHeaderBytes += packetInfo.getHeaderBytes()
				#4
				self.__forwardBytes += packetInfo.getPayloadBytes()
				#5
				self.__forwardLastSeen = currentTimestamp
				#6
			else:
				#1
				#2
				self.__bHeaderBytes += packetInfo.getHeaderBytes()
				#3
				self.__backwardBytes += packetInfo.getPayloadBytes()
				#4
				self.__forwardLastSeen = currentTimestamp



		else:
			#print 'Not directional: ' + str(currentTimestamp)
			#1
			#2
			#3
			self.__fHeaderBytes += packetInfo.getHeaderBytes()
			#4
			self.__forwardBytes += packetInfo.getPayloadBytes()

			#5
			self.__forwardLastSeen = currentTimestamp
			#6

		#1
		self.__flowLastSeen = currentTimestamp
				
	def getFlowStartTime(self):
		return self.__flowStartTime