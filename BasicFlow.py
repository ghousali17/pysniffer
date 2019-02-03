from BasicPacketInfo import BasicPacketInfo

class BasicFlow():
	
	def __init__(self, packetInfo):
		self.__count = 1
		self.initParameters()
		self.__src = packetInfo.getSrc()
		self.__dst = packetInfo.getDst()
		self.__srcPort = packetInfo.getSrcPort()
		self.__dstPort = packetInfo.getDstPort()

	def initParameters(self):
		self.__forward = None
		self.__backward = None
		self.__flowIAT = None
		self.__forwardIAT = None
		self.__backwardIAT = None
		self.__flowActive = None
		self.__flowIdle = None
		self.__flowLengthStats = None
		self.__fwdPktStats = None
		self.__bwdPktStats =  None
		self.__flagCounts = None
		#initFlags();
		self.__isBidirectional = False
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
		print 'Stat: ' + str(self.__count)



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

		if self.__src == packetInfo.src:
			#update forward streM
			#1
			#2
			#3
			#4
			self.__fHeaderBytes = packetInfo.getHeaderBytes()
			self.__forwardLastSeen = packetInfo.getTimestamp()
			self.__forwardBytes += packetInfo.getPayloadBytes()
			if packetInfo.hasFlagPSH():
				self.__fPSH_cnt +=1 

			if packetInfo.hasFlagURG():
				self.__fURG_cnt +=1
			
		else:
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
		

	def firstPacket(self,packetInfo):		
		currentTimestamp = packetInfo.getTimeStamp()

		if self.__isBidirectional:
			#1
			if self.__src = packetInfo.src:
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
				


