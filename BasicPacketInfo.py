

class BasicPacketInfo():
	def __init__(self):
	#Info to generate flows from packers	
		self.__src = '12'
		self.__dst = '10'
		self.__srcPort = 10
		self.__dstPort = 20
		self.__protocol = 15
		self.__timestamp = 20 
		self.__flowId = None
		self.generateFlowId()
#Need to add flags
		self.__TCPWindow = -1
		self.__headerBytesBytes = None
		self.__payloadPacket = 0 


	def generateFlowId(self):
		forward = True

		for i in range(len(self.__src)):
			if int(self.__src[i]) != int(self.__dst[i]): 
				if int(self.__src[i]) > int(self.__dst[i]): #if the difference bit of src is greater we consider it incoming
					forward = False
				i = len(self.__src)

		if(forward):
			print 'forward'
			self.__flowId = str(self.getSourceIp()) + "-" + str(self.getDestinationIp()) + "-" + str(self.__srcPort) + "-" + str(self.__dstPort) + "-" + str(self.__protocol)
		else:
			print 'backwards'
			self.__flowId = str(self.getDestinationIp()) + "-" + str(self.getSourceIp()) + "-" + str(self.__dstPort) + "-" + str(self.__srcPort) + "-" + str(self.__protocol)
			print self.__flowId

		return self.__flowId

	def dumpInfo(self):
		return None

	def getPayloadPacket(self):
		self.__payloadPacket =  self.__payloadPacket + 1
		return self.__payloadPacket


	def getId(self):
		return self.__Id

	def setId(self,Id):
		this.__Id = Id


	def getSrc(self):
		return self.__src

	def setSrc(self,src):
		self.__src = src

	def getDst(self):
		return self.__dst

	def setDst(self,dst):
		self.__dst = dst


	def isForwardPacket(self, src):
		return self.__src == src



	def getSourceIp(self):
		return self.__src #convert to utils format
	def getDestinationIp(self):
		return self.__dst


tester = BasicPacketInfo()
print('Tester created!')
print tester.generateFlowId()
x = tester.getPayloadPacket()
print tester.isForwardPacket('12')