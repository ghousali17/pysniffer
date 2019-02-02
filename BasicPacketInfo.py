class BasicPacketInfo():
	def __init__(self):
		self.__src = '12'
		self.__dst = '10'
		self.__srcPort = 10
		self.__dstPort = 20
		self.__protocol = 15
		self.__timestamp = 20 
		self.__flowId = None
		self.generateFlowId()

	def generateFlowId(self):
		forward = True

		for i in range(len(self.__src)):
			if int(self.__src[i]) != int(self.__dst[i]): 
				if int(self.__src[i]) > int(self.__dst[i]): #if the difference bit of src is greater we consider it incoming
					forward = False
				i = len(self.__src)

		if(forward):
			self.__flowId = str(self.getSourceIp) + "-" + str(self.getDestinationIp) + "-" + str(self.__srcPort) + "-" + str(self.__dstPort) + "-" + str(self.__protocol)
		else:
			self.__flowId = str(self.getDestinationIp) + "-" + str(self.getSourceIp) + "-" + str(self.__dstPort) + "-" + str(self.__srcPort) + "-" + str(self.__protocol)













	def getSourceIp(self):
		return self.__src #convert to utils format
	def getDestinationIp(self):
		return self.__dst


tester = BasicPacketInfo()
print('Tester created!')
print tester.generateFlowId()