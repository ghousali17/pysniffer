class summaryStatistics():
	def __init__(self):
		self.__min = None
		self.__max = None
		self.__sum = 0.0
		self.__count = 0.0

	def addValue(self,value):

		self.__sum +=value
		self.__count += 1

		if self.__min == None:
			self.__min = value
		elif value < self.__min:
			self.__min = value

		if self.__max == None:
			self.__max = value
		elif value > self.__max:
			self.__max = value

	def getSum(self):
		return self.__sum


	def getCount(self):
		return self.__count

	def getMin(self):
		return self.__min

	def getMax(self):
		return self.__max
		


