from statSummary import summaryStatistics


test = summaryStatistics()

'''3, 4, 4, 5, 6, 8
test.addValue(3)
test.addValue(4)
test.addValue(4)
test.addValue(5)
test.addValue(6)
test.addValue(8)
'''
test.addValue(1)
test.addValue(2)
test.addValue(4)
test.addValue(5)
test.addValue(7)
test.addValue(11)

print('Mean:{}'.format(test.getMean()))
print('SD:{}'.format(test.getStandardDeviation()))
print('Variance:{}'.format(test.getVariance()))