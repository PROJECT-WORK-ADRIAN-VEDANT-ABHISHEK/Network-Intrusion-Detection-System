#this needs to be further edited based on our anamoly.txt file

import os, time, signal, sys
import os.path
from os import path

def signal_handler(signal, frame):
	print("\nCleaning firewall rules and exiting gracefully")
	for i in list:
		os.system('netsh advfirewall firewall delete rule name="{}"'.format(i))
	sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

while not path.exists("Anomaly.txt"): 
#Just giving the sniffer script a few seconds to create a pcap and 'anomaly.txt'
	time.sleep(3)

# if suspicious.txt exists, start a loop
while path.exists("suspicious.txt"):
# signal.signal(signal.SIGINT, signal_handler)

	list = []
	inTnotU = []
	f = open('Anomaly.txt', 'r+')
	for i in f:
		inTnotU.append(i)
	f.close()
	for i in inTnotU:
		i=(i[:-1])
		if i not in list:
			list.append(i)
			
	for i in list:
		os.system('netsh advfirewall firewall add rule name="{}" dir=out interface=any action=block remoteip={}'.format(i,i))
	time.sleep(15)
	
	for i in list:
		os.system('netsh advfirewall firewall delete rule name="{}"'.format(i))
