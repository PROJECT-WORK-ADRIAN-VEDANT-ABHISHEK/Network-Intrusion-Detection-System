
import pyshark
cap = pyshark.FileCapture('packetsaved.pcap')
packno=int(input("Which packet do you want to see   :  "))   
print(cap[packno])


