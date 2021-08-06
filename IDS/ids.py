import pyshark
import pandas as pd
import pickle
from py import _std
from py import __metainfo
from py import _builtin
from py import _error
from py import _xmlgen
from py import __pycache__
from py import _code
from py import _io
from py import _log
from py import _path
from py import _process
from py import _path
from py import _vendored_packages

# Capturing Packets
capture = pyshark.LiveCapture(interface='Wi-Fi')
capture.sniff(timeout=2)

data=[]
print(capture)

# Creating List

if len(capture)!=0:
    for x in range(len(capture)):
        # Appending Protocol
        data.append(list())
        try:
            val=capture[x].ip.proto
            data[x].append(int(val))
        except:
            data[x].append(0)

        # Appending land 
        if val=='6':    
            if capture[x].eth.dst==capture[x].eth.src and capture[x].tcp.srcport==capture[x].tcp.dstport:
                data[x].append(0)
            else:
                data[x].append(1)
        elif val=='17':
            if capture[x].eth.dst==capture[x].eth.src and capture[x].udp.srcport==capture[x].udp.dstport:
                data[x].append(0)
            else:
                data[x].append(1)


        # Appending urgent
        # I have a doubt here in the definition it is mentioned that in the same connection.
        z=0
        for y in range(len(capture)):
            if(capture[x].ip.proto=='6'):
                # Adding exception because eventhough it is passing the if condition, it is throwing the error that it can't find tcp.flags_urg parameter.
                try:
                    if capture[x].eth.dst==capture[y].eth.dst and capture[x].eth.src==capture[y].eth.src and (capture[y].tcp.flags_urg==1):
                        z=z+1
                except:
                    continue
        data[x].append(z)

        # Appending count
        z=0
        for y in range(len(capture)):
            if capture[x].eth.dst==capture[y].eth.dst:
                z=z+1
        data[x].append(z)

        # Appending srv_count
        z=0
        for y in range(len(capture)):
            if val=='6': 
                try:      
                    if capture[x].tcp.dstport==capture[y].tcp.dstport:
                        z=z+1
                except:
                    continue
            elif val=='17':
                try:
                    if capture[x].udp.dstport==capture[y].udp.dstport:
                        z=z+1
                except:
                    continue        
        data[x].append(z)

        # Appending dst_host_count
        z=0
        for y in range(len(capture)):
            if val=='6':
                try:    
                    if capture[x].ip.dst_host==capture[y].ip.dst_host:
                        z=z+1
                except:
                    continue
            elif val=='17':
                try:
                    if capture[x].udp.dst_host==capture[y].udp.dst_host:
                        z=z+1
                except:
                    continue
        data[x].append(z)

        # Appending host_srv_count    IT IS THE SAME CODE AS THE SRV_COUNT BECAUSE I DON'T UNDERSTAND THE DIFF BETWEEN THEM
        z=0
        for y in range(len(capture)):
            if val=='6':
                try:    
                    if capture[x].tcp.dstport==capture[y].tcp.dstport:
                        z=z+1
                except:
                    continue
            elif val=='17':
                try:
                    if capture[x].udp.dstport==capture[y].udp.dstport:
                        z=z+1  
                except:
                    continue      
        data[x].append(z)
    
    # Converting to datafram
    
    df = pd.DataFrame(data)
    # df.to_csv('live.csv', index=False, header=False)    This was for csv

    clf= pickle.load(open('finalized_model.sav', 'rb'))
    x=df.iloc[:,:].values
    result = clf.predict(x)
    
    num=1
    textfile = open("a_file.txt", "w")
    textfile.write(" Normal=1 and Anomaly=0 ")
    for element in result:
        textfile.write("Packet "+ str(num) + " Predicted "+ str(element) + "\n")
        num=num+1
    textfile.close()

else:
    print(" No Packets Captured")



