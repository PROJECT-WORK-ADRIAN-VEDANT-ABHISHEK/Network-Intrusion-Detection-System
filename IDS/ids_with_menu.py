import pyshark
import pandas as pd
import pickle
import socket
from getmac import get_mac_address as gma

capture = pyshark.LiveCapture(interface='Wi-Fi',output_file='packetsaved.pcap')
looping=True
run=0

def packet_capture():
    global run
    global capture
    run=1
    # Capturing Packets
    capture = pyshark.LiveCapture(interface='Wi-Fi',output_file='packetsaved.pcap')
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
                if val=='6':
                    data[x].append(1)
                elif val=='17':
                    data[x].append(2)
                else:
                    data[x].append(3)
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
                try:    
                    if capture[x].ip.dst_host==capture[y].ip.dst_host:
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

            # Append host mac

            data[x].append(capture[x].ip.src)

            # Append dest mac

            data[x].append(capture[x].ip.dst)
        
        # Converting to datafram
        
        df = pd.DataFrame(data)
        # df.to_csv('live.csv', index=False, header=False)    This was for csv
        #print(df)
        clf= pickle.load(open('finalized_model.sav', 'rb'))
        x=df.iloc[:,:-2].values
        result = clf.predict(x)
        nor=[]
        ano=[]
        nor=[1 for x in result if x==1]
        ano=[1 for x in result if x==0]

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))


        num=1
        textfile = open("Anomaly.txt", "w")
        textfile.write(" MAC Address of this device is :  {} ".format(gma()))
        textfile.write("\n")
        textfile.write(" IP Address of this device is :  {} ".format(s.getsockname()[0]))
        s.close()
        textfile.write("\n")
        #textfile.write(" Normal=1 and Anomaly=0 " + "\n" )
        textfile.write("\n")
        textfile.write(" Packets found are {} ".format(len(capture)))
        textfile.write("\n")
        textfile.write(" Anomaly found are {} ".format(sum(ano)))
        textfile.write("\n")
        textfile.write("\n")
        
        found_anomanly_src=[]
        for element in result:
            if element==0 and data[num-1][8] not in found_anomanly_src:

                found_anomanly_src.append(data[num-1][8])

                textfile.write("Packet:- "+ str(num) + " Predicted "+ str(element) + "\n")
                textfile.write("protocol -" +str(data[num-1][0])+ "\n")
                textfile.write("land -" +str(data[num-1][1])+ "\n")
                textfile.write("urgent -" +str(data[num-1][2])+ "\n")
                textfile.write("count -" +str(data[num-1][3])+ "\n")
                textfile.write("srv_count -" +str(data[num-1][4])+ "\n")
                textfile.write("dst_host_count -" +str(data[num-1][5])+ "\n")
                textfile.write("Dst_host_srv_count -" +str(data[num-1][6])+ "\n")
                textfile.write("Dst IP Address -" +str(data[num-1][7])+ "\n")
                textfile.write("SRC IP Address -" +str(data[num-1][8])+ "\n")
                textfile.write("\n"+ "\n")
            num=num+1
        textfile.close()
        print(" ")
        a_file = open("Anomaly.txt")
        lines = a_file.readlines()
        for line in lines:
            print(line.rstrip())
        a_file.close()

    else:
        print(" No Packets Captured")

    print(" DONE ")



print(" ")
print("-------------------- WELCOME TO REAL TIME INTRUSION DETECTION SYSTEM--------------------")


while looping:
    
    print(" ")
    print(" What would you like to do")
    print(" 1. Check for Anomaly")
    print(" 2. Check the Captured Packets")
    print(" 3. Exit ")
    print(" ")
    option=int(input(" Choose a number from the above: "))
    print("--------------------------------------------------------------------------------------")
    
    if option==1:
        packet_capture()
        print("--------------------------------------------------------------------------------------")
    if option==2:
        if run==1:
            packet_number=int(input(" Which packet would you like to view : "))
            if packet_number<len(capture):
                print(capture[packet_number-1])
                print("done")
        else:
            print(" No Sniffing detected !!!")
            print("--------------------------------------------------------------------------------------")
    if option==3:
        looping=False
        print("-----------------------------THANK YOU !!-----------------------------")
